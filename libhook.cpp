#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/mman.h> // for mmap flags
#include <vector>
#include <linux/elf.h>
#include "hyde.h"

#define TARG_F "bindtextdomain"
//#define TARG_F "strrchr"
//#define TARG_F "puts"

// TODO: need to make these dynamic, per-asid
// but they probably should work!

static char* last_libname = NULL;
static unsigned long last_match_addr = 0;

//static char payload[] = "\x50\x48\xC7\xC0\xFF\xFF\x00\x00\x0F\x05"; // Push rax, rax=0xffff, syscall
//static char payload2[] = "\x50\x48\xC7\xC0\xFE\xFF\x00\x00\x0F\x05"; // Push rax, rax=0xfffe, syscall

static char payload[] = "\x0f\x05";
static char payload2[] = "\x0f\x05";

static char clobbered_data[sizeof(payload)];
static char clobbered_data2[sizeof(payload)];

static unsigned long int hookedA = 0;
static unsigned long int hookedB = 0;


SyscCoroutine start_coopter_open(asid_details* details) {
  if (hookedB != 0) {
    co_return;
  }
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  int callno = CALLNO(regs);
  int dir_arg_no = (callno == __NR_openat) ? 1 : 0;
  char *host_targname;
  map_guest_pointer(details, host_targname, get_arg(regs, dir_arg_no));

  if (callno == __NR_openat && host_targname[0] != '/') {
    //printf("TODO: handle relative paths for %s\n", host_targname);
    //Just ignore for now...
    co_return;
  }

  char* suffix1 = strstr(host_targname, ".so");
  char* suffix2 = strstr(host_targname, ".so.");
  // Either match '.so' at end of string, or match '.so.' anywhere
  if ((suffix1 == nullptr || strlen(suffix1) != 3) && suffix2 == nullptr) {
      co_return;
  }

  //printf("Saw open of a library: %s\n", host_targname);
  if (last_libname != NULL)
    free(last_libname);
  last_libname = strdup(host_targname);
}

SyscCoroutine start_coopter_mmap(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  int callno = CALLNO(regs);
  // It's an mmap - let's see if there's an FD
  int len = get_arg(regs, 1);
  int prot = get_arg(regs, 2);
  int fd = get_arg(regs, 4);
  int off = get_arg(regs, 5);

  if (fd == -1) {
    co_return;
  }

  // Let's yield the original syscall, then skip it later
  // This way we can analyze the data before the guest continues

  //__u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
  //    get_arg(regs, 0), get_arg(regs, 1), get_arg(regs, 2),
  //    get_arg(regs, 3), get_arg(regs, 4), get_arg(regs, 5));

  co_yield *(details->orig_syscall);
  __u64* guest_buf = (__u64*)details->retval;

  char* host_data;
  map_guest_pointer(details, host_data, guest_buf);

  bool already_bkpt = false;
  if (memcmp(host_data, "\x7F" "ELF", 4) == 0) {
    Elf64_Ehdr ehdr;
    memcpy(&ehdr, host_data, sizeof(ehdr)); // Hoping it doesn't change pages

    unsigned long phnum = ehdr.e_phnum;
    unsigned long phoff = ehdr.e_phoff;
    //printf("Found dynamic section: loaded at %llx with %ld entries in program header table\n",
    //    (__u64)guest_buf, phnum);

    bool found_dynamic = false;
    Elf32_Phdr *dynamic_phdr; // XXX why is this elf32?
    for (int j=0; j < phnum; j++) {
      // Should be able to make this work as an &...[j] style array access
      //map_guest_pointer(details, dynamic_phdr, guest_buf + phoff + (j*sizeof(Elf64_Phdr)));
      int offset = j*ehdr.e_phentsize;
      map_guest_pointer(details, dynamic_phdr, guest_buf + phoff + offset); // XXX this is just ptr sz?
      //printf("Offset 0x%x p_type=0x%x, p_flags=0x%x, p_offset=0x%x vaddr=0x%x\n", offset,
      //      dynamic_phdr->p_type, dynamic_phdr->p_flags, dynamic_phdr->p_offset, dynamic_phdr->p_vaddr);

      // Found dynamic section!
      if (dynamic_phdr->p_type == PT_DYNAMIC){
        found_dynamic = true;
        break;

      // Reached end, no dynamic section - let's bail
      }else if (dynamic_phdr->p_type == PT_NULL){
        //printf("PT NULL\n");
        break;
      }else if (j == phnum -1) {
        //printf("PHNUM-1\n");
        break;
      }
    }

    if (found_dynamic) {
      Elf64_Dyn *tag;
      int numelements_dyn = dynamic_phdr->p_filesz / sizeof(Elf64_Dyn);

      unsigned long strtab = 0, symtab = 0, strtab_size = 0, dt_hash = 0, gnu_hash = 0;
      int j = 0;

      for (int j=0; j < numelements_dyn; j++) {
        map_guest_pointer(details, tag, guest_buf + dynamic_phdr->p_vaddr + (j*sizeof(tag)));
        //printf("Tag %d has type: %lld\n", j, tag->d_tag);
        if (tag->d_tag == DT_STRTAB){
          //printf("Found DT_STRTAB\n");
          strtab = tag->d_un.d_ptr;
        }else if (tag->d_tag == DT_SYMTAB){
          //printf("Found DT_SYMTAB\n");
          symtab = tag->d_un.d_ptr;
        }else if (tag->d_tag == DT_STRSZ ){
          //printf("Found DT_STRSZ\n");
          strtab_size = tag->d_un.d_ptr;
        }else if (tag->d_tag == DT_HASH){
          //printf("Found DT_HASH\n");
          dt_hash = tag->d_un.d_ptr;
        }else if (tag->d_tag == DT_HASH){ // DT_GNU_HASH?
          //printf("Found DT_GNU_HASH\n");
          gnu_hash = tag->d_un.d_ptr;
        }else if (tag->d_tag == DT_NULL){
          //printf("Found DT_NULL \n");
          j = numelements_dyn;
          //break;
        }
      }

      if (strtab   < (__u64)guest_buf)   strtab   += (__u64)guest_buf;
      if (symtab   < (__u64)guest_buf)   symtab   += (__u64)guest_buf;
      if (dt_hash  < (__u64)guest_buf)   dt_hash  += (__u64)guest_buf;
      if (gnu_hash < (__u64)guest_buf)   gnu_hash += (__u64)guest_buf;

      //printf("strtab: %llx symtab: %llx hash: %llx\n", (long long unsigned int) strtab,
      //(long long unsigned int)symtab, (long long unsigned int) dt_hash);

      struct dt_hash_section{
          uint32_t nchains;
          uint32_t nbuckets;
      } *dt;
      int numelements = 0;
      // Get_numelements_symtab
      if ((__u64)guest_buf != dt_hash) {
        bool success;
        map_guest_pointer_status(details, dt, dt_hash, &success);
        if (success) numelements = dt->nbuckets;
      }

      // Get_numelements_hash
      if ((__u64)guest_buf != gnu_hash) {
        printf("TODO: use GNU hash method\n");
      }
      Elf64_Sym* symtabs;
      char* strtabs;

      if (numelements > 0x1000) {
        printf("Warning: found too many elements - ignoring\n");
      }else if (numelements > 0) {
        for (int i=0; i < numelements; i++) {
          Elf64_Sym *onesymtab;
          map_guest_pointer(details, onesymtab, symtab+(sizeof(Elf64_Sym)*i));
          if (onesymtab->st_name < strtab_size && onesymtab->st_value != 0) {
            char* sym_name;
            map_guest_pointer(details, sym_name, strtab+onesymtab->st_name);
            __u64 sym_addr = (__u64)guest_buf + onesymtab->st_value;
            //printf("%llx: %s\n", sym_addr, sym_name);

            if (strcmp(sym_name, TARG_F) == 0 && sym_addr != last_match_addr){
              printf("Found symbol %s at %llx in asid %x\n", TARG_F, sym_addr, details->asid);

              char *target_data;
              bool success;

              map_guest_pointer_status(details, target_data, sym_addr, &success);
              if (success) {
                printf("\tMap symbol success=%d, data=", success);
                for (int i=0; i < 10; i++) {
                  printf("%02x ", target_data[i]&0xff);
                }
                puts("");

                if (memcmp(target_data, payload, sizeof(payload)-1) != 0) {
                  printf("New data\n");
                  last_match_addr = sym_addr;
                } else {
                  printf("Already bkpt at %llx hookedA is %lx\n", sym_addr, hookedA);
                  already_bkpt = true;
                  hookedA = sym_addr+2; // XXX this is bad - these addresses can shift around!
                }
              } else {
                printf("\tFailed to map symbol\n");
              }
            }
          }
        }
      }
    }
  }

  if (prot & PROT_EXEC) {
    if (last_match_addr != 0 && (__u64)guest_buf < last_match_addr) {
      char* target_data;
      bool success;
      map_guest_pointer_status(details, target_data, last_match_addr, &success);
      if (success) {
        if (memcmp(target_data, payload, sizeof(payload)-1) != 0) {

          // Store hookedA as end of layer1
          printf("Insert layer1 at %lx and store as hookedA\n", last_match_addr);
          hookedA = last_match_addr+2;
          // Store data we clobber and then log it
          memcpy(clobbered_data, target_data, sizeof(payload)-1);

          printf("\tClobbering %ld bytes of data: ", sizeof(payload)-1);
          for (int i=0; i < 10; i++) {
            printf("%02x ", target_data[i]&0xff);
          }
          printf("\n\t             with new data: ");
          for (int i=0; i < sizeof(payload)-1; i++) {
            printf("%02x ", payload[i]&0xff);
          }
          printf("\n");

          // Clobber the data
          memcpy(target_data, payload, sizeof(payload)-1);
        } else {
          //printf("Looks like there's already a syscall (of ours?) in place\n");
        }
      //} else if (!already_bkpt) {
      //  // XXX not working?
      //  printf("Failed to map guest pointer for symbol: %lx\n", last_match_addr);
      }
    }
  }

  // Ensure correct RV is set
  details->orig_regs.rax = (__u64)guest_buf;
}


extern "C" int kvm_insert_breakpoint(void *cpu, unsigned long addr, unsigned long len, int type);

// We effectively use two breakpoint to do a single-step after the first one is hit
// so we can restore it. SC1 is the real syscall, while Sc2 is just our helper

// Orig 1   Setup Sc1         ->Orig 1              Setup Sc1
// Orig 2   Setup Sc1           Orig 2              Setup Sc1
// Orig 3   Syscall     *hit*   Orig 3              Syscall1
// Orig 4   Orig 4              Setup Sc2         ->Orig 4
// Orig 5   Orig 5              Setup Sc2           Orig 5
// Orig 6   Orig 6              Syscall     *hit*   Orig 6

SyscCoroutine start_coopter_custom2(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  unsigned long int layer1pc = regs.rcx-(sizeof(payload2)+sizeof(payload)-2);
  printf(">>> Hit layer2 breakpoint at PC %llx, layer 1 is at %lx\n", regs.rcx, layer1pc);

  char* target_data;
  bool success;
  hookedB = 0; // No longer have layer2 hook
  map_guest_pointer_status(details, target_data, layer1pc, &success);
  if (success) {
    if (memcmp(target_data, payload, sizeof(payload)-1) != 0) {

      // Store hookedA as end of layer1
      printf("REInsert layer1 at %lx\n", layer1pc);
      hookedA = layer1pc+2;
      // Store data we clobber and then log it
      memcpy(clobbered_data, target_data, sizeof(payload)-1);

      printf("\tClobbering %ld bytes of data: ", sizeof(payload)-1);
      for (int i=0; i < 10; i++) {
        printf("%02x ", target_data[i]&0xff);
      }
      printf("\n\t             with new data: ");
      for (int i=0; i < sizeof(payload)-1; i++) {
        printf("%02x ", payload[i]&0xff);
      }
      printf("\n");

      // Clobber the data
      memcpy(target_data, payload, sizeof(payload)-1);
    }
  }else{
    printf("Failed to map guest pointer for symbol: %lx\n", layer1pc);
  }

  printf("Restoring original layer2 data at 0x%llx and rerun\n", regs.rcx-(sizeof(payload2)-1));

#if 0
  // Pop saved RAX off stack - not anymore
  unsigned long* stack;
  map_guest_pointer(details, stack, regs.rsp);
  details->orig_regs.rax = stack[0];
  details->orig_regs.rsp += 8;
#endif

  char* host_ptr;
  map_guest_pointer(details, host_ptr, regs.rcx-(sizeof(payload2)-1));
  memcpy(host_ptr, clobbered_data2, sizeof(payload2)-1);
  // Have hyde run a no-op syscall, and on return jump back to the original (now-restored) instruction

  // Jump back to original PC: read out of RCX, decrement by the payload size +1
  details->custom_return = regs.rcx-(sizeof(payload2)-1);
  printf("Revert2 to restored data at %lx\n", details->custom_return);

  // Do we need this?
  yield_syscall(details, __NR_getuid); // Junk syscall - need this at the end, otherwise some of our changes don't take? (not sure which?)
}

SyscCoroutine start_coopter_custom(asid_details* details) {
  // Layer 1 breakpoint

  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  char* s;
  bool success;
  // Arg0: RDI
  char arg0[64];
  char arg1[64];
  map_guest_pointer_status(details, s, regs.rdi, &success);
  if (success) sprintf(arg0, "%s", s);
  else         sprintf(arg0, "[Could not read %llx]", regs.rdi);

  map_guest_pointer_status(details, s, regs.rsi, &success);
  if (success)  sprintf(arg1, "%s", s);
  else          sprintf(arg1, "[Could not read %llx]", regs.rsi);

  printf(">>> Hit hook at %llx: %s(%s, %s) original RAX is %llx\n", regs.rcx, TARG_F, arg0, arg1, regs.rax);

  printf("Restoring original data at 0x%llx and rerun\n", regs.rcx-(sizeof(payload)-1));

#if 0
  // Pop saved RAX off stack - Not anymore!
  unsigned long* stack;
  map_guest_pointer(details, stack, regs.rsp);
  details->orig_regs.rax = stack[0];
  details->orig_regs.rsp += 8;
#endif

  char* host_ptr;
  map_guest_pointer(details, host_ptr, regs.rcx-(sizeof(payload)-1));
  memcpy(host_ptr, clobbered_data, sizeof(payload)-1);
  // Have hyde run a no-op syscall, and on return jump back to the original (now-restored) instruction

  // Jump back to original PC: read out of RCX, decrement by the payload size +1
  details->custom_return = regs.rcx-(sizeof(payload)-1);

  printf("Insert breakpoint2 at %llx\n", regs.rcx);
  char* target_data2;
  map_guest_pointer_status(details, target_data2, regs.rcx, &success);
  hookedB = regs.rcx+2;

  if (success) {
    // Store data we clobber and then log it
    memcpy(clobbered_data2, target_data2, sizeof(payload2)-1);
    printf("\tClobbering %ld bytes of data: ", sizeof(payload2)-1);
    for (int i=0; i < 10; i++) {
      printf("%02x ", target_data2[i]&0xff);
    }
    printf("\n\t             with new data: ");
    for (int i=0; i < sizeof(payload2)-1; i++) {
      printf("%02x ", payload2[i]&0xff);
    }
    printf("\n");
    // Clobber the data
    memcpy(target_data2, payload2, sizeof(payload2)-1);
  }else{
    printf("Failed to insert\n");
  }
  printf("\n");

  printf("Revert to restored layer1 at %lx\n", details->custom_return);

#if 0
  // TODO: how can we keep the syscall in memory after the original is rerun? Single stepping?
  // Set breakpoint on instruction just *after* clobbered data
  int rv = kvm_insert_breakpoint(details->cpu, regs.rcx, /*size=*/1, /*type=GDB_BREAKPOINT_HW*/1);
  if (rv !=0 ) {
    printf("Error inserting bp: %d\n", rv);
  }

  // XXX WIP: enable CPU TF - then run a no-op to make it stick (could move change into here?)
  //yield_syscall(details, __NR_getuid); // Junk

  //enable_singlestep(details); // With this set, we get a trap *BEFORE* we hit the RCX (post-clobber) address

  //details->orig_regs.rflags |= 0x100; // Set TF bit - necessary for bkpt to trigger??

#endif
  // Do we need this?
  yield_syscall(details, __NR_getuid); // Junk syscall - need this at the end, otherwise some of our changes don't take? (not sure which?)
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno, long unsigned int pc) {
  //printf("Syscall at %lx\n", pc);

  if (callno == __NR_open || callno == __NR_openat) {
    return &start_coopter_open;
  }else if (callno == __NR_mmap) {
    return &start_coopter_mmap;
  }

  if (pc == hookedA) {
    return &start_coopter_custom;
  }else if (pc == hookedB) {
    return &start_coopter_custom2;
  }

  return NULL;
}
