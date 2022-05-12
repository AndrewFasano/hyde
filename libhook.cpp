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

static char* last_libname = NULL;
static unsigned long last_puts = 0;

//static char payload[] = "\x48\xC7\xC0\x0D\x00\x00\x00\x0F\x01\xC1"
static char payload[] = "\x48\xC7\xC0\xFF\xFF\x00\x00\x0F\x05"; // syscall with rax=0xffff
static char clobbered_data[sizeof(payload)];

void hydpercall_handle(void* cpu, long unsigned int nr, long unsigned int rip,
                       long unsigned int rbx, long unsigned int a2, long unsigned int a3,
                       long unsigned int a4, long unsigned int a5) {

  int error;
  long unsigned int orig_rip = rip-7; // XXX CUSTOMIZE
  printf("\n\nHyDEpercall\n");
  printf("nr 0x%lx, rip 0x%lx (orig was 0x%lx), rbx 0x%lx\n", nr, rip, orig_rip, rbx);

  // Translate original RIP to host pointer and print data
  __u64 cur_insn_ptr = translate(cpu, orig_rip, &error);
  if (error) {
    printf("Bad translate\n");
    return;
  }
  for (int i=0; i < sizeof(payload)-1; i++) {
    printf("Byte [%02d] at %lx is %02x\n", i, orig_rip+i, ((char*)cur_insn_ptr)[i]&0xff);
  }

  // Restore data
  //memcpy((void*)cur_insn_ptr, clobbered_data, sizeof(payload));

  // Read all registers, then revert PC
  struct kvm_regs regs;
  assert(getregs(cpu, &regs) == 0 && "Couldn't get regs");

  //printf("\nREGS PC=%llx RSP=%llx:\n", regs.rip, regs.rsp);
  //dump_regs(regs);
  regs.rip = orig_rip-2;

  assert(setregs(cpu, &regs) && "Couldn't set regs");
}

bool should_coopt(void*cpu, long unsigned int callno) {
  // We inject syscalls starting at every execve
  return callno == __NR_open || callno == __NR_openat || callno == __NR_mmap || callno == 0xFFFF;
}

SyscCoroutine start_coopter(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  int callno = CALLNO(regs);

  if (callno == 0xFFFF) {
    printf("ZOMG\n");
    details->skip = true;
    set_RET(details->orig_regs, (__u64)0);

  }else if (callno == __NR_open || callno == __NR_openat) {
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

    //printf("[HYDE] Saw open of a library: %s\n", host_targname);
    if (last_libname != NULL)
      free(last_libname);
    last_libname = strdup(host_targname);

  } else {
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
    __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
        get_arg(regs, 0), get_arg(regs, 1), get_arg(regs, 2),
        get_arg(regs, 3), get_arg(regs, 4), get_arg(regs, 5));

    char* host_data;
    map_guest_pointer(details, host_data, guest_buf);

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
          printf("[HYDE] Warning: found too many elements - ignoring\n");
        }else if (numelements > 0) {
          for (int i=0; i < numelements; i++) {
            Elf64_Sym *onesymtab;
            map_guest_pointer(details, onesymtab, symtab+(sizeof(Elf64_Sym)*i));
            if (onesymtab->st_name < strtab_size && onesymtab->st_value != 0) {
              char* sym_name;
              map_guest_pointer(details, sym_name, strtab+onesymtab->st_name);
              __u64 sym_addr = (__u64)guest_buf + onesymtab->st_value;
              //printf("%llx: %s\n", sym_addr, sym_name);

              if (strcmp(sym_name, "puts") == 0 && sym_addr != last_puts){
                printf("\tFound puts at %llx\n", sym_addr);
                last_puts = sym_addr;
              }
            }
          }
        }
      }
    }

    if (prot & PROT_EXEC) {
      if (last_puts != 0 && (__u64)guest_buf < last_puts) {
        char* target_data;
        bool success;
        map_guest_pointer_status(details, target_data, last_puts, &success);
        if (success) {
          if (memcmp(target_data, payload, sizeof(payload)-1) != 0) {
            printf("[HyDE] Rewriting puts in memory at %lx to add hypercall\n", last_puts);
            memcpy(clobbered_data, target_data, sizeof(payload)-1);
            printf("Clobbering %ld bytes of data: ", sizeof(payload)-1);
            for (int i=0; i < sizeof(payload)-1; i++) {
              printf("%02x ", target_data[i]&0xff);
            }
            printf("\n              with new data: ");
            for (int i=0; i < sizeof(payload)-1; i++) {
              printf("%02x ", payload[i]&0xff);
            }
            printf("\n");
            memcpy(target_data, payload, sizeof(payload)-1);
          }
        }else{
          printf("Failed to map guest pointer for symbol: %lx\n", last_puts);
        }
        //last_puts = 0;
      }
    }

    // restore all regs, then set desired return value
    details->skip = true;
    memcpy(&details->orig_regs, &regs, sizeof(regs));
    set_RET(details->orig_regs, (__u64)guest_buf);
  }

#if 0
  __u64 *guest_envp = (__u64*)get_arg(regs, 2); // Can't dereference on host, just use for addrs

  // Create guest and host envp references and use to read arguments out
  __u64 *host_envp; // Can dereference on host
  __u64 *guest_envp = (__u64*)get_arg(regs, 2); // Can't dereference on host, just use for addrs
  for (int i=0; i < 255; i++) {
    map_guest_pointer(host_envp, details, &guest_envp[i]);
    if (*host_envp == 0) break;
    char* env_val;
    map_guest_pointer(env_val, details, *host_envp);

    if (strncmp(inject.c_str(), env_val, inject.find('=')+1) == 0) {
      // Existing env var duplicates the one we're injecting - don't save it
      continue;
    }
    guest_arg_ptrs.push_back(*host_envp);
    arg_list.push_back(std::string(env_val));
  }
  // Note these have to happen at the very end, otherwise subsequent injects will clobber
  //set_ARG2(details->orig_regs, (__u64)guest_buf);
  //details->modify_original_args = true;
#endif
}
