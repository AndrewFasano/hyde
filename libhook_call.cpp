#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/mman.h> // for mmap flags
#include <vector>
#include <linux/elf.h>
#include <map>
#include <byteswap.h>
#include "hyde.h"

#define TARG_F "puts"
//#define TARG_F "raise"

std::map<unsigned int, long unsigned int> asid_puts_map;
std::map<unsigned int, unsigned int> asid_count;

SyscCoroutine start_coopter_open(asid_details* details) {
  if (!asid_puts_map.contains(details->asid)) {
    // We don't know where puts is in this process - skip it
    co_return;
  }

  if (!asid_count.contains(details->asid)) {
    asid_count[details->asid] = 0;
  }

  if (asid_count[details->asid]++ < 20) {
    co_return;
  }

  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // Allocate a buffer
  __u64 guest_buf = (__u64)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_EXEC  | PROT_READ,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  printf("Target syscall reached in %x, on return run shellcode at %llx to call %s at %lx\n", details->asid, guest_buf, TARG_F, asid_puts_map[details->asid]);

#if 0
  bool success;
  char *foo;
  printf("\nPuts:");
  map_guest_pointer_status(details, foo, asid_puts_map[details->asid], &success);
  if (!success) {
    printf("No puts ready - bail\n");
    co_return;
  }
  for (int i=0; i < 20; i++) {
    printf("%02x ", foo[i]&0xff);
  }
  printf("\n\n");
#endif

  // Get host pointers to shellcode and stack to use on return
  char* host_buf;
  long unsigned int *stack;
  map_guest_pointer(details, host_buf, guest_buf);
  map_guest_pointer(details, stack, regs.rsp);

  // On return, we'll update guest state
  auto on_return = [](char* host_buf, unsigned long int guest_buf, long unsigned int *host_stack, long long unsigned int orig_pc,
                      unsigned long int puts_addr, struct kvm_regs* new_regs) {
      printf("Syscall has returned with RAX=%llx - force CPU to jump to shellcode at %lx\n", new_regs->rax, guest_buf);
/*
0:  55                      push   rbp
1:  48 89 e5                mov    rbp,rsp
4:  48 83 e4 f0             and    rsp,0xfffffffffffffff0
8:  57                      push   rdi
9:  50                      push   rax
a:  6a 00                   push   0x0
c:  6a 00                   push   0x0
e:  48 bf 45 23 01 89 67    movabs rdi,0x123456789012345
15: 45 23 01
18: 48 b8 45 23 01 89 67    movabs rax,0x123456789012345
1f: 45 23 01
22: ff d0                   call   rax
24: 58                      pop    rax
25: 58                      pop    rax
26: 58                      pop    rax
27: 5f                      pop    rdi
28: 48 89 ec                mov    rsp,rbp
2b: 5d                      pop    rbp
2c: c3                      ret
*/
      // Prologue & epilogue XXX: Function *MUST* align stack pointer to be an 16-byte aligned before calling other fucntions!!! (E.g., with `and rsp, -16`)
      char sc_template[] = "\x55\x48\x89\xE5\x48\x83\xE4\xF0\x57\x50\x6A\x00\x6A\x00\x48\xBF\x45\x23\x01\x89\x67\x45\x23\x01\x48\xB8\x45\x23\x01\x89\x67\x45\x23\x01\xFF\xD0\x58\x58\x58\x5F\x48\x89\xEC\x5D\xC3" ;

      assert(sizeof(sc_template) < 0x100); // Don't let shellcode overlap with arg

      // Argument goes here in RDI
      unsigned long int data = guest_buf+0x100;
      for (int i=0; i < 8; i++) {
        sc_template[(0xe)+2+i] = ((char*)&data)[i];
      }

      // Adress to call goes here in RAX which is the called
      data = puts_addr;
      for (int i=0; i < 8; i++) {
        sc_template[0x18+2+i] = ((char*)&data)[i];
      }

#if 0
      // Post-call syscall arg 1 in RDI: Address
      data = guest_buf;
      for (int i=0; i < 8; i++) {
        sc_template[0x26+i] = ((char*)&data)[i];
      }

      // Post-call syscall arg 2 in RSI: Size
      //data = 0x0040000000000000; //(size_t)1024 as a 64-bit value?
      data = 0;
      for (int i=0; i < 8; i++) {
        sc_template[0x30+i] = ((char*)&data)[i];
      }
#endif
      for (int i=0; i < sizeof(sc_template); i++) {
        printf("%02x ", sc_template[i]&0xff);
      }
        printf("\n\n");

      // In our buffer, this is our message (RDI points here)
      memcpy(host_buf, sc_template, sizeof(sc_template));
      sprintf(&host_buf[0x100], "Hello world this is HyDE-injected shellcode running at %lx guest was supposed to go to %#llx!\n" \
                                  " .----------------.  .----------------.  .----------------.  .----------------.  \n" \
                                  "| .--------------. || .--------------. || .--------------. || .--------------. | \n" \
                                  "| |  ____  ____  | || |  ____  ____  | || |  ________    | || |  _________   | | \n" \
                                  "| | |_   ||   _| | || | |_  _||_  _| | || | |_   ___ `.  | || | |_   ___  |  | | \n" \
                                  "| |   | |__| |   | || |   \\ \\  / /   | || |   | |   `. \\ | || |   | |_  \\_|  | | \n" \
                                  "| |   |  __  |   | || |    \\ \\/ /    | || |   | |    | | | || |   |  _|  _   | | \n" \
                                  "| |  _| |  | |_  | || |    _|  |_    | || |  _| |___.' / | || |  _| |___/ |  | | \n" \
                                  "| | |____||____| | || |   |______|   | || | |________.'  | || | |_________|  | | \n" \
                                  "| |              | || |              | || |              | || |              | | \n" \
                                  "| '--------------' || '--------------' || '--------------' || '--------------' | \n" \
                                  " '----------------'  '----------------'  '----------------'  '----------------'  \n", guest_buf, orig_pc);

      // Here we're both simulating a fake function call (push orig_pc)
      // *and* a function prologue <- Er, not anymore
      // XXX we *MUST* have our stack be 16-byte aligned + 8

      //host_stack[-2] = 0x121212;
      host_stack[-1] = orig_pc;

      //new_regs->rbp = new_regs->rsp;
      new_regs->rsp -= 8;
      //assert(new_regs->rsp % 16 == 0);

      // Then we go to our payload
      new_regs->rip = guest_buf;
  };

  // Create closure with bind and move to heap
  details->modify_on_ret = new std::function<void(struct kvm_regs*)>(std::bind(on_return,
                                                                                host_buf, guest_buf, stack, details->orig_regs.rcx,
                                                                                asid_puts_map[details->asid], std::placeholders::_1));
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
  __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
      get_arg(regs, 0), get_arg(regs, 1), get_arg(regs, 2),
      get_arg(regs, 3), get_arg(regs, 4), get_arg(regs, 5));

  char* host_data;
  map_guest_pointer(details, host_data, guest_buf);

  unsigned long int func_addr = 0;
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

            if (strcmp(sym_name, TARG_F) == 0 && sym_addr != func_addr){
              //printf("[HYDE] \tFound %s at %llx\n", TARG_F, sym_addr);
              func_addr = sym_addr;
            }
          }
        }
      }
    }
  }

  // In asid we found puts at func_addr
  if (func_addr != 0) {
    if (!asid_puts_map.contains(details->asid)) {
      //printf("In asid %x we have %s at %lx\n", details->asid, TARG_F, func_addr);
      asid_puts_map[details->asid] = func_addr;
    }else{
      printf("In asid %x we found a SECOND %s at %lx\n", details->asid, TARG_F, func_addr);
    }
  }

  // restore all regs, then set desired return value
  details->skip = true;
  memcpy(&details->orig_regs, &regs, sizeof(regs));
  set_RET(details->orig_regs, (__u64)guest_buf);
}

SyscCoroutine sys_exit(asid_details* details) {
  if (asid_puts_map.contains(details->asid)) {
    asid_puts_map.erase(details->asid);
  }
  co_return;
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  if (callno == __NR_open || callno == __NR_openat) {
  //if (callno == __NR_mkdir) {
  //if (callno == __NR_nanosleep) {
  //if (callno == __NR_listen) {
    return &start_coopter_open;
  }else if (callno == __NR_mmap) {
    return &start_coopter_mmap;
  }else if (callno == __NR_exit || callno == __NR_exit_group) {
    return &sys_exit;
  }
  return NULL;
}
