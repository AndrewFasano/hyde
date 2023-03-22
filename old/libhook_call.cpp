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
#include <keystone/keystone.h>
#include "hyde.h"

#define TARG_F "puts"
//#define TARG_F "raise"

std::map<unsigned int, long unsigned int> asid_puts_map;
std::map<unsigned int, unsigned int> asid_buffers;

SyscCoroutine start_coopter_open(asid_details* details) {
  if (!asid_puts_map.contains(details->asid)) {
    // We don't know where puts is in this process - skip it
    co_return;
  }

  //if (!asid_count.contains(details->asid)) {
  //  asid_count[details->asid] = 0;
  //}
  //if (asid_count[details->asid]++ < 20) {
  //  co_return;
  //}

  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // Allocate a buffer
  __u64 guest_buf = (__u64)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_EXEC  | PROT_READ,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  printf("Target syscall reached in %x. On return we will run shellcode at %llx that will call %s at %lx\n",
         details->asid, guest_buf, TARG_F, asid_puts_map[details->asid]);

  // Store the buffer associated with this asid so we can later free it
  asid_buffers[details->asid] = guest_buf;

  // Get host pointers to shellcode and stack to use on return
  char* host_buf;
  long unsigned int *stack;
  map_guest_pointer(details, host_buf, guest_buf);
  map_guest_pointer(details, stack, regs.rsp);

  // On return, we'll update guest state
  auto on_return = [](char* host_buf, unsigned long int guest_buf, long unsigned int *host_stack, long long unsigned int orig_pc,
                      unsigned long int puts_addr, struct kvm_regs* new_regs) {
      ks_engine *ks;
      ks_err err;
      size_t count;
      unsigned char *shellcode;
      size_t size;
      char asm_code[2048];

      printf("Syscall has returned with RAX=%llx - force CPU to jump to shellcode at %lx\n", new_regs->rax, guest_buf);

      assert(new_regs->rsp % 8 == 0); // Can either end with 8 or 0
      bool rsp_aligned = (new_regs->rsp % 16 == 0);
      assert(ks_open(KS_ARCH_X86, KS_MODE_64, &ks) == KS_ERR_OK);

      // "Function" of shellcode with prologue and epilogue
      // XXX: Function *MUST* align stack pointer to be an 16-byte aligned before calling other fns
      sprintf(asm_code, "\
push rbp;         \n  \
mov rbp, rsp;     \n  \
and rsp, -512;    \n  \
\n \
mov     [rsp+0x10+0x08], rax \n \
mov     [rsp+0x10+0x10], rcx \n \
mov     [rsp+0x10+0x18], rdx \n \
mov     [rsp+0x10+0x20], rsi \n \
mov     [rsp+0x10+0x28], rdi \n \
mov     [rsp+0x10+0x30], r8  \n \
mov     [rsp+0x10+0x38], r9  \n \
mov     [rsp+0x10+0x40], r10 \n \
mov     [rsp+0x10+0x48], r11 \n \
\n \
\n \
movabs rdi,%#lx;  \n  \
movabs rax,%#lx;  \n  \
call rax;         \n  \
\n \
mov  rax,  [rsp+0x10+0x08]\n \
mov  rcx,  [rsp+0x10+0x10]\n \
mov  rdx,  [rsp+0x10+0x18]\n \
mov  rsi,  [rsp+0x10+0x20]\n \
mov  rdi,  [rsp+0x10+0x28]\n \
mov  r8 ,  [rsp+0x10+0x30]\n \
mov  r9 ,  [rsp+0x10+0x38]\n \
mov  r10,  [rsp+0x10+0x40]\n \
mov  r11,  [rsp+0x10+0x48]\n \
\n \
mov rsp, rbp;     \n  \
pop rbp;          \n  \
ret",
            /* RDI (argument) = */guest_buf+0x100,
            /* RAX (the func we call) = */puts_addr
            );

      //puts(asm_code);

      if (ks_asm(ks, asm_code, 0, &shellcode, &size, &count) != KS_ERR_OK) {
          printf("ERROR: ks_asm() failed & count = %lu, error = %u\n", count, ks_errno(ks));
          assert(0);
      }
      // Copy the assembled payload into guest memory
      memcpy(host_buf, shellcode, size);
      ks_free(shellcode);
      ks_close(ks); // close Keystone instance

      // Add string argument into memory
      sprintf(&host_buf[0x100], "Hello world this is HyDE-injected shellcode running at %lx guest was supposed to go to %#llx!\n",
              guest_buf, orig_pc);

      // Here we're simulating a fake function call by pushing the original PC
      // that our shellcode should return to
      // XXX we *MUST* have our stack be 16-byte aligned + 8
      // We can't handle cleanup of that here, so it's the shellcode's problem :(

      // We set the old PC to be syscall
      // and we clobber RAX to be 0xFFFF
      // and save old RAX on stack
#if 0
      if (rsp_aligned) {
        // 16-byte aligned
        host_stack[-1] = orig_pc;
        //new_regs->rbp = new_regs->rsp;
        new_regs->rsp -= 8;
      } else {
        // 8-byte aligned
        host_stack[-2] = 0x11223344;
        host_stack[-1] = orig_pc;
        //new_regs->rbp = new_regs->rsp;
        new_regs->rsp -= 8;
      }
      //assert(new_regs->rsp % 16 == 0);
      //assert(new_regs->rsp % 16 == 0);
#endif

      printf("Old RAX was %llx\n", new_regs->rax);
      host_stack[-2] = orig_pc-2;
      host_stack[-1] = new_regs->rax;
      new_regs->rsp -= 16;
      new_regs->rax = 0xFFFF;

      // Then we jump to our shellcode
      new_regs->rip = guest_buf;
  };

  // Create closure with bind and move to heap
  details->modify_on_ret = new std::function<void(struct kvm_regs*)>(std::bind(on_return,
                                                                                host_buf, guest_buf, stack, details->orig_regs.rcx,
                                                                                asid_puts_map[details->asid], std::placeholders::_1));
}

SyscCoroutine post_libcall(asid_details* details) {
  // The current process ran syscall at PC X, we hijacked it on return
  // to run some shellcode and when we finished, we jumped back to the syscall
  // again, giving us a chance to clean up with more syscalls (or, I guess repeat the process)
  
  if (!asid_buffers.contains(details->asid)) {
    co_return;
  }

  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  long unsigned int *stack;
  map_guest_pointer(details, stack, regs.rsp);

  // We'll "pop" the original RAX (from first syscall return) off the stack
  long unsigned int orig_rax = stack[0];

  details->orig_regs.rsp += 8;
  details->modify_original_args = true;

  // We're going to inject a free and then skip
  __u64 free_ret = (__u64)yield_syscall(details, __NR_munmap,
      /*addr=*/asid_buffers[details->asid], /*size=*/1024);

  asid_buffers.erase(details->asid);
  details->skip = true;

  printf("Cleaned up after library call in %x. Resuming execution at %llx\n", details->asid, details->orig_regs.rcx);

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
  //if (callno == __NR_open || callno == __NR_openat) {
  //if (callno == __NR_mkdir) {
  if (callno == __NR_nanosleep) {
  //if (callno == __NR_listen) {
    return &start_coopter_open;
  }else if (callno == __NR_mmap) {
    return &start_coopter_mmap;
  }else if (callno == __NR_exit || callno == __NR_exit_group) {
    return &sys_exit;
  }else if (callno == 0xFFFF) {
    return &post_libcall;
  }
  return NULL;
}
