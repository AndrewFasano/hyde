#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include <cstring> // memcpy
#include <sys/mman.h> // for mmap flags
#include "hyde.h"

SyscCoroutine inject_shellcode(asid_details* details) {
  __u64 guest_buf = (__u64)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_EXEC,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  char* host_buf;
  map_guest_pointer(details, host_buf, guest_buf);

  // HyDE push PC, jump into our shellcode, set RV, and ret
  long unsigned int *stack;
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  map_guest_pointer(details, stack, regs.rsp);

  // Configurable payload: - For now just return
  //host_buf[0] = '\xc3'; // Just return

  // "Push" pc which was in RCX by placing it above the top of the stack - XXX the syscall itself could clobber this?
  stack[-1] = details->orig_regs.rcx; // Instruction at this address isn't run until our shellcode returns to it

  // After the original syscall returns, we'll
  // 1) Decrement RSP so our above-stack value is there
  // 2) Change RIP so we jump to the target PC

  // Create local function
  std::function<void(char*, unsigned long int, struct kvm_regs*)> on_return = [](char* host_buf, unsigned long int guest_buf, struct kvm_regs* new_regs) {
      printf("In on return - Force CPU to jump to %lx\n", guest_buf);
      host_buf[0] = '\xc3';
      new_regs->rsp -= 8;
      new_regs->rip = guest_buf;
  };

  // Create closure with bind and move to heap
  details->modify_on_ret = new std::function<void(struct kvm_regs*)>(std::bind(on_return, host_buf, guest_buf, std::placeholders::_1));
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  if (callno == __NR_nanosleep)
    return &inject_shellcode;
  return NULL;
}
