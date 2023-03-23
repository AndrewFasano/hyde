#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include "hyde.h"

#define PRE_INJECT

SyscCoroutine start_coopter(asid_details* details) {
  // Test: Change writes to stderr to be shifted by 1 char
  // If pre-inject is set we first inject a syscall
  // otherwise we just modify without an inject
#ifdef PRE_INJECT
  __u64 pid = yield_syscall(details, __NR_getpid);
  printf("PID %lld is doing a print, let's shift it\n", pid);
#endif

  // We should see the `password` prompt at login become `assword`
  details->modify_original_args = true;
  __u64 foo = get_arg(details->orig_regs, 1);
  set_ARG1(details->orig_regs, foo+1);
  co_return;
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  if (callno == __NR_write) {
    struct kvm_regs r;
    assert(getregs(cpu, &r) == 0);
    if (get_arg(r, 0) == 2) // Is it writing to (probably) stderr?
      return &start_coopter;
  }
  return NULL; 
}


