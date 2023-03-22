#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include "hyde.h"

// Not sure what this example is supposed to do, for now it just prints names and uid/pid info pre-execve

SyscCoroutine pre_exec(asid_details* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // Copy first argument (name) into host buffer
  char fname[128];
  yield_from(details, ga_memread, fname, get_arg(regs, RegIndex::ARG0), sizeof(fname));

  printf("[NoRootID] SYS_exec(%s)\n", fname);
  int uid = yield_syscall0(details, getuid); // callno102

  if (uid != 0) {
    int pid = yield_syscall0(details, getpid); // callno=39
    printf("[NoRootID]: Non-root process! UID is %lld PID is %lld\n", uid, pid);
  }

  co_yield *(details->orig_syscall); // callno=59
  co_return ExitStatus::SUCCESS;
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  if (callno == SYS_execve)
    return &pre_exec;
  return NULL;
}