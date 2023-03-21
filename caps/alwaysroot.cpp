#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include "hyde.h"

SyscCoroutine start_coopter(asid_details* details) {
  // Don't run the original syscall, set the result to 0
#if 0
  __u64 pid = yield_syscall(details, __NR_getpid);
  printf("[coopter] PID is %llx\n", pid);

  __u64 uid = yield_syscall(details, __NR_getuid);
  printf("[coopter] UID is %llx\n", uid);
#endif
  // Note we *don't* run the original syscall, instead we just set the RV directly
  //co_yield *(details->orig_syscall);
  details->orig_syscall->has_retval = true;
  details->orig_syscall->retval = 0;

  co_return;
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  if (callno == __NR_getuid || callno == __NR_geteuid)
    return &start_coopter;
  return NULL;
}

