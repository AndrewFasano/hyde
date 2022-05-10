#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include "hyde.h"

bool should_coopt(void*cpu, long unsigned int callno) {
  return callno == __NR_getuid;
}

SyscCoroutine start_coopter(asid_details* details) {
  // Test: don't run syscall, just set RV to 0 *always*
  details->skip = true;
  set_RET(details->orig_regs, 0);
  co_return;
}


