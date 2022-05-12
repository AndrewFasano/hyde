#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include "hyde.h"

SyscCoroutine start_coopter(asid_details* details) {
  // Test: don't run syscall, just set RV to 0 *always*
  details->skip = true;
  set_RET(details->orig_regs, 0);
  co_return;
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  if (callno == __NR_getuid)
    return &start_coopter;
  return NULL;
}

