#include <sys/syscall.h> // for SYS_
#include <iostream> // cout, cerr
#include <set>

#include "hyde.h"
#include "file_helpers.h"

uint64_t counter = 0; 
int N = -1; // Every N syscalls we'll run inject_getpid

SyscallCoroutine inject_getpid(syscall_context* details) {
  //printf("[INJECT before %lu]\n", details->orig_syscall->callno);
  //dump_syscall(details->orig_syscall);
  pid_t pid = yield_syscall0(details, getpid);
  //printf("%lx (%d): wants to run %lu - coopted\n", details->asid, pid, details->orig_syscall->callno);

  co_yield *(details->orig_syscall);
  //printf("\toriginal syscall returns: %ld\n", details->last_sc_retval);
  co_return ExitStatus::SUCCESS;
}

void __attribute__ ((constructor)) setup(void) {
    if (getenv("N") != NULL && atoi(getenv("N")) != 0) {
      N = atoi(getenv("N"));
    } else {
      std::cerr << "ERROR: N must be set to a non-zero integer" << std::endl;
      exit(1);
    }
}

void __attribute__ ((destructor)) teardown(void) {
  std::cout << "Total number of syscalls: " << counter << std::endl;
}

// set of syscalls we've coopted
std::set<long unsigned int> coopted_syscalls;

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

  if ((counter++ % N) == 0) {
    // TODO: exit and vfork can't be injected before??
    // fork makes sense - child will start modified and un-coopted? Maybe? I'm not so sure anymore.
    // shouldn't the parent be all cleaned up before the fork happens?
    /*
    if (callno == SYS_exit_group || 
        callno == SYS_vfork || 
        callno == SYS_exit || 
        callno == SYS_clone || 
        callno == SYS_fork)
          return NULL;
    */

    // Only inject in a few, make sure they work
    // Just 1 - works
    if (callno == 0) return &inject_getpid;
  }

  //printf("%x: wants to run %lu - allowed\n", asid, callno);

  return NULL;
}