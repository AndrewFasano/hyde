#include <sys/syscall.h> // for SYS_
#include <iostream> // cout, cerr
#include <set>

#include <coroutine>

#include "syscall_coroutine.h"
#include "plugin_common.h"


#include "hyde_sdk.h"
#include "file_helpers.h"

uint64_t counter = 0; 
int N = -1; // Every N syscalls we'll run inject_getpid


#if 0
SyscallCoroutine inject_getpid(syscall_context* details) {
  printf("[INJECT before %lu]\n", details->orig_syscall->callno);
  //dump_syscall(details->orig_syscall);
  pid_t pid = yield_syscall(details, getpid);
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
  std::cerr << "Total number of syscalls: " << counter << std::endl;
}
#endif

SyscallCoroutine inject_getpid(syscall_context* ctx) {
  printf("PID: %ld\n", yield_syscall(ctx, getpid));
  co_yield *ctx->get_orig_syscall();
  co_return ExitStatus::SUCCESS;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  //all_syscalls = &inject_getpid;
  //printf("Set all syscalls at %p to %p\n", &all_syscalls, &inject_getpid);
  map[SYS_geteuid] = inject_getpid;

  return true;
}
