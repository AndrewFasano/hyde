#include <sys/syscall.h> // for SYS_
#include <iostream> // cout, cerr
#include <set>

#include <coroutine>

#include "syscall_coroutine.h"
#include "hyde_common.h"

#include "hyde_sdk.h"
#include "file_helpers.h"

uint64_t counter = 0; 
int N = -1; // Every N syscalls we'll run inject_getpid


SyscallCoroutine inject_getpid(SyscallCtx* ctx) {
  if (counter++ % N == 0) {
    int rv = yield_syscall(ctx, getpid);
  }

  yield_and_finish(ctx, *ctx->get_orig_syscall(), ExitStatus::SUCCESS);
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
  std::cerr << "[Perf_eval]: Observed " << counter << ". guest syscalls. Injected getpid between every " << N << "." << std::endl;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[-1] = inject_getpid;

  return true;
}
