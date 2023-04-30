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

constexpr size_t BUF_SZ = 4096; // Standard minimum page size

SyscallCoroutine do_inject(SyscallCtx* ctx) {
  if (counter++ % N == 0) {
    uint64_t buffer = yield_syscall(ctx, mmap, 0, BUF_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int64_t sb = (int64_t)buffer;
    if (sb < 0 && sb > -4096) {
      std::cerr << "ERROR: mmap failed with errno " << sb << " after " << counter << " injections! " << std::endl;
      std::cerr << "Current PID is " << yield_syscall(ctx, getpid) << std::endl;
      //assert(0);
      //co_yield_noreturn(ctx, *ctx->get_orig_syscall(), ExitStatus::FATAL);
      hsyscall die = hsyscall(SYS_exit);
      die.set_arg(0, 1);
      die.nargs = 1;

      co_yield_noreturn(ctx, die, ExitStatus::SINGLE_FAILURE);
      //co_yield_noreturn(ctx, *ctx->get_orig_syscall(), ExitStatus::FINISHED);
    }
    int64_t rv = yield_syscall(ctx, munmap, buffer, BUF_SZ);
    if (rv < 0) {
      std::cerr << "Munmap failed with errno " << rv << " after " << counter << " injections!" << std::endl;
    }
  }

  co_yield_noreturn(ctx, *ctx->get_orig_syscall(), ExitStatus::SUCCESS);
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
  map[-1] = do_inject;
  return true;
}
