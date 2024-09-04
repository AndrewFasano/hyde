#include <iostream>
#include <cassert>
#include "hyde_sdk.h"

// Unit test: can we run syscalls repeatedly and get the same (expected) results
SyscallCoroutine run_test(SyscallCtx* ctx) {
    int pid = yield_syscall(ctx, getpid);
    int tid = yield_syscall(ctx, gettid);
    int uid = yield_syscall(ctx, getuid);

    // Make sure we stay in the same process
    for (int i=0; i < 100; i++) {
      assert(pid == yield_syscall(ctx, getpid));
      assert(tid == yield_syscall(ctx, gettid));
      assert(uid == yield_syscall(ctx, getuid));
    }

    std::cout << "PASS " << pid << " " << tid << " " << uid << std::endl;
    co_yield *(ctx->get_orig_syscall());
    co_return ExitStatus::FINISHED;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_getuid] = run_test;
  return true;
}