#include <sys/sysinfo.h>
#include "hyde_sdk.h"


#if 0
    // Compare to running sysinfo on the host
    struct sysinfo host_sysinfo;
    int host_rv = syscall(SYS_sysinfo, &host_sysinfo);
    printf("Host sysinfo returns %d, updtime is %lu seconds\n", host_rv, host_sysinfo.uptime);
#endif

SyscallCoroutine get_sysinfo(SyscallCtx* ctx) {
  // Example: run sysinfo in the guest
  struct sysinfo info;

  int rv = yield_syscall(ctx, sysinfo, &info);
  if (rv != 0) {
    co_yield_noreturn(ctx, *ctx->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
  }
  printf("Uptime is %lu seconds\n", info.uptime);
  printf("Total RAM: %lu MB\n", info.totalram / 1024 / 1024);
  printf("Free RAM: %lu MB\n", info.freeram / 1024 / 1024);
  printf("Number of processes: %d\n", info.procs);
  printf("Load average (1/5/15 min): %lu %lu %lu\n", info.loads[0], info.loads[1], info.loads[2]);

  co_yield_noreturn(ctx, *ctx->get_orig_syscall(), ExitStatus::FINISHED);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[-1] = get_sysinfo;
  return true;
}