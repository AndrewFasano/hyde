#include <sys/sysinfo.h>
#include "hyde_sdk.h"

SyscallCoroutine guest_sysinfo(SyscallCtx* ctx) {
  struct sysinfo info;
  yield_syscall(ctx, sysinfo, &info);
  printf("Uptime is %lu seconds\n", info.uptime);
  printf("Number of processes: %d\n", info.procs);
  printf("Load average (1/5/15 min): %lu %lu %lu\n",
      info.loads[0], info.loads[1], info.loads[2]);

  // Finish by running the original syscall and unloading this plugin
  yield_and_finish(ctx, ctx->pending_sc(), ExitStatus::FINISHED);
}

bool init_plugin(CoopterMap map) {
  // Before any guest process runs any syscall, launch our coroutine
  map[-1] = guest_sysinfo;
  return true;
}