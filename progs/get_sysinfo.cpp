#include <sys/sysinfo.h>
#include "hyde_sdk.h"

SyscallCoroutine get_sysinfo(SyscallCtx* ctx) {
    // Example: run sysinfo in the guest
    struct sysinfo info;
    int rv = yield_syscall(ctx, sysinfo, &info);
    printf("Guest sysinfo returns %d, uptime is %lu seconds\n", rv, info.uptime);

    // Compare to running sysinfo on the host
    struct sysinfo host_sysinfo;
    int host_rv = syscall(SYS_sysinfo, &host_sysinfo);
    printf("Host sysinfo returns %d, updtime is %lu seconds\n", host_rv, host_sysinfo.uptime);

    char msg[] = {"[Guest] Hello - I'm inside the guest before getuid!\n"};
    size_t bytes_written = yield_syscall(ctx, write, 1, msg, strlen(msg));
    printf("[HyDE Prog] write syscall returns %lu (expected %lu)\n", bytes_written, strlen(msg));

    co_yield *(ctx->get_orig_syscall());
    co_return ExitStatus::FINISHED;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  // When a guest process tires to run getuid, co-opt with our get_sysinfo logic
  map[SYS_getuid] = get_sysinfo;
  return true;
}