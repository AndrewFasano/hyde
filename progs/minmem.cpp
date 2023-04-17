#include <sys/sysinfo.h>
#include "hyde.h"

SyscallCoroutine start_coopter(syscall_context* details) {
    struct sysinfo info;
    int rv = yield_syscall(details, sysinfo, &info);
    printf("Guest sysinfo returns %d, uptime is %lu seconds\n", rv, info.uptime);

    struct sysinfo host_sysinfo;
    int host_rv = syscall(SYS_sysinfo, &host_sysinfo);
    printf("Host sysinfo returns %d, updtime is %lu seconds\n", host_rv, host_sysinfo.uptime);

    char msg[] = {"[Guest] Hello - I'm inside the guest before getuid!\n"};
    size_t bytes_written = yield_syscall(details, write, 1, msg, strlen(msg));
    printf("[HyDE Prog] write syscall returns %lu (expected %lu)\n", bytes_written, strlen(msg));

    co_yield *(details->orig_syscall); // Run original syscall
    co_return ExitStatus::FINISHED;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno, long unsigned int pc, unsigned int asid) {
  if (callno == SYS_getuid || callno == SYS_geteuid)
    return &start_coopter;
  return NULL;
}

#if 0
SyscallCoroutine test(syscall_context* details) {
  int fd = 1;
  char out_path[128];
  char in_path[128];

  snprintf(in_path, sizeof(in_path), "/proc/self/fd/%d", fd);
  int readlink_rv = yield_syscall(details, readlink, in_path, out_path, sizeof(out_path));

  printf("Readlink of %s returns %d with out_path=%s\n", in_path, readlink_rv, out_path);

  struct sysinfo info;
  yield_syscall(details, sysinfo, &info);
  printf("Guest uptime is %lu seconds\n", info.uptime);

  char msg[] = {"Hello from the coopter!\n"};
  int bytes_written = yield_syscall(details, write, 1, msg, strlen(msg));
  printf("Wrote %d bytes into guest (expected %lu)\n", bytes_written, strlen(msg));

  co_yield (*details->orig_syscall);

  co_return 0;
}

int main(int argc, char **argv) {

  // Start executing the start_coopter coroutine. Say we were co-opting the getuid syscall.
  syscall_context *details = new syscall_context({
    .orig_syscall = new hsyscall({
      .callno = __NR_getuid,
      .nargs = 0
    })
  });

  auto h = test(details).h_;
  auto &promise = h.promise();
  while(!h.done()) {
    auto sc = promise.value_;
    if (sc.callno == SYS_mmap) {
      details->last_sc_retval = 0x100000;
    }else {
      details->last_sc_retval = 0; // Lie?
    }
    h();
  }
  h.destroy();
  return 0;
}
#endif
