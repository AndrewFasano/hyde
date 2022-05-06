#include <asm/unistd.h> // Syscall numbers
#include <coroutine>
#include <stdio.h>
#include "hyde.h" // Hyde-API is provided in qemu which we can call into to thanks to `-rdynamic` linker flag

// Functions *we provide* should be extern C to avoid mangling
extern "C" {
  bool should_coopt(void*cpu, long unsigned int callno);
  SyscCoroutine start_coopter(asid_details* r);
}

bool should_coopt(void*cpu, long unsigned int callno) {
  return callno == __NR_execve;
}

SyscCoroutine start_coopter(asid_details* r) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  int rv = getregs(r, &regs);
  if (rv != 0) {
    printf("[HYDE] Fatal error reading registers, bailing: %d\n", rv);
    co_return;
  }

  // Read first argument from guest memory
  hsyscall sc;
  __u64 fname = memread(r, ARG0(regs), &sc);

  if (fname == (__u64)-1) {
    // Read failed - we need to injrect a syscall
    co_yield sc;
    fname = memread(r, ARG0(regs), nullptr);
  }

  printf("[NoRootID] SYS_exec(%s)\n", (char*)fname);
  build_syscall(&sc, __NR_getuid);
  co_yield sc;

  if (r->retval != 0) {
    auto uid = r->retval;

    build_syscall(&sc, __NR_getpid);
    co_yield sc;
    printf("[NoRootID]: Non-root process! UID is %ld PID is %ld\n", uid, r->retval);
  }
}
