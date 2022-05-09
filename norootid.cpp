#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include "hyde.h" // Hyde-API is provided in qemu which we can call into to thanks to `-rdynamic` linker flag

bool should_coopt(void*cpu, long unsigned int callno) {
  return callno == __NR_execve;
}

SyscCoroutine start_coopter(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // Create `fname`, a pointer into *guest* memory at the address that's in the first syscall arg
  make_guest_pointer(fname, details, get_arg(regs, 0));

  printf("[NoRootID] SYS_exec(%s)\n", (char*)fname);
  __u64 uid = yield_syscall(details, __NR_getuid);

  if (uid != 0) {
    __u64 pid = yield_syscall(details, __NR_getpid);
    printf("[NoRootID]: Non-root process! UID is %lld PID is %lld\n", uid, pid);
  }
}
