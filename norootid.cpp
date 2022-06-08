#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include "hyde.h" // Hyde-API is provided in qemu which we can call into to thanks to `-rdynamic` linker flag

SyscCoroutine start_coopter(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // Create `fname`, a pointer into *guest* memory at the address that's in the first syscall arg
  char * fname;
  map_guest_pointer(details, fname, get_arg(regs, 0));

  printf("[NoRootID] SYS_exec(%s)\n", fname);
  __u64 uid = yield_syscall(details, __NR_getuid); // callno102

  if (uid != 0) {
    __u64 pid = yield_syscall(details, __NR_getpid); // callno=39
    printf("[NoRootID]: Non-root process! UID is %lld PID is %lld\n", uid, pid);
  }

  // When we yield the original execve, we lose control over the process because
  // it returns into the child process
  co_yield *(details->orig_syscall); // callno=59
  // Subsequent code won't run because it's execve
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  if (callno == __NR_execve)
    return &start_coopter;
  return NULL;
}

