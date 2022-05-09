#include <asm/unistd.h> // Syscall numbers
#include <coroutine>
#include <stdio.h>
#include "hyde.h"

bool should_coopt(void*cpu, long unsigned int callno) {
  return callno == __NR_execve;
}


SyscCoroutine start_coopter(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // Create `envp` - pointer to target env
  char* fname;
  bool success;
  map_guest_pointer_status(fname, details, get_arg(regs, 0), &success);
  assert(success);
  __u64 guest_envp = get_arg(regs, 2);
  printf("\nExec of %s with env list starting at guest %llx\n", fname, guest_envp);

  // Get a pointer to the env list
  __u64* host_envp;
  map_guest_pointer_status(host_envp, details, guest_envp, &success);

  __u64 pagenum = (__u64)&host_envp >> 4;

  for (int i=0; i < 100; i++) {
    // Check if host pointer is on a new page, if so recalculate
    if (((__u64)&host_envp[i] >> 4) != pagenum ) {
      map_guest_pointer_status(host_envp, details, guest_envp + (8*i), &success);
      assert(success);
      pagenum = (__u64)&host_envp >> 4;
      host_envp -= i; // Shift back so we can index at i to get the start of our new mapping
    }

    if (host_envp[i] == 0) break;
    char* env_val;
    map_guest_pointer_status(env_val, details, host_envp[i], &success);
    assert(success);
    printf(" env[%d] @ guest 0x%llx | host %p => %s\n", i, guest_envp + (8*i), &host_envp[i], env_val);
  }
}
