#include <asm/unistd.h> // Syscall numbers
#include <coroutine>
#include <stdio.h>
#include "hyde.h" // Hyde-API is provided in qemu which we can call into to thanks to `-rdynamic` linker flag

bool should_coopt(void*cpu, long unsigned int callno) {
  return callno == __NR_execve;
}


// Hardcoded config for now. Replace foo with zoo
#define PAGESIZE 0x1000

SyscCoroutine start_coopter(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // Create `envp` - pointer to target env
  char* fname;
  bool success;
  map_guest_pointer(fname, details, get_arg(regs, 0), &success);
  printf("\nExec of %s with env list starting at guest %llx\n", fname, get_arg(regs, 2));

  // Get host pointer to start of env list
  __u64* host_envp;
  char* tmp;
  map_guest_pointer(host_envp, details, get_arg(regs, 2), &success); // Only safe until % 0x1000

  for (int i=0; i < 100; i++) {
    char* env_val;

    if (i > 0 && (__u64)&host_envp[i] % PAGESIZE == 0) { /// XXX could also skip 0, need better check
      //printf("RETRANSL. guest %llx because host is on a new page: %p\n", get_arg(regs, 2) + (8*i),  &host_envp[i]);
      map_guest_pointer(host_envp, details, get_arg(regs, 2) + (8*i), &success);
      assert(success);
      //printf("New host mapping: %p\n", host_envp);
      // Test: can we read at idx 0, before we shift?
      //map_guest_pointer(env_val, details, host_envp[0], &success);
      //printf("\tAlt read: %s\n", env_val);
      //assert(success);

      host_envp -= i; // Shift back so we can index at i to get the start of our new mapping
      map_guest_pointer(env_val, details, host_envp[i], &success);
      assert(success);
      //printf("\tAlt read2: %s\n", env_val);
    }

    if (host_envp[i] == 0) break;
    map_guest_pointer(env_val, details, host_envp[i], &success);
    assert(success);
    printf("Env[%d] is at guest %llx and host %p => %s\n", i, get_arg(regs, 2)+(8*i), &host_envp[i], env_val);
  }


#if 0
  __u64 this_env_ptr;
  for(int i=0; i < 5; i++) {
    map_guest_pointer(this_env_ptr, details, envp);
    printf("Guest has %llx as env pointer. Can read this char** on host at %llx\n", envp, this_env_ptr);

    // Now that we have it as a host address, we read a *GUEST* pointer out of memory there
    __u64 guest_ptr = *(__u64*)this_env_ptr;
    if (guest_ptr == 0) break;
    printf("Var %d is at guest %llx\n", i, guest_ptr);

    // Now let's map the guest address
    map_guest_pointer(this_env_ptr_value, details, guest_ptr);

    printf("String is at %llx\n", guest_ptr);

    map_guest_pointer(foo, details, this_env_ptr_value);
    printf("Wat %s\n", *(char**)foo);
    envp += 8;
  }
#endif

}
