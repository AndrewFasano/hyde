#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <vector>
#include "hyde.h"


SyscCoroutine start_coopter(asid_details* details) {
  // Environment to inject - hardcoded in here for now
  std::string inject = "HyDE_var=HyDE_val";

  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  std::vector<__u64> guest_arg_ptrs;
  std::vector<std::string> arg_list;

  // Create guest and host envp references and use to read arguments out
  uint64_t host_envp; // Can dereference on host
  uint64_t guest_envp = (uint64_t)get_arg(regs, 2); // Can't dereference on host, just use for addrs
  for (int i=0; i < 255; i++) {
    //map_guest_pointer(details, host_envp, &guest_envp[i]);
    //printf("On iteration %d, trying to read guest memory at %lx\n", i, guest_envp+i);
    yield_from(new_memread, details, guest_envp+(i*sizeof(host_envp)), &host_envp, sizeof(host_envp));

    if (host_envp == 0) break;
    char env_val[128];
    //map_guest_pointer(details, env_val,*host_envp);
    //printf("Following guest memory to read from %lx in guest...\n", host_envp);
    yield_from(new_memread, details, host_envp, &env_val, sizeof(env_val));
    //printf("Got env var: %s\n", env_val);

    if (strncmp(inject.c_str(), env_val, inject.find('=')+1) == 0) {
      // Existing env var duplicates the one we're injecting - don't save it
      continue;
    }
    guest_arg_ptrs.push_back(host_envp);
    arg_list.push_back(std::string(env_val));
  }

  // We've read out all the args. Now we need to create a new guest allocation,
  // add our inejcted variable, add the original pointers plus a pointer to our
  // injected variable. Finally, we need to change the `envp` that will be
  // used by the original execve to point to the start of our pointer list

  // test with:    strace -f systemctl start snapd.service
  // better test: /usr/lib/snapd/snapd
  __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  if ((signed long long int)guest_buf <= 0 && (signed long long int)guest_buf > -0x1000) {
    printf("[HYDE] ERROR allocating scratch buffer got: %lld\n", (signed long long int) guest_buf);
    co_return;
  }

  // Write our `inject` string into buffer, save it's guest addr
  char* host_buf;
  bool success;
  map_guest_pointer_status(details, host_buf, guest_buf, &success);
  if (!success) {
    printf("FAILURE to map guest pointer at %llx\n", (__u64)guest_buf);
    co_return;
  }
  strncpy(host_buf, inject.c_str(), 1024);
  __u64 *injected_arg_g = guest_buf;
  // Then increment guest_buf to be right after our string
  guest_buf += inject.length();

  // Now write each of the original env pointers into the buffer
  // TODO: we have new_memread, now we need just a new_memmap, and/or a new_memwrite
  int i=0;
  char** newenvp;
  for (auto &env_item : guest_arg_ptrs) {
    map_guest_pointer(details, newenvp, &guest_buf[i]);
    *newenvp = (char*)env_item;
    i++;
  }

  // Add our new variable, then a null terminator
  map_guest_pointer(details, newenvp, &guest_buf[i]);
  *newenvp = (char*)injected_arg_g;
  map_guest_pointer(details, newenvp,&guest_buf[i+1]);
  *newenvp = (char*)0;

  // Finally, we run the original (execve) syscall, but with a different arg2 pointing to our buffer
  details->orig_syscall->args[2] = (__u64)guest_buf;
  co_yield *(details->orig_syscall); // noreturn
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  // We inject syscalls starting at every execve
  if (callno == __NR_execve)
    return &start_coopter;
  return NULL;
}


