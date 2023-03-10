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
  ga* guest_envp = (ga*)get_arg(regs, 2); // Guest pointer
  for (int i=0; i < 255; i++) {
    uint64_t host_envp;
    char env_val[128];
    // Read out the guest pointer to the next env var
    yield_from(ga_memcpy, details, &host_envp, &guest_envp[i], sizeof(host_envp));
    if (host_envp == 0) break;

    // Read out the value of the env var
    yield_from(ga_memcpy, details, &env_val, (ga*)host_envp, sizeof(env_val));

    if (strncmp(inject.c_str(), env_val, inject.find('=')+1) == 0) {
      // Skip past any env vars that have the same key as our injection
      continue;
    }
    // Save both strings and pointers for each env var
    guest_arg_ptrs.push_back(host_envp);
    arg_list.push_back(std::string(env_val));
  }

  // We've read out all the args. Now we need to create a new guest allocation,
  // add our inejcted variable, add the original pointers plus a pointer to our
  // injected variable. Finally, we need to change the `envp` that will be
  // used by the original execve to point to the start of our pointer list

  // test with:    strace -f systemctl start snapd.service
  // better test: /usr/lib/snapd/snapd
  ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  if ((int64_t)guest_buf <= 0 && (int64_t)guest_buf > -0x1000) {
    printf("[HYDE] ERROR allocating scratch buffer got: %lu\n", (int64_t) guest_buf);
    co_return;
  }

  // Save start of guest buffer
  ga* injected_arg = guest_buf;

  // Write our `inject` string into buffer, save it's guest addr
  char* host_buf;
  yield_from(ga_map, details, guest_buf, (void**)&host_buf, inject.length()+1);
  strncpy(host_buf, inject.c_str(), inject.length());
  // Then increment guest_buf to be right after our string plus a null byte
  guest_buf += inject.length();

  // Now write each of the original env pointers into the buffer
  int i=0;
  char** newenvp;
  for (auto &env_item : guest_arg_ptrs) {
    yield_from(ga_map, details, &guest_buf[i], (void**)&newenvp, 128);
    *newenvp = (char*)env_item;
    i++;
  }

  // Add our new variable, then a null terminator
  //map_guest_pointer(details, newenvp, &guest_buf[i]);
  yield_from(ga_map, details, &guest_buf[i], (void**)&newenvp, sizeof(injected_arg));
  *newenvp = (char*)injected_arg;
  //map_guest_pointer(details, newenvp,&guest_buf[i+1]);
  yield_from(ga_map, details, &guest_buf[i+1], (void**)&newenvp, 1);
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