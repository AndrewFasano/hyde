#include <asm/unistd.h> // Syscall numbers
#include <coroutine>
#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include <sys/mman.h> // for MMAP flags
#include "hyde.h"

bool should_coopt(void*cpu, long unsigned int callno) {
  return callno == __NR_execve;
}

SyscCoroutine start_coopter(asid_details* details) {
  // Variable to inject - hardcoded in here for now
  std::string inject = "hello=world";

  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  std::vector<__u64> guest_arg_ptrs;
  std::vector<std::string> arg_list;

  // Create `envp` - pointer to target env
  char* fname;
  bool success;
  map_guest_pointer(details, fname, get_arg(regs, 0));
#if 0
  __u64 guest_envp = get_arg(regs, 2);
  // Optimized implementation, only update host mapping on page changes
  __u64* host_envp;
  map_guest_pointer_status(details, host_envp, guest_envp, &success);
  __u64 pagenum = (__u64)&host_envp >> 4;

  for (int i=0; i < 255; i++) {
    // Optimization: if host pointer is on a new page, recalculate mapping
    if (((__u64)&host_envp[i] >> 4) != pagenum ) {
      map_guest_pointer(details, host_envp, guest_envp + (8*i), &success);
      pagenum = (__u64)&host_envp >> 4;
      host_envp -= i; // Shift back so we can index at i to get the start of our new mapping
    }

    if (host_envp[i] == 0) break;

    char* env_val;
    map_guest_pointer(details, env_val,host_envp[i]);
    //printf(" env[%d] @ guest 0x%llx | host %p => %s\n", i, guest_envp + (8*i), &host_envp[i], env_val);
    guest_arg_ptrs.push_back(host_envp[i]);
    arg_list.push_back(std::string(env_val));
  }
#else
  __u64 *host_envp; // Can dereference on host
  __u64 *guest_envp = (__u64*)get_arg(regs, 2); // Can't dereference on host, just use for guest addresses
  for (int i=0; i < 255; i++) {
    map_guest_pointer(details, host_envp,&guest_envp[i]);
    if (*host_envp == 0) break;
    char* env_val;
    map_guest_pointer(details, env_val, *host_envp);
    guest_arg_ptrs.push_back(*host_envp);
    arg_list.push_back(std::string(env_val));
  }

#endif

  // We've read out all the args. Now we need to create a new guest allocation,
  // add our inejcted variable, add the original pointers plus a pointer to our
  // injected variable. Finally, we need to change the `envp` that will be
  // used by the original execve to point to the start of our pointer list

  __u64* buf_g = (__u64*)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  if ((signed long long int)buf_g <= 0 && (signed long long int)buf_g > -0x1000) {
    printf("Error allocating scratch buffer got: %lld\n", (signed long long int) buf_g);
    co_return;
  }

  // Write our `inject` string into buffer, save it's guest addr, then increment buf_g to be past
  // the injected string.
  char* host_buf;
  map_guest_pointer(details, host_buf, buf_g);
  strncpy(host_buf, inject.c_str(), 1024);
  __u64 *injected_arg_g = buf_g;
  buf_g += strlen(inject.c_str());

  // Now write each of the original env pointers into the buffer
  int i=0;
  char** newenvp;
  for (auto &env_item : guest_arg_ptrs) {
    map_guest_pointer(details, newenvp,&buf_g[i]);
    *newenvp = (char*)env_item;
    i++;
  }

  // Add our new variable
  map_guest_pointer(details, newenvp, &buf_g[i]);
  *newenvp = (char*)injected_arg_g;
  i++;

  // Null terminate the new envp list
  map_guest_pointer(details, newenvp, &buf_g[i]);
  *newenvp = (char*)0;

  // Finally: when HyDE goes to restore the original syscall, we *don't* want
  // to use the old arg2 (envp) value, but instead our new buffer.
  // XXX these have to happen at the very end, otherwise subsequent injects will clobber
  set_ARG2(details->orig_regs, (__u64)buf_g);
  details->modify_original_args = true;
}


