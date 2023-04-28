#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <vector>
#include "hyde_common.h"
#include "hyde_sdk.h"


SyscallCoroutine pre_exec(SyscallCtx* details) {

  // Environment to inject - hardcoded in here for now
  std::string inject = "HyDE_var=HyDE_val_1234";

  std::vector<__u64> guest_arg_ptrs;
  std::vector<std::string> arg_list;
  int i=0;
  char* zero = NULL;
  uint64_t injected_arg;


  // Create guest and host envp references and use to read arguments out
  uint64_t guest_envp = details->get_arg(2);

  for (int i=0; i < 255; i++) {
    uint64_t envp;
    char env_val[128];
    // Read out the guest pointer to the next env var - If we actually can't read this, break
    if (yield_from(ga_memread, details, &envp, guest_envp + (i*8), 8) == -1) {

      if (i < 10) { 
        // We failed really early - this probably indicates a bug
        printf("[EnvMgr] Error reading &envp[%d] at gva %lx\n", i, guest_envp + (i*8));
        co_return ExitStatus::SINGLE_FAILURE;
      } else {
        // We successfuly read some and then failed - we're probably past the end of the list
        break;
      }
    }
    if (envp == 0) break;

    // Read out the value of the env var
    if (yield_from(ga_strnread, details, &env_val, envp, sizeof(env_val)) < 0) {
      printf("[EnvMgr] Error reading envp[%d] at gva %lx, not checking for duplicate name\n", i, (uint64_t)envp);
      strcpy(env_val, "[MEM ERROR]");
      goto save_ptrs;
    }

    if (strncmp(inject.c_str(), env_val, inject.find('=')+1) == 0) {
      // Skip past any env vars that have the same key as our injection
      continue;
    }

    //printf("Existing var at GVA %lx is %s\n", envp, env_val);

    save_ptrs:
    // Save both strings and pointers for each env var
    guest_arg_ptrs.push_back(envp);
    arg_list.push_back(std::string(env_val));
  }

  // We've read out all the args. Now we need to create a new guest allocation,
  // add our inejcted variable, add the original pointers plus a pointer to our
  // injected variable. Finally, we need to change the `envp` that will be
  // used by the original execve to point to the start of our pointer list

  uint64_t guest_buf = yield_syscall(details, mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  //printf("[EnvMgr] Allocated scratch buffer: %lx\n", (uint64_t) guest_buf);

  if ((int64_t)guest_buf <= 0 && (int64_t)guest_buf > -0x1000) {
    printf("[EnvMgr] ERROR allocating scratch buffer got: %lu\n", (int64_t) guest_buf);
    co_return ExitStatus::SINGLE_FAILURE;
  }

  // Save start of guest buffer
  injected_arg = guest_buf;

  // Write our `inject` string into buffer, will have address saved at injected_arg
  char* inject_c = (char*)inject.c_str();
  //printf("Writing new string at %lx\n", guest_buf);
  if (yield_from(ga_memwrite, details, guest_buf, (void*)inject_c, inject.length()+1) == -1) {
    printf("[EnvMgr] Error writing %lu bytes from hva %lx to gva %lx\n", inject.length()+1, (uint64_t)inject_c, guest_buf);
    goto cleanup_buf;
  }

  // Then increment guest_buf to be right after our string plus a null byte
  guest_buf += inject.length()+1; // Keep null terminator?
  guest_buf = (guest_buf + 32) - ((guest_buf + 32) % 32); // Align to 32 bytes

  // Now write each of the original env pointers into the buffer
  for (auto &env_item : guest_arg_ptrs) {
    if (yield_from(ga_memwrite, details, guest_buf + (i * sizeof(uint64_t)), (void**)&env_item, sizeof(char*)) == -1) {
      printf("[EnvMgr] Error mapping pointer for value %d\n", i);
      goto cleanup_buf;
    }
    i++;
  }

  // Note, we could also construct a char[][] array on our host here, fill it with pointers,
  // then cast it to a char[] and yield an execve syscall with execve(orig_arg(0), orig_arg(1), host_envp)

  // Add our new variable, then a null terminator
  //printf("Write new var pointer at %lx (points to %lx)\n", (guest_buf + (i * sizeof(uint64_t))), (uint64_t)&injected_arg );
  if (yield_from(ga_memwrite, details, guest_buf + (i * sizeof(uint64_t)), (void*)&injected_arg, sizeof(char*)) == -1) {
    printf("[EnvMgr] Error mapping pointer for injected variable\n");
    goto cleanup_buf;
  }

  if (yield_from(ga_memwrite, details, guest_buf + ((i+1) * sizeof(uint64_t)), (void**)&zero, sizeof(char*)) == -1) {
    printf("[EnvMgr] Error mapping pointer for null terminator\n");
    goto cleanup_buf;
  }

  // Finally, update the original (execve) syscall so arg2 points to our buffer
  details->set_arg(2, guest_buf);

  // Inject the modified syscall, then be done
  co_yield_noreturn(details, *details->get_orig_syscall(), ExitStatus::SUCCESS);

cleanup_buf: // We have failed after allocating memory, clean it up
  //printf("[EnvMgr] Deallocate buffer at %llx for error\n", (__u64)injected_arg);
  yield_syscall(details, munmap, injected_arg, 1024);

  co_yield_noreturn(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_execve] = pre_exec;
  return true;
}