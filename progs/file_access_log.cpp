#include <stdio.h>
#include <string>
#include <iostream>
#include "hyde_sdk.h"
#include "qemu_api.h"

// Read the pathname passed to all open/openat syscalls.
// Count the total number of times we see those syscalls and
// the total number of times we can't read the pathname.
// Report results on exit.

// If BASELINE is defined, we don't use syscall injection,
// otherwise we do.
//#define BASELINE

uint64_t failc = 0;
uint64_t goodc = 0;

// Before every open check if filename is paged out or not
SyscallCoroutine pre_open(SyscallCtx *details) {
    // Open: path pointer is first argument
    int path_arg = 0;

    if (details->get_orig_syscall()->callno == SYS_openat) {
        // openat: path pointer is second argument - we won't bother resolving dirfd
        path_arg = 1;
    }

    uint64_t path_ptr = details->get_arg(path_arg);

#ifdef BASELINE
    uint64_t hva;
    if (!details->translate_gva(path_ptr, &hva)) {
        failc++;
    } else {
        goodc++;
    }
#else
    // Read path pointer
    char path[8];
    if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
        printf("Woah, we couldn't read the path pointer: %lx", path_ptr);
    }else {
        if (strlen(path) > 0) {
            goodc++;
        } else {
            goodc++;
            // This isn't a failure, but if we see it often, we should investigate
            // Seems to show up once in coreutils tests suite - sounds reasonable
            printf("\nXXX: we got an empty path string\n\n");
        }
    }
#endif

    co_yield_noreturn(details, *details->get_orig_syscall(), ExitStatus::SUCCESS);
}

void __attribute__ ((destructor)) teardown(void) {
  std::cerr << "Fail count: " << failc << std::endl;
  std::cerr << "Success count: " << goodc << std::endl;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_open] = pre_open;
  map[SYS_openat] = pre_open;
  return true;
}