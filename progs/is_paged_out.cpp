#include <stdio.h>
#include <string>
#include "hyde.h"
#include <iostream>

// Read the pathname passed to all open/openat syscalls.
// Count the total number of times we see those syscalls and
// the total number of times we can't read the pathname.
// Report results on exit.

// If BASELINE is defined, we don't use syscall injection,
// otherwise we do.
// #define BASELINE

uint64_t failc = 0;
uint64_t goodc = 0;

// Before every open check if filename is paged out or not
SyscCoro start_coopter(asid_details *details)
{
    struct kvm_regs regs;
    get_regs_or_die(details, &regs);

    // Open: path pointer is first argument
    RegIndex path_arg = RegIndex::ARG0;

    if (details->orig_syscall->callno == SYS_openat) {
        // openat: path pointer is second argument - we won't bother resolving dirfd
        path_arg = RegIndex::ARG1;
    }

    uint64_t path_ptr = get_arg(regs, path_arg);

#ifdef BASELINE
    uint64_t hva;
    if (!translate_gva(details, path_ptr, &hva)) {
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

    co_yield *(details->orig_syscall);
    co_return ExitStatus::SUCCESS;
}

void __attribute__ ((destructor)) teardown(void) {
  std::cerr << "Fail count: " << failc << std::endl;
  std::cerr << "Success count: " << goodc << std::endl;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

  if (callno == SYS_openat || callno == SYS_open)
      return &start_coopter;

  return NULL;
}