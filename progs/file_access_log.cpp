#include <stdio.h>
#include <string>
#include <iostream>
#include "hyde_sdk.h"
#include "qemu_api.h"

// Record pathname + mode passed to all open/openat syscalls
// FOR SCIENCE: we count how often the pathname string is paged out
// and if we're able to read it with our reliable memory access techniques
//#define BASELINE

// fail/good: how many pointers could just be read
// hydec: how many could be read with hyde
static uint64_t total_calls = 0;
static uint64_t native_failures = 0;
static uint64_t hyde_failures = 0;

FILE* fp;


// Before every open check if filename is paged out or not
SyscallCoroutine pre_open(SyscallCtx *details) {
    // Called for both open and openat. If it's open path arg 0, else 1
    int path_arg = (details->get_orig_syscall()->callno == SYS_open ? 0 : 1);
    uint64_t path_ptr = details->get_arg(path_arg);

    total_calls++;

    // Check if KVM can provide a translation for the path pointer and count results
    uint64_t hva;
    if (!details->translate_gva(path_ptr, &hva)) {
        native_failures++;
    }

    // Now use HyDE APIs to do the read 
    char path[64];
    int bytes_read = yield_from(ga_strncpy, details, path, path_ptr, sizeof(path));
    if (bytes_read < 0) {
        // This should never happen - increment our counter, but also raise a fatal error
        printf("ERROR: HyDE failed to read path pointer %lx\n", path_ptr);
        hyde_failures++;
        yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::FATAL);
    }

    fprintf(fp, "File access: %s, flags %lx, mode: %lx\n", path, details->get_arg(path_arg+1), details->get_arg(path_arg+2));
    if (strstr(path, ".nocache") != NULL) [[unlikely]] { // Just to enable automated testing
        fflush(fp);
        fflush(NULL);
    }
    yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SUCCESS);
}

void __attribute__ ((destructor)) teardown(void) {
    fprintf(fp, "Of the %lu open/openat syscalls, %lu could not be read with the standard approach. %lu could not be ready by hyde\n", total_calls, native_failures, hyde_failures);
    fclose(fp);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  fp = fopen("file_access_log.log", "w");

  map[SYS_open] = pre_open;
  map[SYS_openat] = pre_open;

  return true;
}
