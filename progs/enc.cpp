#include <asm/unistd.h> // Syscall numbers
#include <algorithm>
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <sys/types.h> // for open flags
#include <sys/stat.h> // for open flags
#include <fcntl.h>
#include <unordered_set>
#include <mutex>
#include <map>
#include <sstream>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>

#include "hyde_sdk.h"
#include "file_helpers.h"

static int open_count = 0;
static bool created_placeholder = false;

// Hardcoded crypto stuff for now
const char host_file[] = {"/etc/issue"};
const char guest_file[] = {"/issue"};
const char encrypted_dir[] = {"/tmp/encrypted"};

// XXX: This is a placeholder, we'll want to manage keys on the host
const char key[] = {"ABCDEIOUHWETAFP"};

SyscallCoroutine pre_write(SyscallCtx *details) {
    // Guest is about to write a FD - is out ours? Check with readlink /proc/self/fd/<fd>
    char path[128];
    int rv = yield_from(fd_to_filename, details, details->get_arg(0), path);

    if (rv < 0) {
        printf("[Enc]: Error: could not get filename before write for fd %ld\n", details->get_arg(0));
        yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
    }

    if (strncmp(path, encrypted_dir, strlen(encrypted_dir)) == 0) {
        //printf("[Enc]: guest writes enc file: %s\n", path);

		// Before we write, get the position of the FD since this will affect how we decrypt
        ssize_t pos;
        int rv = yield_from(fd_to_pos, details, details->get_arg(0), pos);
        if (rv != 0) {
            printf("[Enc]: Error: could not get position before write for fd %ld\n", details->get_arg(0));
            yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
        }

        // Before we run the write, encrypt the buffer in guest memory. Hold on to a copy so
        // we can restore after the write

        // Read the buffer out of guest memory
        uint64_t bytes_to_write = details->get_arg(2);
        char* buf = (char*)malloc(bytes_to_write);
        if (yield_from(ga_memread, details, buf, details->get_arg(1), bytes_to_write) == -1) {
            printf("Unable to read data from guest\n");
            yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
        }
        //printf("[Enc]: Writing %ld bytes to guest: %s\n", bytes_to_write, buf);

        char* plaintext  = (char*)malloc(bytes_to_write);
        memcpy(plaintext, buf, bytes_to_write);

        // Encrypt the buffer
        for (int i=0; i < bytes_to_write; i++) {
            buf[i] = buf[i] ^ key[pos+i % strlen(key)];
        }
        // Write the buffer back into guest memory
        if (yield_from(ga_memwrite, details, details->get_arg(1), buf, bytes_to_write) == -1) {
            printf("Unable to write encrypted data into guest\n");
            yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
        }
        free(buf);

        // Run original syscall which should tell us bytes read and populate buffer with encrypted data
		co_yield *details->get_orig_syscall();
        uint64_t bytes_written = details->get_result();

        // Write the decrypted buffer back into guest memory
        if (yield_from(ga_memwrite, details, details->get_arg(1), plaintext, bytes_to_write) == -1) {
            printf("Unable to write decrypted data into guest\n");
            yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
        }
        free(plaintext);

        // Orig syscall should return the number of bytes written
        details->set_nop(bytes_written);

        // Can't run noreturn since we did set_nop
        co_yield *details->get_orig_syscall();
        finish(details, ExitStatus::SUCCESS);
    }

    // Not ours - just run original syscall and don't track return
    yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SUCCESS);
}

bool is_allowed(char* path, int pid) {
    return pid % 2; // only odd PID's
}

SyscallCoroutine pre_read(SyscallCtx *details) {
    // Guest is about to read a FD - is out ours? Check with readlink /proc/self/fd/<fd>
    char path[128];
    int rv = yield_from(fd_to_filename, details, details->get_arg(0), path);

    if (rv < 0) {
        printf("[Enc]: Error: could not get filename before read for fd %ld\n", details->get_arg(0));
        yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
    }

    if (strncmp(path, encrypted_dir, strlen(encrypted_dir)) == 0) {
        //printf("[Enc]: guest read our file: %s\n", path);

		// Before we read, get the position of the FD since this will affect how we decrypt
        ssize_t pos;
        int rv = yield_from(fd_to_pos, details, details->get_arg(0), pos);
        if (rv != 0) {
            printf("[Enc]: Error: could not get position before read for fd %ld\n", details->get_arg(0));
            yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
        }

		int pid = yield_syscall(details, getpid);
        if (!is_allowed(path, pid)) {
            printf("[Enc]: Guest %d is not allowed to read %s\n", pid, path);
            yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SUCCESS);
        }

        // Run original syscall which should tell us bytes read and populate buffer with encrypted data
		co_yield *details->get_orig_syscall();
        uint64_t bytes_read = details->get_result();

		// Read the encrypted buffer out of guest memory - if any bytes were read
        if (bytes_read) {
            char* encrypted_buf = (char*)malloc(bytes_read);
            if (yield_from(ga_memread, details, encrypted_buf, details->get_arg(1), bytes_read) == -1) {
                printf("Unable to read encrypted data from guest\n");
                yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
            }

            //printf("[Enc]: Read %ld bytes from guest to get encrypted %s\n", bytes_read, encrypted_buf);

            // Decrypt the buffer
            for (int i=0; i < bytes_read; i++) {
                encrypted_buf[i] = encrypted_buf[i] ^ key[pos+i % strlen(key)];
            }

            //printf("[Enc]: Buffer decrypts to %s\n", encrypted_buf);

            // Write the buffer back into guest memory
            if (yield_from(ga_memwrite, details, details->get_arg(1), encrypted_buf, bytes_read) == -1) {
                free(encrypted_buf);
                printf("Unable to write decrypted data into guest\n");
                yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
            }
            free(encrypted_buf);
        //} else {
            //printf("[Enc]: No bytes read from guest\n");
        }

        // Orig syscall should return the number of bytes read
        details->set_nop(bytes_read);

        // Can't run noreturn since we did set_nop
        co_yield *details->get_orig_syscall();
        finish(details, ExitStatus::SUCCESS);
    }

    // Not ours - just run original syscall and don't track return
    yield_and_finish(details, *details->get_orig_syscall(), ExitStatus::SUCCESS);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_read] = pre_read;
  map[SYS_write] = pre_write;

  return true;
}