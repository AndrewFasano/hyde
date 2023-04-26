#include <asm/unistd.h> // Syscall numbers
#include <algorithm>
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <sys/types.h> // for open flags
#include <sys/stat.h> // for open flags
#include <fcntl.h>
#include <vector>
#include <mutex>
#include <map>
#include <sstream>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>

#include "hyde_sdk.h"
#include "file_helpers.h"

static int open_count = 0;

// Hardcoded file that guest will see when it's allowed
const char host_file[] = {"/etc/issue"};
const char guest_file[] = {"/issue"};
const char guest_placeholder[] = {"/tmp/.secretfile"};

std::map<std::pair<int, int>, int> pid_tid_pos; // (pid,tid) -> position in our file

bool is_allowed(int pid) {
    return pid % 2; // only odd PID's
}

SyscallCoroutine pre_close(SyscallCtx *details) {
    // Guest is about to read a FD - is out ours? Check with readlink /proc/self/fd/<fd>

    char path[128];
    int rv = yield_from(fd_to_filename, details, (uint64_t)details->get_arg(0), path); // XXX why you fail

    if (rv < 0) {
        printf("SecretFile: Error: could not get filename before close for fd %ld\n", details->get_arg(0));
        co_return ExitStatus::SINGLE_FAILURE;
    }

    if (strncmp(path, guest_placeholder, strlen(path)) == 0) {
        open_count--;
    }

    co_yield *(details->get_orig_syscall());
    co_return ExitStatus::SUCCESS;

}

SyscallCoroutine pre_read(SyscallCtx *details) {
    // Guest is about to read a FD - is out ours? Check with readlink /proc/self/fd/<fd>

    char path[128];
    int rv = yield_from(fd_to_filename, details, details->get_arg(0), path);

    if (rv < 0) {
        printf("SecretFile: Error: could not get filename before read for fd %ld\n", details->get_arg(0));
        co_return ExitStatus::SINGLE_FAILURE;
    }

    if (strncmp(path, guest_placeholder, strlen(path)) == 0) {
        //printf("*****SecretFile: guest read our file: %s\n", path);
        // Wahoo, let's go and do something!

        // read should copy the contents of the host file into the guest
        // the arguments of the read syscall are fd, buf, count. We just care about buf and count
        uint64_t outbuf = details->get_arg(1);
        ssize_t count = (size_t)details->get_arg(2);

        //printf("Populate buffer at %lx with up to %ld bytes from file\n", (uint64_t)outbuf, count);
        int pid = yield_syscall(details, getpid);
        int tid = yield_syscall(details, gettid);

        auto pid_tid = std::make_pair(pid, tid);

        if (pid_tid_pos.find(pid_tid) == pid_tid_pos.end()) {
            pid_tid_pos[pid_tid] = 0;
        }
        // open the host file and read it into a buffer - no helper since it's a host file
        int host_fd = open(host_file, O_RDONLY);
        if (host_fd < 0) {
            printf("SecretFile: Unable to open host file %s: error %d\n", host_file, host_fd);
            co_yield *(details->get_orig_syscall());
            co_return ExitStatus::SINGLE_FAILURE;
        }

        // Seek to guest_pos if non-zero
        int guest_pos = pid_tid_pos[pid_tid];
        if (guest_pos >0 ) {
            lseek(host_fd, guest_pos, SEEK_SET);
        }

        // Read data into scratch buffer
        char* scratch = (char*)malloc(count);
        count = std::min(count, read(host_fd, scratch, count)); // no more than requested, no more than (remaining) file size

        close(host_fd);
        pid_tid_pos[pid_tid] += count; // update position in file

        // Write data into guest memory at the requested output buffer, if there's any data
        if (count > 0 && yield_from(ga_memwrite, details, outbuf, (void*)scratch, count) == -1) {
            printf("Unable to write hostfile data into guestfile\n");
        }

        // Orig syscall should return the number of bytes read
        details->set_nop(count);

        free(scratch);
    }

    co_yield *(details->get_orig_syscall());
    co_return ExitStatus::SUCCESS;
}

SyscallCoroutine start_coopter(SyscallCtx *details)
{
    ExitStatus rv = ExitStatus::SUCCESS;

    // Open: path pointer is first argument
    int path_arg = 0;

    if (details->get_orig_syscall()->callno == SYS_openat) {
        // openat: path pointer is second argument
        // TODO: do we care about resolving dirfd? Could use fcntls to get path
        path_arg = 1;
    }

    uint64_t path_ptr = details->get_arg(path_arg);

    //printf("Read path at %lx aka %lx\n", (uint64_t)get_arg(regs, path_arg), (uint64_t)path_ptr);
    char path[128];
    if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
        printf("SecretFile: Unable to read path pointer %lx\n", path_ptr);
        co_yield *(details->get_orig_syscall());
        co_return ExitStatus::SINGLE_FAILURE;
    }

    int pid = yield_syscall(details, getpid);

    if (strncmp(path, guest_file, sizeof(guest_file)) == 0) {
        // Trying to open our target file
        //printf("SecretFile: Guest is trying to open %s\n", path);
        if (is_allowed(pid)) {
            // Open and create the placeholder file
            int fd = yield_syscall(details, open, guest_placeholder, O_CREAT);
            if (fd >= 0) {
                open_count++;
                // Modify orig_syscall object so when we yield it in a sec, the guest
                // will end up with our FD instead of the one it wanted
                details->set_nop(fd);
            } else {
                printf("[SecretFile] Unable to open placeholder file %s]", guest_placeholder);
                rv = ExitStatus::SINGLE_FAILURE;
            }
        } else {
            printf("[SecretFile] Guest %d is not allowed to open %s\n", pid, path);
        }
    }

    co_yield *(details->get_orig_syscall());
    co_return rv;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_openat] = start_coopter;
  map[SYS_open] = start_coopter;
  map[SYS_read] = pre_read;
  map[SYS_close] = pre_close;

  return true;
}