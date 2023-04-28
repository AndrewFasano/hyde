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

std::unordered_set<int> pids;

// Hardcoded file that guest will see when it's allowed
const char host_file[] = {"/etc/issue"};
const char guest_file[] = {"/issue"};
const char guest_placeholder[] = {"/tmp/.secretfile.txt"};

std::map<std::pair<int, int>, int> pid_tid_pos; // (pid,tid) -> position in our file

bool is_allowed(int pid) {
    return pid % 2; // only odd PID's
}

SyscallCoroutine pre_close(SyscallCtx *details) {
    // Guest is about to read a FD - is out ours? Check with readlink /proc/self/fd/<fd> if we have any active pids

    if (pids.size() == 0 || pids.count(yield_syscall(details, getpid)) == 0) {
        co_yield_noreturn(details, *(details->get_orig_syscall()), ExitStatus::SUCCESS);
    }

    char path[sizeof(guest_placeholder)];
    int rv = yield_from(fd_to_filename, details, (uint64_t)details->get_arg(0), path); // XXX why you fail

    if (rv < 0) {
        if (rv == -ENOENT || rv == -ENAMETOOLONG) {
            // There's no /proc/self/fd/<fd>, perhaps the guest is closing an FD that isn't opened (which happens a lot)
            // Or the name is larger than the name of our placeholder file, indicating it's *not* our file
            // Just ignore it
            co_yield_noreturn(details, *(details->get_orig_syscall()), ExitStatus::SUCCESS);
        }
        printf("SecretFile: Error: could not get filename before close for fd %ld: Error %d\n", details->get_arg(0), rv);
        co_return ExitStatus::SINGLE_FAILURE;
    }

    if (strncmp(path, guest_placeholder, strlen(path)) == 0) {
        printf("DROP PID FROM PIDS: %d\n", yield_syscall(details, getpid));
        pids.erase(yield_syscall(details, getpid));
        printf("PIDS now has %ld elements\n", pids.size());
    }

    co_yield_noreturn(details, *(details->get_orig_syscall()), ExitStatus::SUCCESS);
}

SyscallCoroutine pre_read(SyscallCtx *details) {
    // Guest is about to read a FD - is out ours? Check with readlink /proc/self/fd/<fd>

    // Is pid in pids?
    if (pids.size() == 0 || pids.count(yield_syscall(details, getpid)) == 0) {
        co_yield_noreturn(details, *(details->get_orig_syscall()), ExitStatus::SUCCESS);
    }

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
            co_yield_noreturn(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
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

        // Can't run noreturn since we did set_nop
        co_yield *details->get_orig_syscall();
        co_return ExitStatus::SUCCESS;
    }

    // Not ours - just run original syscall and don't track return
    co_yield_noreturn(details, *details->get_orig_syscall(), ExitStatus::SUCCESS);
}

SyscallCoroutine pre_open(SyscallCtx *details) {
    ExitStatus rv = ExitStatus::SUCCESS;

    int path_arg = (details->get_orig_syscall()->callno == SYS_open ? 0 : 1);
    uint64_t path_ptr = details->get_arg(path_arg);

    char path[128];
    if (yield_from(ga_strncpy, details, path, path_ptr, sizeof(path)) == -1) {
        printf("SecretFile: Unable to read path pointer %lx\n", path_ptr);
        co_yield_noreturn(details, *details->get_orig_syscall(), ExitStatus::SINGLE_FAILURE);
    }

    if (strncmp(path, guest_file, sizeof(guest_file)) == 0) {
        int pid = yield_syscall(details, getpid);
        // Trying to open our target file
        //printf("SecretFile: Guest is trying to open our file: %s\n", path);
        if (is_allowed(pid)) {
            printf("[SecretFile] Guest %d IS allowed to open %s\n", pid, path);
            // Open and create the placeholder file
            int fd = yield_syscall(details, open, guest_placeholder, O_CREAT | O_RDWR, 0644);
            if (fd >= 0) {
                open_count++;
                // Modify orig_syscall object so when we yield it in a sec, the guest
                // will end up with our FD instead of the one it wanted
                created_placeholder = true;

            } else if (fd == -EEXIST && created_placeholder) {
                fd = yield_syscall(details, open, guest_placeholder, O_RDONLY);
            }

            if (fd >= 0) {
                details->set_nop(fd);
                pids.insert(pid);
                co_yield *details->get_orig_syscall();
                co_return ExitStatus::SUCCESS;
            }
            printf("[SecretFile] Unable to open/create placeholder file %s]", guest_placeholder);
            rv = ExitStatus::SINGLE_FAILURE;
        } else {
            printf("[SecretFile] Guest %d is not allowed to open %s\n", pid, path);
        }
    }

    co_yield_noreturn(details, *details->get_orig_syscall(), rv);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_openat] = pre_open;
  map[SYS_open] = pre_open;
  map[SYS_read] = pre_read;
  map[SYS_close] = pre_close;

  return true;
}