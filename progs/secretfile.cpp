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
#include "hyde.h"
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

SyscallCoroutine pre_close(syscall_context *details) {
    // Guest is about to read a FD - is out ours? Check with readlink /proc/self/fd/<fd>

    struct kvm_regs regs;
    get_regs_or_die(details, &regs);

    char path[128];
    int rv = yield_from(fd_to_filename, details, get_arg(regs, RegIndex::ARG0), path);

    if (rv < 0) {
        co_return ExitStatus::SINGLE_FAILURE;
    }

    if (strncmp(path, guest_placeholder, strlen(path)) == 0) {
        open_count--;
    }

    co_yield *(details->orig_syscall);
    co_return ExitStatus::SUCCESS;

}

SyscallCoroutine pre_read(syscall_context *details) {
    // Guest is about to read a FD - is out ours? Check with readlink /proc/self/fd/<fd>

    struct kvm_regs regs;
    get_regs_or_die(details, &regs);

    char path[128];
    int rv = yield_from(fd_to_filename, details, get_arg(regs, RegIndex::ARG0), path);

    if (rv < 0) {
        co_return ExitStatus::SINGLE_FAILURE;
    }

    if (strncmp(path, guest_placeholder, strlen(path)) == 0) {
        //printf("*****SecretFile: guest read our file: %s\n", path);
        // Wahoo, let's go and do something!

        // read should copy the contents of the host file into the guest
        // the arguments of the read syscall are fd, buf, count. We just care about buf and count
        uint64_t outbuf = get_arg(regs, RegIndex::ARG1);
        ssize_t count = (size_t)get_arg(regs, RegIndex::ARG2);

        //printf("Populate buffer at %lx with up to %ld bytes from file\n", (uint64_t)outbuf, count);
        int pid = yield_syscall0(details, getpid);
        int tid = yield_syscall0(details, gettid);

        auto pid_tid = std::make_pair(pid, tid);

        if (pid_tid_pos.find(pid_tid) == pid_tid_pos.end()) {
            pid_tid_pos[pid_tid] = 0;
        }
        // open the host file and read it into a buffer - no helper since it's a host file
        int host_fd = open(host_file, O_RDONLY);
        if (host_fd < 0) {
            //printf("SecretFile: Unable to open host file %s: error %d\n", host_file, host_fd);
            co_yield *(details->orig_syscall);
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
        details->orig_syscall->has_retval = true;
        details->orig_syscall->retval = count;

        free(scratch);
    }

    co_yield *(details->orig_syscall);
    co_return ExitStatus::SUCCESS;
}

SyscallCoroutine start_coopter(syscall_context *details)
{
    ExitStatus rv = ExitStatus::SUCCESS;
    struct kvm_regs regs;
    get_regs_or_die(details, &regs);

    // Open: path pointer is first argument
    RegIndex path_arg = RegIndex::ARG0;

    if (details->orig_syscall->callno == SYS_openat) {
        // openat: path pointer is second argument
        // TODO: do we care about resolving dirfd? Could use fcntls to get path
        path_arg = RegIndex::ARG1;
    }

    uint64_t path_ptr = get_arg(regs, path_arg);

    //printf("Read path at %lx aka %lx\n", (uint64_t)get_arg(regs, path_arg), (uint64_t)path_ptr);
    char path[128];
    if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
        printf("SecretFile: Unable to read path pointer %lx\n", path_ptr);
        co_yield *(details->orig_syscall);
        co_return ExitStatus::SINGLE_FAILURE;
    }

    int pid = yield_syscall0(details, getpid);

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
                details->orig_syscall->retval = fd;
                details->orig_syscall->has_retval = true;
            } else {
                printf("[SecretFile] Unable to open placeholder file %s]", guest_placeholder);
                rv = ExitStatus::SINGLE_FAILURE;
            }
        } else {
            printf("[SecretFile] Guest %d is not allowed to open %s\n", pid, path);
        }
    }

    co_yield *(details->orig_syscall);
    co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
    if (callno == SYS_openat || callno == SYS_open)
        return &start_coopter;
    else if (open_count > 0 && callno == SYS_read)
        return &pre_read;
    else if (open_count > 0 && callno == SYS_close)
        return &pre_close;

    return NULL;
}