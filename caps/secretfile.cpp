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
#include <sstream>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include "hyde.h"

static std::mutex running_in_root_proc;
static bool any_opened = false;

// Hardcoded file that guest will see when it's allowed
const char host_file[] = {"/etc/issue"};
const char guest_file[] = {"/issue"};
const char guest_placeholder[] = {"/tmp/.secretfile"};

bool is_allowed() {
    // TODO
    return true;
}

SyscCoro read_fd(asid_details *details) {
    // Guest is about to read a FD - is out ours? Check with fcntl

    struct kvm_regs regs;
    get_regs_or_die(details, &regs);
    int fd = (int)get_arg(regs, 0);
    int readlink_rv;

    // allocate a buffer for the filename
    ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap, 0, 128, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // Write /proc/self/fd/<fd> into guest memory
    char fd_path[128];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (yield_from(ga_memwrite, details, guest_buf, (void*)fd_path, strlen(fd_path)) == -1) {
        printf("[SecretFile] Error: could not to write fd_path into to guest memory\n");
        goto error;
    }

    // Use readlink to read /proc/self/fd/<fd>
    readlink_rv = yield_syscall(details, __NR_readlink, guest_buf, guest_buf, 128);

    // Read the result, readlink_rv is the length of the string
    char path[128];
    if (yield_from(ga_memcpy, details, path, guest_buf, std::min(sizeof(path), (size_t)readlink_rv+1)) == -1) {
        printf("SecretFile: Unable to read path from fcntl %lx\n", (uint64_t)guest_buf);
        goto error_cleanup;
    }

    if (strncmp(path, guest_placeholder, strlen(path)) == 0) {
        printf("*****SecretFile: guest read our file: %s\n", path);
        // Wahoo, let's go and do something!

        // read should copy the contents of the host file into the guest
        // the arguments of the read syscall are fd, buf, count. We just care about buf and count
        ga* outbuf = (ga*)get_arg(regs, 1);
        ssize_t count = (size_t)get_arg(regs, 2);

        printf("Populate buffer at %lx with %ld bytes from file\n", (uint64_t)outbuf, count);
        int pid = yield_syscall(details, __NR_getpid);
        int tid = yield_syscall(details, __NR_getpid);
        // TODO: use target (pid,tid) to track position in the file

        char* scratch;

        // open the host file and read it into a buffer
        int host_fd = open(host_file, O_RDONLY);
        if (host_fd == -1) {
            printf("SecretFile: Unable to open host file %s\n", host_file);
            goto error_cleanup;
        }

        scratch = (char*)malloc(count);
        count = std::min(count, read(host_fd, scratch, count));

        if (yield_from(ga_memwrite, details, outbuf, (void*)scratch, count) == -1) {
            printf("Unable to write hostfile data into guestfile\n");
        }

        // Orig syscall should return the number of bytes read
        details->orig_syscall->has_retval = true;
        details->orig_syscall->retval = count;

        free(scratch);
    }

cleanup:
    yield_syscall(details, __NR_munmap, guest_buf, 128);
    co_yield *(details->orig_syscall);
    co_return 0; // success

error_cleanup:
    // Cleanup
    yield_syscall(details, __NR_munmap, guest_buf, 128);

error:
    co_yield *(details->orig_syscall);
    co_return -1;
}

SyscCoro open_placeholder(asid_details *details) {
    // Open placeholder file, need to allocate memory

    int fd = -1;

    //ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap,
    //    /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
    //    /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);
    hsyscall hsc = {
        .callno = __NR_mmap,
        .nargs = 6,
        .args = {0, 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, static_cast<uint64_t>(-1), 0}
    };
    co_yield hsc;
    ga* guest_buf = (ga*)details->last_sc_retval;

    if ((int64_t)guest_buf <= 0 && (int64_t)guest_buf > -0x1000) {
        printf("[EnvMgr] ERROR allocating scratch buffer got: %lu\n", (int64_t) guest_buf);
        co_return -1;
    }

  // Builtin memwrite
  uint64_t hva;
    if (yield_from(ga_memwrite, details, guest_buf, (void*)guest_placeholder, sizeof(guest_placeholder)) == -1) {
        printf("[SecretFile] Error: could not to copy placeholder file name into to guest memory\n");
    } else {
        fd = yield_syscall(details, __NR_open, (uint64_t)guest_buf, O_CREAT);
    }
    yield_syscall(details, __NR_munmap, guest_buf, 1024);
    co_return fd;
}

SyscCoro start_coopter(asid_details *details)
{
    int rv = 0;
    int pid;
    struct kvm_regs regs;
    get_regs_or_die(details, &regs);

    ga *path_ptr;
    // Open: path pointer is first argument
    int path_arg = 0;

    if (details->orig_syscall->callno == __NR_openat) {
        // openat: path pointer is second argument
        // TODO: do we care about resolving dirfd? Could use fcntls to get path
        path_arg = 1;
    }

    path_ptr = (ga*)get_arg(regs, path_arg);

    //printf("Read path at %lx aka %lx\n", (uint64_t)get_arg(regs, path_arg), (uint64_t)path_ptr);

    char path[128];
    if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
        printf("SecretFile: Unable to read path pointer %lx\n", (uint64_t)path_ptr);
        rv = -1;
        goto out;
    }

    //pid = yield_syscall(details, __NR_getpid);
    //printf("PID %d opens %s\n", pid, path);

    if (strncmp(path, guest_file, sizeof(guest_file)) == 0) {
        // Trying to open our target file
        printf("SecretFile: Guest is trying to open %s\n", path);
        if (is_allowed()) {
            int fd = yield_from(open_placeholder, details);
            any_opened = true;
            if (fd == -1) {
                rv = -1;
                goto out;
            }
            // Modify orig_syscall object so when we yield it in a sec, the guest
            // will end up with our FD instead of the one it wanted
            details->orig_syscall->retval = fd;
            details->orig_syscall->has_retval = true;
        }
    }

out:
    co_yield *(details->orig_syscall); // noreturn
    co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
    if (callno == __NR_openat || callno == __NR_open)
        return &start_coopter;
    else if (any_opened && callno == __NR_read)
        return &read_fd;

    return NULL;
}