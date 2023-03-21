#include <asm/unistd.h> // Syscall numbers
#include <algorithm>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
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
#include <dirent.h>
#include <vector>
#include "hyde.h"

static std::mutex running_in_root_proc;
static bool done = false;


SyscCoro read_file(asid_details *details, ga* guest_buf, char* pathname, char**contents, int scratch_size) {
    int read_rv = -1;
    *contents = NULL;

    if (yield_from(ga_memwrite, details, guest_buf, (void*)pathname, strlen(pathname)+1) == -1) {
        printf("[PS] Error: could not to write path %s into to guest memory\n", pathname);
        co_return -1;
    }

    char* data = (char*)malloc(scratch_size);
    data[0] = '\0';

    // Open file
    int fd = yield_syscall(details, __NR_open, guest_buf, O_RDONLY, 0);
    if (fd < 0) {
        printf("[PS] Error: could not open %s\n", pathname);
        snprintf(data, scratch_size, "[open error]");
    } else {
       read_rv = yield_syscall(details, __NR_read, fd, guest_buf, scratch_size);

        if (read_rv < 0) {
            snprintf(data, scratch_size, "[read error]");
        } else if (read_rv == 0) {
            snprintf(data, scratch_size, "[empty]");
        } else {
            if (yield_from(ga_memcpy, details, data, guest_buf, read_rv) == -1) {
                printf("[PS] Error: could not read data from guest memory for file %s\n", pathname);
                snprintf(data, scratch_size, "[virt mem read error]");
            }

            // Drop null terminators up to the last one (since we have null-seperated args)
            for (int i = 0; i < read_rv-1; i++)
                if (data[i] == '\0')
                    data[i] = ' ';
        }
        // Close fd
        yield_syscall(details, __NR_close, fd);
    }

    *contents = data;

    co_return read_rv;

}

#define BUF_SIZE 1024

SyscCoro print_procinfo(asid_details *details, std::vector<int> *pids) {
    ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap, 0, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (int pid : *pids) {
        char fd_path[128];
        char* cmdline;
        char* comm;

        // Read /proc/<pid>/cmdline and /proc/<pid>/comm, drop newlines in output
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/cmdline", pid);
        int cmdline_read = yield_from(read_file, details, guest_buf, fd_path, &cmdline, BUF_SIZE);
        if (cmdline_read > 0 && cmdline != NULL) 
            for (int i = 0; i < cmdline_read; i++)
                if (cmdline[i] == '\n') cmdline[i] = ' ';

        snprintf(fd_path, sizeof(fd_path), "/proc/%d/comm", pid);
        int comm_read = yield_from(read_file, details, guest_buf, fd_path, &comm, BUF_SIZE);
        if (comm_read && comm != NULL)
            for (int i = 0; i < comm_read; i++)
                if (comm[i] == '\n') comm[i] = ' ';

        printf("%d: %s  %s\n", pid, cmdline, comm);
        if (cmdline) free(cmdline);
        if (comm) free(comm);

    }

    yield_syscall(details, __NR_munmap, guest_buf, BUF_SIZE);
    co_return 0;

}

SyscCoro ls_dir(asid_details *details, char* dirname, std::vector<int> *pids) {
    int fd;
    long nread;
    char d_type;

    ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap, 0, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // Write dirname into guest_buf
    if (yield_from(ga_memwrite, details, guest_buf, (void*)dirname, strlen(dirname)) == -1) {
        printf("[PS] Error: could not to write dirname into to guest memory at %lx\n", (uint64_t)guest_buf);
        goto error;
    }

    // Yield syscall to guest_buf as a readonly directory
    fd = yield_syscall(details, __NR_open, guest_buf, O_RDONLY | O_DIRECTORY);

    if (fd < 0) {
        printf("[PS] unable to open %s\n", dirname);
        goto error_cleanup;
    }

    while(true) {
        // Yield getdents syscall with fd
        // See man 2 getdents64 for example that this is based on
        nread = (long)yield_syscall(details, __NR_getdents64, fd, guest_buf, BUF_SIZE);

        if (nread == -1) {
            printf("[PS] unable to read dentries in loop\n");
        }

        if (nread == 0)
            break; // All done

        for (long bpos = 0; bpos < nread;) {
            struct dirent64 d;
            // Map guest memory to d. Note the syscall can return more than sizeof(d) bytes such as a struct stat
            // after it - we intentionally dont' bother mapping this full buffer because we're lazy. As a result,
            // we can't see d_type
            if (yield_from(ga_memcpy, details, &d, (ga*)((uint64_t)guest_buf + bpos), sizeof(d)) == -1) {
                printf("[PS] Error: could not read dentry from guest memory\n");
                goto error_cleanup;
            }

            int pid = atoi(d.d_name);
            if (pid > 0) {
                //printf("PID %d\n", pid);
                pids->push_back(pid);
            }

            bpos += d.d_reclen;
        }
    }

    // close fd
    yield_syscall(details, __NR_close, fd);

    // munmap guest_buf
    yield_syscall(details, __NR_munmap, guest_buf, BUF_SIZE);
    co_return 0;

error_cleanup:
    yield_syscall(details, __NR_munmap, guest_buf, BUF_SIZE);

error:
    co_return -1;


}

SyscCoro start_coopter(asid_details *details)
{
    // Grab a mutex in a root process, get PIDs from /proc , then print info for each PID
    int rv = 0;
    char target_dir[] = {"/proc"};

    if (yield_syscall(details, __NR_geteuid)) {
        // Non-root
        rv = -1;
    } else if (done) {
        // Finished
    }else if (!running_in_root_proc.try_lock()) {
        // Lock unavailable, bail on this coopter
        // Note we don't want to wait since that would block a guest proc
        rv = -1;
    }else {
        // Now running in a root process with the lock
        std::vector<int> pids;
        // Get list of PIDs
        yield_from(ls_dir, details, (char*)target_dir, &pids);

        // Print info for all PIDs
        yield_from(print_procinfo, details, &pids);

        done = true; // We did it, yay!
    }


    co_yield *(details->orig_syscall);
    co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

    if (!done)
        return &start_coopter;

    return NULL;
}