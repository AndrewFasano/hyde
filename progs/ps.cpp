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
#include "hyde_sdk.h"

static std::mutex running_in_root_proc;


SyscCoroHelper my_read_file(SyscallCtx *ctx, char* out_data, char* pathname, int out_size) {
    char local_pathname[128];
    if (strlen(pathname) > sizeof(local_pathname)) {
        printf("[PS] Error: pathname too long\n");
        co_return -1;
    }
    //assert(strlen(pathname) < sizeof(local_pathname));
    char *start = out_data;
    memset(out_data, 'A', out_size);

    // Open file
    memcpy(local_pathname, pathname, sizeof(local_pathname));
    int fd = yield_syscall(ctx, open, local_pathname, O_RDONLY, 0);

    if (fd < 0) {
        printf("[PS] Error: could not open %s\n", pathname);
        snprintf(out_data, out_size, "[open error]");
        out_data[0] = 0;
        co_return fd;
    }

    char host_buf[1024];
    int read_rv;
    int bytes_read = 0;
    do {
        read_rv = yield_syscall(ctx, read, fd, host_buf, 1024);
        memcpy(out_data, host_buf, std::min(read_rv, (int)(out_size - (out_data - start))));
        out_data += read_rv;

        bytes_read += read_rv;

        if (out_data - start > out_size) {
            break;
        }
    } while (read_rv > 0);

    yield_syscall(ctx, close, fd);
    if (read_rv < 0) {
        printf("Error reading: %d\n", read_rv);
        co_return read_rv; // linux errno
    }
    start[bytes_read] = 0; // Ensure null term
    co_return bytes_read;
}

SyscCoroHelper print_procinfo(SyscallCtx *ctx, std::vector<int> *pids) {
    for (int pid : *pids) {
        char fd_path[128];
        char comm[128];
        char cmdline[128];

        // Read /proc/<pid>/cmdline and /proc/<pid>/comm
        // Replace null bytes and newlines with spaces, except for the final null byte
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/cmdline", pid);

        int cmdline_read = yield_from(my_read_file, ctx, cmdline, fd_path, sizeof(fd_path));

        for (int i = 0; i < std::max(0, cmdline_read); i++) {
            if (cmdline[i] == '\n') cmdline[i] = ' ';
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
        cmdline[cmdline_read] = 0 ; // Put back null term

        snprintf(fd_path, sizeof(fd_path), "/proc/%d/comm", pid);
        int comm_read = yield_from(my_read_file, ctx, comm, fd_path, sizeof(comm));
        for (int i = 0; i < std::max(0, comm_read); i++) {
            if (comm[i] == '\n') comm[i] = ' ';
            if (comm[i] == '\0') comm[i] = ' ';
        }
        comm[comm_read] = 0; // Put back null term
        printf("%03d: %-50s  %-20s\n", pid, cmdline, comm);
    }

    co_return 0;

}

SyscCoroHelper ls_dir(SyscallCtx *ctx, char* dirname, std::vector<int> *pids) {
    int fd;
    long nread;
    char d_type;

    char local_dirname[128]; // Fixed size will automap unlike char*
    memcpy(local_dirname, dirname, sizeof(local_dirname));

    // Yield syscall to guest_buf as a readonly directory
    fd = yield_syscall(ctx, open, local_dirname, O_RDONLY | O_DIRECTORY);

    if (fd < 0) {
        printf("[PS] unable to open %s\n", dirname);
        co_return fd; // Pass errno back through
    }

    while(true) {
        // Yield getdents syscall with fd
        // See man 2 getdents64 for example that this is based on
        char host_buf[1024];
        nread = (long)yield_syscall(ctx, getdents64, fd, host_buf, sizeof(host_buf));

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
            memcpy(&d, host_buf + bpos, sizeof(d));

            int pid = atoi(d.d_name);
            if (pid > 0) {
                pids->push_back(pid);
            }

            bpos += d.d_reclen;
        }
    }

    // close fd
    yield_syscall(ctx, close, fd);
    co_return 0;
}

SyscallCoroutine ps_in_root(SyscallCtx *ctx) {
    // Grab a mutex in a root process, get PIDs from /proc , then print info for each PID
    char target_dir[] = {"/proc"};

    if (yield_syscall(ctx, geteuid)) {
        // Non-root
        co_yield_noreturn(ctx, *ctx->get_orig_syscall(), ExitStatus::SUCCESS); // Not an error, but not done

    } else if (!running_in_root_proc.try_lock()) {
        // Lock unavailable, bail on this coopter
        // Note we don't want to wait since that would block a guest proc
        co_yield_noreturn(ctx, *ctx->get_orig_syscall(), ExitStatus::SUCCESS); // Not an error, but not done
    }

    // Now running in a root process with the lock
    std::vector<int> pids;
    // Get list of PIDs
    yield_from(ls_dir, ctx, (char*)target_dir, &pids);

    // Print info for all PIDs
    yield_from(print_procinfo, ctx, &pids);

    running_in_root_proc.unlock();
    //co_yield *(ctx->get_orig_syscall());
    //co_return ExitStatus::FINISHED;
    co_yield_noreturn(ctx, *ctx->get_orig_syscall(), ExitStatus::FINISHED);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[-1] = ps_in_root;
  return true;
}