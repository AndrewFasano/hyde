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
#include "file_helpers.h"

static std::mutex running_in_root_proc;

FILE* fp;

SyscCoroHelper print_procinfo(SyscallCtx *ctx, std::vector<int> *pids) {
    for (int pid : *pids) {
        char fd_path[128];
        //char comm[128];
        //char cmdline[128];

        // Read /proc/<pid>/cmdline and /proc/<pid>/comm
        // Replace null bytes and newlines with spaces, except for the final null byte
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/cmdline", pid);

        std::string cmdline, comm;
        int cmdline_read = yield_from(read_file, ctx, fd_path, &cmdline);
        for (int i = 0; i < std::max(0, cmdline_read); i++) {
            if (cmdline[i] == '\n') cmdline[i] = ' ';
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
        cmdline[std::max(cmdline_read, 0)] = 0 ; // Put back null term

        snprintf(fd_path, sizeof(fd_path), "/proc/%d/comm", pid);
        int comm_read = yield_from(read_file, ctx, fd_path, &comm);
        // Replace all null bytes in our comm string
        for (int i=0; i < std::max(0, comm_read); i++) {
            if (comm[i] == '\0') comm[i] = ' ';
            if (comm[i] == '\n') comm[i] = ' ';
        }

        fprintf(fp, "%03d: %-50s  %-20s\n", pid, cmdline.c_str(), comm.c_str());
    }

    co_return 0;

}

SyscCoroHelper ls_dir(SyscallCtx *ctx, char* dirname, std::vector<int> *pids) {
    char local_dirname[128]; // Fixed size will automap unlike char*
    strncpy(local_dirname, dirname, sizeof(local_dirname) - 1);
    local_dirname[sizeof(local_dirname) - 1] = '\0';


    // Yield syscall to guest_buf as a readonly directory
    int fd = yield_syscall(ctx, open, local_dirname, O_RDONLY | O_DIRECTORY);

    if (fd < 0) {
        printf("[PS] unable to open %s: %d\n", dirname, fd);
        co_return fd; // Pass errno back to caller
    }

    while (true) {
        // Buffer to hold dentries. By calling this loop multiple times I think
        // we iterate through the dentries(?) - eventually we get a return of 0 when we're done
        char d_buffer[2048]; 

        long nread = (long)yield_syscall(ctx, getdents64, fd, d_buffer, sizeof(d_buffer));
        assert (nread <= sizeof(d_buffer));

        if (nread < 0 ) {
            printf("[PS] unable to read dentries in loop: %ld\n", nread);
        }

        if (nread == 0) {
            break; // All done
        }

        for (long bpos = 0; bpos < nread;) {
            const struct dirent64 *d_ptr = reinterpret_cast<const struct dirent64 *>(d_buffer + bpos);

            // If it's a directory, and the name is a number, add it to the PID list
            if (d_ptr->d_type == DT_DIR) {
                int pid = atoi(d_ptr->d_name);
                if (pid > 0) {
                    pids->push_back(pid);
                }
            }

            bpos += d_ptr->d_reclen;
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
        yield_and_finish(ctx, *ctx->get_orig_syscall(), ExitStatus::SUCCESS); // Not an error, but not done

    } else if (!running_in_root_proc.try_lock()) {
        // Lock unavailable, bail on this coopter
        // Note we don't want to wait since that would block a guest proc
        yield_and_finish(ctx, *ctx->get_orig_syscall(), ExitStatus::SUCCESS); // Not an error, but not done
    }

    // Now running in a root process with the lock
    std::vector<int> pids;
    // Get list of PIDs
    yield_from(ls_dir, ctx, (char*)target_dir, &pids);

    // Print info for all PIDs
    yield_from(print_procinfo, ctx, &pids);

    //printf("Finish!\n");
    //running_in_root_proc.unlock(); // Maybe never unlock?
    yield_and_finish(ctx, *ctx->get_orig_syscall(), ExitStatus::FINISHED);
}
void __attribute__ ((destructor)) teardown(void) {
  fclose(fp);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  fp = fopen("ps.log", "w");
  map[-1] = ps_in_root;
  return true;
}
