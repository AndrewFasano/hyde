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

#define BUF_SIZE 1024

SyscCoro print_procinfo(asid_details *details, std::vector<int> *pids) {

    ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap, 0, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (int pid : *pids) {
        char fd_path[128];
        char cmdline[BUF_SIZE];
        char comm[BUF_SIZE];

        // Populate fd_path with /proc/<pid>/cmdline
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/cmdline", pid);
        if (yield_from(ga_memwrite, details, guest_buf, (void*)fd_path, strlen(fd_path)+1) == -1) {
            printf("[PS] Error: could not to write cmdline path into to guest memory for pid %d\n", pid);
            continue;
        }

        // Read cmdline and comm into guest_buf
        //int fd = yield_syscall(details, __NR_openat, AT_FDCWD, guest_buf, O_RDONLY);
        int fd = yield_syscall(details, __NR_open, guest_buf, O_RDONLY, 0);
        if (fd < 0) {
            printf("[PS] Error: could not open cmdline file for pid %d - open(%s, %d) => %d;\n", pid, fd_path, O_RDONLY, fd);
            strcpy(cmdline, "[open error]");
        } else {
            // Assuming cmdline is less than BUF_SIZE so we only need one read
            int read_rv = yield_syscall(details, __NR_read, fd, guest_buf, BUF_SIZE);

            if (read_rv < 0) {
                strcpy(cmdline, "[read error]" );
            } else if (read_rv == 0) {
                strcpy(cmdline, "[empty]" );
            } else {
                if (yield_from(ga_memcpy, details, cmdline, guest_buf, read_rv) == -1) {
                    printf("[PS] Error: could not read cmdline from guest memory for pid %d\n", pid);
                    strcpy(cmdline, "???");
                }

                // Drop null terminators up to the last one (since we have null-seperated args)
                for (int i = 0; i < read_rv-1; i++)
                    if (cmdline[i] == '\0')
                        cmdline[i] = ' ';
            }
            // Close fd
            yield_syscall(details, __NR_close, fd);
        }

        // Now read comm into guest_buf, just like before
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/comm", pid);
        if (yield_from(ga_memwrite, details, guest_buf, (void*)fd_path, strlen(fd_path)+1) == -1) {
            printf("[PS] Error: could not to write comm path into to guest memory for pid %d\n", pid);
            continue;
        }

        fd = yield_syscall(details, __NR_open, guest_buf, O_RDONLY, 0);
        if (fd < 0) {
            printf("[PS] Error: could not open comm file for pid %d - open(%s, %d) => %d;\n", pid, fd_path, O_RDONLY, fd);
            strcpy(comm, "[open error]");
        } else {
            int read_rv = yield_syscall(details, __NR_read, fd, guest_buf, BUF_SIZE);

            if (read_rv < 0) {
                strcpy(comm, "[read error]" );
            } else if (read_rv == 0) {
                strcpy(comm, "[empty]" );
            } else {
                // Populate comm
                if (yield_from(ga_memcpy, details, comm, guest_buf, read_rv) == -1) {
                    printf("[PS] Error: could not read comm from guest memory for pid %d\n", pid);
                    strcpy(comm, "???");
                }else {
                    comm[read_rv-1] = '\0';
                }
            }
            yield_syscall(details, __NR_close, fd);
        }


        printf("%d: %s  %s\n", pid, cmdline, comm);

    }

done:
    yield_syscall(details, __NR_munmap, guest_buf, BUF_SIZE);
    co_return 0;

error:
    yield_syscall(details, __NR_munmap, guest_buf, BUF_SIZE);
    co_return -1;

}

SyscCoro ls_dir(asid_details *details, char* dirname, std::vector<int> *pids) {
    int fd;
    long nread;
    //char buf[BUF_SIZE];
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
    // Grab a mutex in a root process and run ls_dir

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