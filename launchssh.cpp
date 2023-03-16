#include <asm/unistd.h> // Syscall numbers
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
#include "hyde.h"

static bool done = false;
static bool did_fork = false;
static bool found_child = false;
static int pending_parent_pid = -1;
static std::mutex running_in_root_proc;

// What program do we run, with what args?
const char path[] = {"/bin/systemctl"};
std::vector argv = {"systemctl", "restart", "sshd.service"};

SyscCoro drive_child(asid_details* details) {
    // This will run in the child of our injected fork
    // after we yield execve, this function will never continue
    ga* envp;

    // First allocate scratch
    ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap, NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    printf("Scratch buffer is at %lx\n", (uint64_t)guest_buf);


    // Now write the path to the target process - Do we need null terminator explicitly, guest mem needs it for sure
    if (yield_from(ga_memwrite, details, guest_buf, (void*)path, strlen(path)+1) == -1) {
        printf("[launchssh] Error: could not to write path %s into to guest memory at %lx\n", path, (uint64_t)guest_buf);
    }

    // Now write the argv. We have two sets of memory writes to perform. 1) at guest_buf[strlen(path)+1] we need to
    // write the arguments, then we write a list of pointers to this buffer later

    ga* scratch = guest_buf + strlen(path)+1;
    scratch = (ga*)(((uint64_t)scratch + 0x10) & ~0x0f); // Align to 16 bytes

    std::vector <uint64_t> argv_ptrs;
    //for (auto &env_item : argv) {
    for (auto env_item = argv.begin(); env_item != argv.end(); env_item++) {
        if (yield_from(ga_memwrite, details, scratch, (void*)*env_item, strlen(*env_item)+1) == -1) {
            printf("[launchssh] Error writing %s into guest memory at %lx\n", *env_item, (uint64_t)scratch);
            goto fatal;
        }

        argv_ptrs.push_back((uint64_t)scratch);
        scratch += sizeof(ga*);
        //scratch += (scratch + 0x10) % 0x10;
    }

    argv_ptrs.push_back(0); // Null terminate

    // For each of the pointers in argv_ptrs, write the address into guest memory
    scratch = (ga*)(((uint64_t)scratch + 0x10) & ~0x0f); // Align to 16 bytes
    envp = (ga*)scratch; // Keep a copy to the start here

    for (auto &env_addr : argv_ptrs) {
        if (yield_from(ga_memwrite, details, scratch, &env_addr, sizeof(env_addr)) == -1) {
            printf("[launchssh] Error writing pointer %lx into guest memory at %lx\n", (uint64_t)env_addr, (uint64_t)scratch);
            goto fatal;
        }
        scratch += sizeof(env_addr);
    }

    printf("Running execve with pathname at %lx (%s) and envp at %lx\n", (uint64_t)guest_buf, path, (uint64_t)envp);
    yield_syscall(details, __NR_execve, guest_buf, envp, NULL); // XXX no return, for real, even on error
    assert(0 && "Unreachable");

fatal:
    printf("Fatal error in child - exiting\n");
    yield_syscall(details, __NR_exit, 0);

    co_return 0;
}

SyscCoro find_child_proc(asid_details* details) {

    int pid = yield_syscall(details, __NR_getpid);
    int ppid = yield_syscall(details, __NR_getppid);
    int tid = yield_syscall(details, __NR_gettid);

    if (ppid == pending_parent_pid) {
        printf("Found child: %d %d parent is %d\n", pid, tid, ppid);
        found_child = true;

        yield_from(drive_child, details);
        //assert(0 && "Unreachable");
    }

    co_yield *(details->orig_syscall);
    co_return 0;
}

SyscCoro start_coopter(asid_details* details) {
    int rv = 0;
    int fd;
    int pid;
    int tid;

    if (done) goto out;

    if (yield_syscall(details, __NR_geteuid)) {
        rv = -1;
        goto out;
    }

    if (!running_in_root_proc.try_lock()) {
        // Lock unavailable, bail on this coopter
        // Note we don't want to wait since that would block a guest proc
        rv = -1;
        goto out;
    }
    // Now running with the lock
    if (done) {
        goto out;
    }

    pid = yield_syscall(details, __NR_getpid);
    tid = yield_syscall(details, __NR_gettid);
    pending_parent_pid = pid;
    printf("Fork this: %d %d\n", pid, tid);

    did_fork = true;
    yield_syscall(details, __NR_fork);

    printf("Finished post-fork\n");
    done=true;

    running_in_root_proc.unlock();

out:
    co_yield *(details->orig_syscall); // noreturn
    co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

    if (did_fork && !found_child)
        return &find_child_proc;

    if (!done)
        return &start_coopter;

  return NULL;
}