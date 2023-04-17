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
static bool finished = false;
static bool did_fork = false;
static bool found_child = false;
static int pending_parent_pid = -1;
static std::mutex running_in_root_proc;

// What program do we run, with what args?
const char path[] = {"/bin/systemctl"};
std::vector argv = {"systemctl", "restart", "sshd.service"};
#define ARGV_SIZE 3
//const char path[] = {"/bin/sleep"};
//std::vector argv = {"sleep", "5m"};

SyscCoroHelper drive_child(syscall_context* details) {
    // This will run in the child of our injected fork
    // after we yield execve, this function will never continue
    uint64_t argv_addr;

    // First allocate scratch, we'll need to persistently store our argv array in there - both values and pointers
    uint64_t scratch = yield_syscall(details, mmap, NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    // Write argv strings into guest memory, populate a vector of with these pointers
    std::vector <uint64_t> argv_ptrs;
    for (auto env_item = argv.begin(); env_item != argv.end(); env_item++) {
        //printf("At guest %lx write %s (size with null is %lu)\n", (uint64_t)scratch, *env_item, strlen(*env_item)+1);
        if (yield_from(ga_memwrite, details, scratch, (void*)*env_item, strlen(*env_item)+1) == -1) {
            printf("[launchssh] Error writing %s into guest memory at %lx\n", *env_item, (uint64_t)scratch);
            goto fatal;
        }
        argv_ptrs.push_back(scratch);
        scratch += strlen(*env_item)+1;
        scratch = ((uint64_t)scratch + 0x10) & ~0x0f; // Align to 16 bytes - probably unnecessary
    }
    argv_ptrs.push_back(0); // And null teriminate the list of pointers

    // Now write argv itself (list of pointers) into guest memory, save the start of this array into argv_addr
    argv_addr=scratch;
    for (auto &env_addr : argv_ptrs) {
        if (yield_from(ga_memwrite, details, scratch, &env_addr, sizeof(env_addr)) == -1) {
            printf("[launchssh] Error writing pointer %lx into guest memory at %lx\n", (uint64_t)env_addr, (uint64_t)scratch);
            goto fatal;
        }
        scratch += sizeof(env_addr);
    }

    // We can't set an exit status directly here since we never return
    // Instead we'll set finished, and on the next syscall we'll indicate that we're done
    finished = true;
    yield_syscall(details, execve, path, argv_addr, NULL); // XXX no return, for real, even on error
    assert(0 && "Unreachable");

fatal:
    printf("Fatal error in child - exiting\n");
    yield_syscall(details, exit, 0);

    co_return -1;
}

SyscallCoroutine find_child_proc(syscall_context* details) {

    int pid = yield_syscall0(details, getpid);
    int ppid = yield_syscall0(details, getppid);
    int tid = yield_syscall0(details, gettid);

    if (ppid == pending_parent_pid) {
        printf("Found child: %d %d parent is %d\n", pid, tid, ppid);
        found_child = true;

        if (yield_from(drive_child, details) == -1) {
            // Child process failed to run execve so we killed it. Bad but non-fatal.
            // Set us up to retry forking another process
            did_fork = false;
            found_child = false;
            co_return ExitStatus::SINGLE_FAILURE;
        }
    }

    co_yield *(details->orig_syscall);
    co_return ExitStatus::SUCCESS;
}

SyscallCoroutine fork_root_proc(syscall_context* details) {
    int fd;
    int pid;
    int tid;

    if (done) goto out;

    if (yield_syscall0(details, geteuid)) {
        goto out;
    }

    if (!running_in_root_proc.try_lock()) {
        // Lock unavailable, bail on this coopter
        // Note we don't want to wait since that would block a guest proc
        goto out;
    }
    // Now running with the lock
    if (done) {
        goto out;
    }

    pid = yield_syscall0(details, getpid);
    tid = yield_syscall0(details, gettid);
    pending_parent_pid = pid;
    //printf("Fork this: %d %d\n", pid, tid);

    did_fork = true;
    yield_syscall0(details, fork);
    done=true;
    running_in_root_proc.unlock();

out:
    co_yield *(details->orig_syscall); // noreturn
    co_return ExitStatus::SUCCESS; // Even if we're waiting, it's not a failure
}

SyscallCoroutine indicate_success(syscall_context* details) {
    // Simple coro to change nothing, but indicate that we're done
    // This runs after we execve'd and abandoned that child
    co_yield *(details->orig_syscall);
    co_return ExitStatus::FINISHED;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

    if (did_fork && !found_child)
        return &find_child_proc;

    if (!done)
        return &fork_root_proc;

    if (finished)
        return &indicate_success;

  return NULL;
}