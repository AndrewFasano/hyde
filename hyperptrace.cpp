#include <asm/unistd.h> // Syscall numbers
#include <sys/mman.h> // for mmap flags
#include <stdio.h>
#include <time.h> // nanosleep
#include <sys/wait.h> // for waitid
#include <errno.h> // EINTR
#include <sys/ptrace.h> // PTRACE_
#include <sys/user.h> // GETREGS layout for x86_64
#include <mutex>
#include <string.h>
#include "hyde.h"


int target_pid = 1137; // TODO - bash

static bool done = false;
static bool did_fork = false;
static bool found_child = false;
static int pending_parent_pid = -1;
static std::mutex running_in_root_proc;

static bool pending_fork = false;
static int parent_pid = -1;
static hsyscall pending_sc;

SyscCoro drive_child(asid_details* details) {
  signed long wait_rv;

  // We drive the child process we created, making it attach to the target process with ptrace,
  // then we allow the target process to run up to the next syscall.

  // First allocate scratch buffer
  ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap, NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

  // Next, request to attach to our target process.
  // Yield a syscall to attach with ptrace to target_pid
  // This will cause the target process to stop (SIGSTOP) soon, and we'll see it with waitid
  int ptrace_rv = yield_syscall(details, __NR_ptrace, PTRACE_ATTACH, target_pid, 0, 0);
  //printf("Ptrace attach to %d returns %d\n", target_pid, ptrace_rv);

  // Wait until the target is stopped
  do {
    // We'll see -EINTR a lot (telling us to retry) so let's handle that
    wait_rv = yield_syscall(details, __NR_waitid, P_PID, target_pid, (long unsigned)guest_buf, WSTOPPED, 0);
    //printf("Waitid returns %ld\n", wait_rv);
  } while (wait_rv == -EINTR);

  if (wait_rv < 0) {
    printf("FATAL? wait failed: %ld\n", wait_rv);
    assert(0);
  }
  //printf("Drive child - successfull attach and wait (%ld), now let's resume debuge to the next syscall\n", wait_rv);

  // "Debug loop" - either we have a command pending or we sleep (and make the debugee stall)
  // Right now we have no way to specify commands, so we just run between syscalls

  int ctr = 0;
  while (true) {
    ctr++;
    if (ctr % 2 == 1) { // Log on return, callno + retval
      // First get registers into guest memory
      long int greg_rv = (long int)yield_syscall(details, __NR_ptrace, PTRACE_GETREGS, target_pid, 0, (long unsigned)guest_buf);
      //printf("Getregs returns %ld\n", greg_rv);

      // Read registers out of guest memory
      user_regs_struct gregs;
      if (yield_from(ga_memread, details, &gregs, guest_buf, sizeof(user_regs_struct)) != 0) {
        printf("Failed to read gregs struct from guest memory\n");
        assert(0);
      }
      printf("%2d syscall: %lld  => %llx\n", ctr/2, gregs.orig_rax, gregs.rax); // Maybe we want orig_rax?
    }

    // Run the ptrace(PTRACE_SYSCALL, target) in order to continue the target process until the next syscall
    //printf("Continue target...\n");
    int pt_sc_rv = yield_syscall(details, __NR_ptrace, PTRACE_SYSCALL, target_pid, 1, 0);
    //printf("PTRACE_SYSCALL returns %d\n", pt_sc_rv);

    do {
      wait_rv = yield_syscall(details, __NR_waitid, P_PID, target_pid, (long unsigned)guest_buf, WSTOPPED|WEXITED, 0);
      //printf("Waitid2 returns %ld\n", wait_rv);
    } while (wait_rv == -EINTR);

    //printf("Wait RV returned %ld\n", wait_rv);

    if (wait_rv < 0) {
      printf("Bad wait_rv: %ld\n", wait_rv);
      assert(0);
    }

    int tmp_peek = yield_syscall(details, __NR_ptrace, PTRACE_PEEKUSER, target_pid, 0, (long unsigned)guest_buf);

    //printf("Peek returns %d\n", tmp_peek);

    if (tmp_peek == -ESRCH) {
      printf("Debuggee exited\n");
      break;
    }
    
    continue;
  #if 0

    // sleep no-op
    timespec req_h = {
      .tv_sec = 1,
      .tv_nsec = 0
    };
    // Write req_h into guest memory at guest_buf
    if (yield_from(ga_memwrite, details, guest_buf, &req_h, sizeof(timespec)) != 0) {
      printf("Failed to write timespec to guest memory\n");
      assert(0);
    }

    __u64 req_guest = (__u64)guest_buf;
    __u64 rem_guest = (__u64)guest_buf + sizeof(timespec);

    yield_syscall(details, __NR_nanosleep, guest_buf, (ga*)(uint_64t)guest_buf + sizeof(timespec));
#endif
  }

  // Finish? XXX want core platform to discard this asid? - should inejct exit
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
        co_return 0;
    }

    co_yield *(details->orig_syscall);
    co_return 0;
}

SyscCoro fork_root_proc(asid_details* details) {
    int rv = 0;
    int fd;
    int pid;

    if (!done) {
      if (yield_syscall(details, __NR_geteuid)) {
          rv = -1;
      }else {
        if (!running_in_root_proc.try_lock()) {
            // Lock unavailable, bail on this coopter
            // Note we don't want to wait since that would block a guest proc
            rv = -1;
        } else if (!done) {
          pid = yield_syscall(details, __NR_getpid);
          pending_parent_pid = pid;

          did_fork = true;
          yield_syscall(details, __NR_fork);

          done=true;
          running_in_root_proc.unlock();
        }
      }
    }

    co_yield *(details->orig_syscall); // noreturn
    co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

    if (did_fork && !found_child) {
        return &find_child_proc;
    }

    if (!done)
        return &fork_root_proc;

  return NULL;
}

