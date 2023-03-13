#include <asm/unistd.h> // Syscall numbers
#include <sys/mman.h> // for mmap flags
#include <stdio.h>
#include <time.h> // nanosleep
#include <sys/wait.h> // for waitid
#include <errno.h> // EINTR
#include <sys/ptrace.h> // PTRACE_
#include <sys/user.h> // GETREGS layout for x86_64
#include <string.h>
#include "hyde.h"

#define TARGET "whoami"

static bool pending_fork = false;
static int parent_pid = -1;
static hsyscall pending_sc;

SyscCoroutine start_coopter(asid_details* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  
  unsigned long pid;
  unsigned long child;
  // Create `fname`, a pointer into *guest* memory at the address that's in the first syscall arg
  char *fname;
  map_guest_pointer(details, fname, get_arg(regs, 0));
  //printf("[HyperPtrace] SYS_exec(%s)\n", fname);

  if (strchr(fname, '/') == NULL) {
    if (strcmp(fname, TARGET) != 0) { // No slash and not exact match
      goto end;
    }
  } else if ((strcmp(rindex(fname, '/')+1, TARGET) != 0)) { // Has slash, compare after last
    goto end;
  }

  {
    pid = yield_syscall(details, __NR_getpid);
    pending_fork = true;
    parent_pid = pid;
    printf("[PARENT] [debug] do fork in pid %ld with asid %x at PC %llx\n", pid, details->asid, details->orig_regs.rcx);

    child = yield_syscall(details, __NR_fork);

    memcpy(&pending_sc, details->orig_syscall, sizeof(pending_sc));

    if ((signed int)child < 0) {
      printf("Error with execve - ignore\n");
      pending_fork = false;
      parent_pid = -1;
      details->orig_regs.rax = child; // Assume fork failure code can be used for execve?
      co_return;
    }
    printf("[PARENT] PID is %ld with child %ld\n", pid, child);

    // Allocate a scratch buffer in the parent - this process will never return so we
    // can do anything we want in it
    __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
        /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
        /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

    // First we wait for the child to start and then be stopped
    // his_sc = Syscall('waitid', [consts.P_PID, child_pid, outbuf, consts.WSTOPPED, 0], signed=True)

    printf("[PARENT] waiting on child %s to start...\n", fname);
    signed long wait_rv = -EINTR;

    // We get -10 a LOT right now...
    while (wait_rv == -EINTR) {
      wait_rv = yield_syscall(details, __NR_waitid, P_PID, child, (long unsigned)guest_buf, WSTOPPED, 0);
    }
    if (wait_rv < 0) {
      printf("FATAL? wait failed: %ld\n", wait_rv);
      assert(0);
    }
    printf("[PARENT]: child is ready!\n");

    // "Debug loop" - either we have a command pending or we sleep the parent process (and the child)
    int ctr = 0;
    while (true) {

      ctr++;
      if (ctr % 2 == 1) { // Log on return, callno + retval
        // First get registers
        long int greg_rv = yield_syscall(details, __NR_ptrace, PTRACE_GETREGS, child, 0, (long unsigned)guest_buf);
        //printf("Greg: %ld\n", greg_rv);

        user_regs_struct *gregs;
        map_guest_pointer(details, gregs, guest_buf);
        printf("%2d syscall: %lld  => %llx\n", ctr/2, gregs->orig_rax, gregs->rax); // Maybe we want orig_rax?
      }

      yield_syscall(details, __NR_ptrace, PTRACE_SYSCALL, child, 1, 0);

      // Syscall('waitid', [consts.P_PID, child_pid, outbuf, consts.WSTOPPED|consts.WEXITED, 0], signed=True)
      wait_rv = -EINTR;
      while (wait_rv == -EINTR) {
        wait_rv = yield_syscall(details, __NR_waitid, P_PID, child, (long unsigned)guest_buf, WSTOPPED|WEXITED, 0);
      }

      if (wait_rv < 0) {
        printf("Bad wait_rv: %ld\n", wait_rv);
        assert(0);
      }

      //yield (tmp_peek := Syscall('ptrace', [cmd, child_pid, 0, outbuf], signed=True))
      auto tmp_peek = yield_syscall(details, __NR_ptrace, PTRACE_PEEKUSER, child, 0, (long unsigned)guest_buf);

      if (tmp_peek == -ESRCH) {
        printf("Debuggee exited\n");
        break;
      }
      
      continue;
      // sleep no-op
      timespec* req_h;
      map_guest_pointer(details, req_h, guest_buf);
      req_h->tv_sec  = 1;
      req_h->tv_nsec = 0;
      __u64 req_guest = (__u64)guest_buf;
      __u64 rem_guest = (__u64)guest_buf + sizeof(timespec);
      child = yield_syscall(details, __NR_nanosleep, req_guest, rem_guest);
    }

    // Finish? XXX want core platform to discard this asid? - should inejct exit
    yield_syscall(details, __NR_exit, 0);
    co_return;
  }

end:
  co_yield *(details->orig_syscall); // callno=59
}

SyscCoroutine possible_child(asid_details* details) {
  // For every process that could be a child, check it's PPID and see if it matches the pending parent
  unsigned long ppid = yield_syscall(details, __NR_getppid);

  if (parent_pid == ppid) {
    unsigned long pid = yield_syscall(details, __NR_getpid);
    printf("\n[CHILD] Found child with pid %ld, asid %x at PC %llx\n", pid, details->asid, details->orig_regs.rcx);
    pending_fork = false;
    parent_pid = -1;

    // Enable tracing
    yield_syscall(details, __NR_ptrace, PTRACE_TRACEME, 0, 0, 0);

    // Inject the execve requested by the parent
    co_yield pending_sc;
    co_return;
  }
  co_yield *(details->orig_syscall);
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  if (callno == __NR_execve) {
    return &start_coopter;
    // } else if (callno == __NR_ptrace) {
    // Hmm, we'll see our own injected ptrace syscalls here
  } else if (pending_fork) {
    return &possible_child;
  }
  return NULL;
}

