#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>   // for ORIG_RAX register
#include <sys/syscall.h>

// Simple program to detect unexpected syscalls to test
// if HyDE is active from within a guest

void run_child(int syscall_num) {
    // Allow the parent to trace this process
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("ptrace(TRACEME)");
        exit(1);
    }

    // Trigger a stop to let the parent process attach
    raise(SIGSTOP);

    // Execute the target syscall
    syscall(syscall_num);

    // Exit cleanly after executing the syscall
    exit(0);
}

void run_parent(pid_t child_pid, int expected_syscall) {
    int status;
    long syscall;

    // Wait for the child to stop at SIGSTOP
    waitpid(child_pid, &status, 0);

    // Attach to the child process
    if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_SYSCALL)");
        exit(1);
    }

    // Monitor child syscalls
    while (1) {
        // Wait for child to hit syscall entry/exit
        waitpid(child_pid, &status, 0);

        // Check if the child has exited
        if (WIFEXITED(status)) break;

        // Get the syscall number (ORIG_RAX holds the syscall number)
        syscall = ptrace(PTRACE_PEEKUSER, child_pid, sizeof(long) * ORIG_RAX, NULL);

        // Compare observed syscall with expected syscall.
        // We might see a spurious rt_sigreturn syscall, which we can ignore.
        // We should eventually see an exit syscall, which we can also ignore.
        if (syscall != expected_syscall && \
            syscall != SYS_rt_sigreturn && \
            syscall != SYS_exit && syscall != SYS_exit_group) {
            printf("Child tasked with syscall %d but we observed %ld\n", expected_syscall, syscall);
            exit(1);
        }

        // Continue to the next syscall
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    }
}

int main(int argc, char *argv[]) {
    int syscall_num;
    for (syscall_num = 0; syscall_num < 1000; syscall_num++) {

        // rt_sigreturn is weird - skip it
        // vfork and pause will both stall our test - skip these
        if (syscall_num == SYS_rt_sigreturn || \
            syscall_num == SYS_vfork || syscall_num == SYS_pause) {
            continue;
        }

        pid_t child_pid = fork();

        if (child_pid == -1) {
            perror("fork");
            return 1;
        }

        if (child_pid == 0) {
            // Child process
            run_child(syscall_num);
        } else {
            // Parent process
            run_parent(child_pid, syscall_num);
        }
    }

    return 0;
}