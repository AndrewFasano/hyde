/* Written entirely by GPT-4 with the following prompt:
 * Write a C++ program (similar to strace) that uses the ptrace APIs to debug a target program,
 * specified by PID in argv[1] . After attaching to the target, allow the program to resume until
 * the next syscall (using PTRACE_SYSCALL). At the syscall, print the contents of every guest register.
 * Then advance until the syscall returns (again with PTRACE_SYSCALL), print the contents of all
 * registers flagging the values that have changed during the syscall.
 * 
 * And then a request clarifying I wanted callno on enter and difference on return
 * 
 * And then I manually added the fork and child stuff and made GPT4 fix it
 */
/* Written entirely by GPT-4 with the following prompt:
 * Write a C++ program (similar to strace) that uses the ptrace APIs to debug a target program,
 * specified by PID in argv[1] . After attaching to the target, allow the program to resume until
 * the next syscall (using PTRACE_SYSCALL). At the syscall, print the contents of every guest register.
 * Then advance until the syscall returns (again with PTRACE_SYSCALL), print the contents of all
 * registers flagging the values that have changed during the syscall.
 * 
 * And then a request clarifying I wanted callno on enter and difference on return
 * 
 * NORMAL OUTPUT
 
Syscall listen
RAX: 0xffffffffffffffda => 0xffffffffffffffa8

Syscall callno=231

 */
#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

void print_registers(struct user_regs_struct &regs, struct user_regs_struct &prev_regs) {
  const char* reg_names[] = {
    "R15", "R14", "R13", "R12", "RBP", "RBX", "R11", "R10", "R9", "R8", "RAX", "RCX", "RDX", "RSI", "RDI", "ORIG_RAX",
    "RIP", "CS", "EFLAGS", "RSP", "SS", "FS_BASE", "GS_BASE", "DS", "ES", "FS", "GS"
  };

  for (int i = 0; i < 27; i++) {
    uint64_t reg_value = reinterpret_cast<uint64_t*>(&regs)[i];
    uint64_t prev_reg_value = reinterpret_cast<uint64_t*>(&prev_regs)[i];

    if (reg_value != prev_reg_value) {
        std::cout << reg_names[i] << ": 0x" << std::hex << prev_reg_value << " => 0x" << reg_value << std::dec << std::endl;
    }
  }
}

int main(int argc, char* argv[]) {
    pid_t target_pid = fork();

    if (target_pid == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP); // Signal the parent process to start tracing
        syscall(SYS_listen, 0, 0, 0); // This is the syscall we want to trace
        return 0;
    }

    // Wait for the child process to stop after calling PTRACE_TRACEME
    waitpid(target_pid, nullptr, 0);

    struct user_regs_struct prev_regs, current_regs;
    bool at_syscall_entry = false; // XXX this could be backwards

    while (true) {
        ptrace(PTRACE_SYSCALL, target_pid, nullptr, nullptr);
        int status;
        waitpid(target_pid, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break; // Break the loop if the child process has exited or has been signaled to stop
        }

        prev_regs = current_regs;
        ptrace(PTRACE_GETREGS, target_pid, nullptr, &current_regs);

        if (current_regs.orig_rax != -1) {
            at_syscall_entry = !at_syscall_entry;
        }

        if (at_syscall_entry) {
            std::cout << "Syscall callno=" << current_regs.orig_rax << std::endl;
        } else {
            std::cout << "Sysret" << std::endl;
            print_registers(current_regs, prev_regs);
            std::cout << std::endl;
        }
    }

    ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);
    return 0;
}
