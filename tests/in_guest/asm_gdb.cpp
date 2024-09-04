#include <iostream>
#include <sys/syscall.h>
#include <signal.h>

int main(int argc, char* argv[]) {
    // Run a specified syscall
    //int sc_no = atoi(argv[1]);

    // With raw assembly, push magic values into all the GPRs
    // and then trigger the syscall
    __asm__("mov $0xb3, %%rax;"
            "mov $0x13371338, %%rbx;"
            "mov $0x13371339, %%rcx;"
            "mov $0x1337133A, %%rdx;"
            "mov $0x1337133B, %%rsi;"
            "mov $0x1337133C, %%rdi;"
            "mov $0x1337133D, %%rbp;"
            "mov $0x1337133E, %%rsp;" // Don't modify the stack pointer
            "mov $0x1337133F, %%r8;"
            "mov $0x13371340, %%r9;"
            "mov $0x13371341, %%r10;"
            "mov $0x13371342, %%r11;"
            "mov $0x13371343, %%r12;"
            "mov $0x13371344, %%r13;"
            "mov $0x13371345, %%r14;"
            "mov $0x13371346, %%r15;"
            //"mov $0x13371347, %%rflags;" // Don't modify flags
            //"mov $0x13371348, %%cs;" // Don't modify segment registers
            //"mov $0x13371349, %%ss;"
            //"mov $0x1337134A, %%ds;"
            //"mov $0x1337134B, %%es;"
            //"mov $0x1337134C, %%fs;"
            //"mov $0x1337134D, %%gs;"
            //"mov $0x1337134E, %%fs_base;" // Don't modify segment base addresses
            //"mov $0x1337134F, %%gs_base;"
            //"mov $0x13371350, %%orig_rax;" // Don't modify orig_rax
            "syscall;"
            "int $3;"
            : /* No output */
            : /* No input */
            );
    return 0;
}
