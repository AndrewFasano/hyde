#include <asm/unistd.h>
#include <cstring>
#include <stdio.h>
#include "hyde.h"
#include "windows.h"

SyscCoroutine openfile(asid_details* details) {
  // On NtOpenFile syscalls, inject the requested syscall, examine its
  // results and possibly inject more in order to access guest
  // memory. Then log the info. When we finish, prevent the original
  // syscall from being run a second time.
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // Injected the _requested_ syscall now
  hsyscall s;
  s.callno = NtOpenFile;
  s.nargs = 4; // Remainder of real args are on stack - we can just leave them alone
  s.args[0] = regs.r10;
  s.args[1] = regs.rdx;
  s.args[2] = regs.r8;
  s.args[3] = regs.r9;
  co_yield s;

  // We had a pointer to a handle in the first arg, map and read the value the kernel set!
  long unsigned int *handle;
  map_guest_pointer(details, handle, regs.r10);

  // Now let's parse the disgusting object_attributes struct in the third arg
  object_attributes *oa_struct;
  unicode_string* path_struct;
  wchar_t* path;
  map_guest_pointer(details, oa_struct, regs.r8);
  map_guest_pointer(details, path_struct, oa_struct->ObjectName);
  map_guest_pointer(details, path, path_struct->Buffer);

  // Convert the windows wide char* to a linux c char* with our helper function
  char c_name[512];
  wchar_to_char(c_name, path, 512);
  printf("OpenFile of '%s' returns status %lx and handle %lx\n", c_name, details->retval, *handle);

  // We already ran the requested syscall, don't run it again
  details->skip = true;
  details->orig_regs.rax = details->retval;

  co_return;
}


SyscCoroutine readfile(asid_details* details) {
  // NtReadFile has a handle as the first argument, just log it
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  printf("ReadFile: Handle at %llx in %x\n", regs.r10, details->asid);
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  switch (callno) {
    case NtReadFile:
      return &readfile;
      break;
    case NtOpenFile:
      return &openfile;
      break;
  }
  return NULL;
}

