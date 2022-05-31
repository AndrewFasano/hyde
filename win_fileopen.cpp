#include <asm/unistd.h>
#include <cstring>
#include <stdio.h>
#include <set>
#include <tuple>
#include "hyde.h"
#include "windows.h"

#define MIN(a, b) (a < b ? a : b)

std::set<std::tuple<unsigned, unsigned>> seen_handles;

SyscCoroutine closefile(asid_details* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  std::tuple<int, int> current = std::make_pair((unsigned)details->asid, (unsigned)regs.r10);

  if (seen_handles.contains(current)) {
    //printf("Asid %x closes handle %llx\n", details->asid, regs.r10);
    seen_handles.erase(current);
  }
}

SyscCoroutine openfile(asid_details* details) {
  // On NtOpenFile syscalls, inject the requested syscall, examine its
  // results and possibly inject more in order to access guest
  // memory. Then log the info. When we finish, prevent the original
  // syscall from being run a second time.

  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  long unsigned int *stack;
  map_guest_pointer(details, stack, regs.rsp);

  // We had a pointer to a handle in the first arg, map and read the value the kernel set!
  unsigned *handle;
  bool success;
  map_guest_pointer_status(details, handle, regs.r10, &success);
  if (!success) {
    //printf("Could not dereference handle pointer at %llx. Bail\n", regs.r10);
    co_return;
  }
  char open_name[512];

  sprintf(open_name, "[Error]");

  // Now let's parse the disgusting object_attributes struct in the third arg
  object_attributes *oa_struct;
  unicode_string* path_struct;
  wchar_t* path;
  map_guest_pointer_status(details, oa_struct, regs.r8, &success);
  if (!success) {
    //printf("Could not map r8 at %llx to an object_attributes struct\n", regs.r8);
    goto inject;
  }else{
#if 0
    printf("Object_attributes (%ld bytes):\n\tLength = 0x%lx\n\tRootDirectory = 0x%lx\n\tObjectName = 0x%lx\n\tAttributes = 0x%lx\n\tSecurityDescriptor = 0x%lx\n\tSecurityQoS = %lx\n",
        sizeof(object_attributes),
        (unsigned long)oa_struct->Length,
        (unsigned long)oa_struct->RootDirectory,
        (unsigned long)oa_struct->ObjectName,
        (unsigned long)oa_struct->Attributes,
        (unsigned long)oa_struct->SecurityDescriptor,
        (unsigned long)oa_struct->SecurityQualityOfService
        );
#endif
  }

  map_guest_pointer_status(details, path_struct, oa_struct->ObjectName, &success);
  if (!success) {
    //printf("Could not map object name at %lx\n", (unsigned long)oa_struct->ObjectName);
    goto inject;
  }

#if 0
  printf("object->ObjectName = path_struct:\n\tLength 0x%x\n\tMaxLen 0x%x\n\tBuffer 0x%lx\n",
      path_struct->Length, path_struct->MaximumLength, (unsigned long)path_struct->Buffer);
#endif

  map_guest_pointer_status(details, path, path_struct->Buffer, &success);
  if (!success) {
    //printf("Could not map object buffer with length %u at %lx\n",
    //    path_struct->Length, (unsigned long)path_struct->Buffer);
    goto inject;
   }
  // Convert the windows wide char* to a linux c char* with our helper function
  wchar_to_char(open_name, path, MIN(512, path_struct->Length));


inject:
  // Injected the requested syscall *now*, not when this co-opter finishes
  unsigned long int open_return = yield_syscall(details, NtOpenFile,
                                                regs.r10, regs.rdx,
                                                regs.r8, regs.r9,
                                                stack[5], stack[6]);
  bool open_failed = false;
  if (open_return != 0) {
    //printf("OpenFile in %x fails with  %lx\n", details->asid, open_return);
    open_failed = true;
  }

  if (!success) {
    //printf("OpenFile in %x couldn't read something - bail early\n", details->asid);
    //co_return;
  }

  //printf("OpenFile returned %lx - let's look into it more\n", open_return);

  // Now let's allocate a scratch buffer!
  get_regs_or_die(details, &regs);

  // XXX We'll pass RSP-based pointers - need to manually adjust stack

  // We're going to clobber 2 things below the stack at [0], [1]. We need to
  //  1) Save original values
  //  2) replace
  //  3) run syscall
  //  4) read new values
  //  5) restore original values

  unsigned int old_stack[2];
  map_guest_pointer(details, stack, regs.rsp);

  // Save original values
  memcpy(&old_stack, stack, sizeof(long unsigned int)*2);

  // Clobber
  stack[0] = 0; // Args[1] points here for in/out BaseAddress. Input is 0, output is buffer
  stack[1] = 0x1000; // Args[3] points here for RegionSize

  // Run the syscall - which will modify these stack-based values
  unsigned long allocate_ret = yield_syscall(details, NtAllocateVirtualMemory,
                -1,         // Handle: -1 => self
                regs.rsp,   // void** in out BaseAddress->ActualAddress
                0,          //
                regs.rsp+8, // int* in out requested size -> allocated size
                0x1000,     // Allocation type = MEM_COMMIT|MEM_RESERVE
                0x04);      // PAGE_READWRITE

  if (allocate_ret != 0) {
    printf("ERROR: Allocate returned %lx\n", allocate_ret);
  }

  // Just see if the mapping worked
  char* junk;
  map_guest_pointer_status(details, junk, stack[0], &success);

  unsigned long int buffer = stack[0];
  // Restore clobbered things from the stack
  memcpy(stack, &old_stack, sizeof(long unsigned int)*2);

  if (allocate_ret == 0 && success) {
    unsigned long query_ret = yield_syscall(details, NtQueryInformationProcess,
                  -1, // Handle: -1 => self
                  27, // ProcessImageFileName
                  buffer,
                  0x1000,
                  0); // output size pointer - not using

    if (query_ret == 0) {
      unicode_string *name_struct;
      map_guest_pointer(details, name_struct, buffer);
      
      wchar_t* name_w;
      map_guest_pointer_status(details, name_w, name_struct->Buffer, &success);
      if (success) {
        char c_name[512];
        wchar_to_char(c_name, name_w, MIN(512, name_struct->Length));
        if (!open_failed) {
          std::tuple<int, int> current = std::make_pair((unsigned)details->asid, (unsigned)*handle);
          seen_handles.insert(current);
          //printf("Asid %x is program '%s'\n\tOpens file '%s'\n\tGiven handle %x\n",
          //   details->asid, c_name, open_name, *handle);
        }else{
          //printf("Asid %x is program: '%s'\n\tFailed to open file '%s'\n\tGiven handle %x\n",
          //    details->asid, c_name, open_name, *handle);
        }
      }
    }else{
      //printf("Query returned %lx\n", query_ret);
    }
  }

  if (allocate_ret == 0) {
    // Now free allocated memory, again we have 2 pointers onto stack we cache and restore
    // Save original values
    memcpy(&old_stack, stack, sizeof(long unsigned int)*2);
    // Clobber
    stack[0] = buffer;
    stack[1] = 0x1000;

    get_regs_or_die(details, &regs);

    unsigned long free_ret = yield_syscall(details, NtFreeVirtualMemory,
                  -1,         // Handle: -1 => self
                  regs.rsp,   // void** in out BaseAddress
                  regs.rsp+8, // *Region size - must point to 0
                  0x8000);    // MEM_RELEASE

    unsigned long out_buf = stack[0];
    if (free_ret != 0) {
      printf("WARNING: free returns %lx with out_buf %lx\n", free_ret, out_buf);
    }
    memcpy(stack, &old_stack, sizeof(long unsigned int)*2);
  }

  // We already ran the requested syscall, don't run it again
  details->skip = true;
  details->orig_regs.rax = open_return;

  co_return;
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  switch (callno) {
    case NtOpenFile:
      return &openfile;
      break;
    case NtClose:
      return &closefile;
      break;
  }
  return NULL;
}

