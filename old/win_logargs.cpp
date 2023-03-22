#include <asm/unistd.h>
#include <cstring>
#include <stdio.h>
#include "hyde.h"
#include "windows.h"

#define MIN(a, b) (a < b ? a : b)

// WIP: inject NtQueryInformationProcess to learn about current process - 
// needs scratch buffer
#if 0
  // Now let's inject a NtQueryInformationProcess to get PID!
typedef struct {
  byte                          Reserved1[2];
  byte                          BeingDebugged;
  byte                          Reserved2[1];
  void*                         Reserved3[2];
  char                          Ldr[8+(64*3)+(64*2)];
  char                          ProcessParameters[100]; // XXX bad size
  void*                         Reserved4[3];
  void*                         AtlThunkSListPtr;
  void*                         Reserved5;
  unsigned long                 Reserved6;
  void*                         Reserved7;
  unsigned long                 Reserved8;
  unsigned long                 AtlThunkSListPtr32;
  void*                         Reserved9[45];
  byte                          Reserved10[96];
  char                          PostProcessInitRoutine[100]; //pps_post_process_init_routine
  byte                          Reserved11[128];
  void*                         Reserved12[1];
  unsigned long                 SessionId;
} peb;

typedef struct  {
    long int ExitStatus;
    peb* PebBaseAddress;
    unsigned long* AffinityMask;
    unsigned long BasePriority;
    unsigned long* UniqueProcessId;
    unsigned long* InheritedFromUniqueProcessId;
} process_basic_information;

  s.callno = NtQueryInformationProcess;
  /*
   *   [in]            HANDLE           ProcessHandle,
   *   [in]            PROCESSINFOCLASS ProcessInformationClass,
   *   [out]           PVOID            ProcessInformation,
   *   [in]            ULONG            ProcessInformationLength,
   *   [out, optional] PULONG           ReturnLength
  */
  s.nargs = 4; // Will manually set up stack?
  s.args[0] = -1;  // Handle: Current process
  s.args[1] = 0;  // ProcessInfoClass: ProcessBasicInformation=0
  s.args[2] = regs.rsp-100;  // Pointer for struct
#endif  

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
  unsigned long int open_return = details->retval;

  // We had a pointer to a handle in the first arg, map and read the value the kernel set!
  long unsigned int *handle;
  map_guest_pointer(details, handle, regs.r10);

  // Now let's parse the disgusting object_attributes struct in the third arg
  object_attributes *oa_struct;
  unicode_string* path_struct;
  wchar_t* path;
  bool success;
  map_guest_pointer_status(details, oa_struct, regs.r8, &success);
  if (!success) goto failure;

  if (open_return == 0) {
    map_guest_pointer_status(details, path_struct, oa_struct->ObjectName, &success);
    if (!success) goto failure;
    map_guest_pointer_status(details, path, path_struct->Buffer, &success);
    if (!success) goto failure;
    // Convert the windows wide char* to a linux c char* with our helper function
    char c_name[512];
    wchar_to_char(c_name, path, MIN(512, path_struct->Length));
    printf("OpenFile '%s' gets handle %lx\n", c_name, *handle);
  } else {
failure:
    printf("OpenFile returns %lx - unable to read data\n", open_return);
  }

  // We already ran the requested syscall, don't run it again
  details->skip = true;
  details->orig_regs.rax = open_return;

  co_return;
}


SyscCoroutine readfile(asid_details* details) {
  printf("ReadFile\n");
  // NtReadFile has a handle as the first argument, just log it
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  printf("ReadFile: Handle at %llx in %x\n", regs.r10, details->asid);
  // 4 reg args, then stack - args 6 and 7 are buffer+length
  // Stack[1] is arg 6, stack[2] is arg 7

  long unsigned int *stack;
  unsigned long g_buf_ptr;
  unsigned long g_buf_sz;
  map_guest_pointer(details, stack, regs.rsp);
  g_buf_ptr = stack[2];
  g_buf_sz = stack[3];
  printf("\tBuf is at %lx with length %lx\n", g_buf_ptr, g_buf_sz);

  for (int i=0; i < 8; i++) {
    printf("Stack[%d] = %lx\n", i, stack[i]);
  }

  // Again, let's inject the syscall early 
  hsyscall s;
  s.callno = NtReadFile;
  s.nargs = 4; // Remainder of real args are on stack - we can just leave them alone
  s.args[0] = regs.r10;
  s.args[1] = regs.rdx;
  s.args[2] = regs.r8;
  s.args[3] = regs.r9;
  co_yield s;
  unsigned long int read_ret = details->retval; // Always 0?

  get_regs_or_die(details, &regs);
  map_guest_pointer(details, stack, regs.rsp);
  printf("\tBuf is at %lx with length %lx\n", g_buf_ptr, g_buf_sz);

  bool success;
  unsigned long *data;
  printf("RetReg  [0] = %16lx ==> ", regs.r10);
  map_guest_pointer_status(details, data, regs.r10, &success);
  if (success) {
    printf("%lx", *data);
  }
  printf("\nRetReg  [1] = %16lx ==> ", regs.rdx);
  map_guest_pointer_status(details, data, regs.rdx, &success);
  if (success) {
    printf("%lx", *data);
  }
  printf("\nRetReg  [2] = %16lx ==> ", regs.r8);
  map_guest_pointer_status(details, data, regs.r8, &success);
  if (success) {
    printf("%lx", *data);
  }
  printf("\nRetReg  [3] = %16lx ==> ", regs.r9);
  map_guest_pointer_status(details, data, regs.r9, &success);
  if (success) {
    printf("%lx", *data);
  }
  printf("\n");


  for (int i=-3; i < 8; i++) {
    printf("RetStack[%d] = %16lx ==> ", i, stack[i]);
    map_guest_pointer_status(details, data, stack[i], &success);
    if (success) {
      printf("%lx", *data);
    }
    printf("\n");
  }

  //map_guest_pointer_status(details, stack, regs.rsp, &success);
  if (1) {

    char *buffer;
    map_guest_pointer_status(details, buffer, g_buf_ptr, &success);

    //for (int i=0; i < MIN(100, g_buf_sz); i++) {
    //  printf("Data[%d]: 0x%02x\n", i, buffer[i]&0xff);
    //}

    if (success) {
      //char data[512];
      //wchar_to_char(data, buffer, MIN(512, stack[3]));
      //printf("Data: %s\n", data);
      printf("Data: %s\n", buffer);
    }
  }

  details->skip = true;
  details->orig_regs.rax = read_ret;
}

SyscCoroutine logargs(asid_details* details) {
  // NtReadFile has a handle as the first argument, just log it
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  long unsigned int *stack;
  map_guest_pointer(details, stack, regs.rsp);

  // Again, let's inject the syscall early 
  hsyscall s;
  s.callno = regs.rax; // Original callno should be in rax
  printf("\nSyscall %lx\n", s.callno);
  s.nargs = 4; // Remainder of real args are on stack - we can just leave them alone
  s.args[0] = regs.r10;
  s.args[1] = regs.rdx;
  s.args[2] = regs.r8;
  s.args[3] = regs.r9;
  co_yield s;
  unsigned long int orig_ret = details->retval;

  struct kvm_regs after_regs;
  get_regs_or_die(details, &after_regs);
  map_guest_pointer(details, stack, after_regs.rsp);

  bool success;
  unsigned long *data;
  printf("RetReg   [0] = %16lx ==> ", after_regs.r10);
  map_guest_pointer_status(details, data, after_regs.r10, &success);
  if (success) {
    printf("%lx", *data);
  }
  printf("\nRetReg   [1] = %16lx ==> ", after_regs.rdx);
  map_guest_pointer_status(details, data, after_regs.rdx, &success);
  if (success) {
    printf("%lx", *data);
  }
  printf("\nRetReg   [2] = %16lx ==> ", after_regs.r8);
  map_guest_pointer_status(details, data, after_regs.r8, &success);
  if (success) {
    printf("%lx", *data);
  }
  printf("\nRetReg   [3] = %16lx ==> ", after_regs.r9);
  map_guest_pointer_status(details, data, after_regs.r9, &success);
  if (success) {
    printf("%lx", *data);
  }
  printf("\n");


  for (int i=-3; i < 8; i++) {
    printf("RetStack[%2d] = %16lx ==> ", i, stack[i]);
    map_guest_pointer_status(details, data, stack[i], &success);
    if (success) {
      printf("%lx", *data);
    }
    printf("\n");
  }
  details->skip = true;
  details->orig_regs.rax = orig_ret;
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  switch (callno) {
    //case NtCreateFile:
    //    return &logargs;
    //    break;
    //case NtReadFile:
    //  return &readfile;
    //  break;
    case NtOpenFile:
      return &openfile;
      break;
  }
  return NULL;
}

