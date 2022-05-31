#include <asm/unistd.h>
#include <cstring>
#include <stdio.h>
#include <set>
#include <tuple>
#include "hyde.h"
#include "windows.h"
#define MIN(a, b) (a < b ? a : b)

typedef unsigned char byte;

typedef struct _list_entry {
  uint32_t *Flink; // On a 64-bit guest, you'd think these would be bigger
  uint32_t *Blink; // But they seem to really be 32-bit pointers
} list_entry;

//typedef struct  { // Official version?
//    byte Reserved1[8];
//    uint32_t Reserved2[3]; // XXX 32 or 64?
//    list_entry InMemoryOrderModuleList;
//} peb_ldr_data;
//
typedef struct  { // XP-based version?
    uint32_t Length;
    uint8_t Initialized[4];
    uint32_t SsHandle;
    list_entry InLoadOrder;
    list_entry InMemOrder;
    list_entry InInitOrder;
} peb_ldr_data;

typedef struct {
  byte                          Reserved1[2];
  byte                          BeingDebugged;
  byte                          Reserved2[1];
  void*                         Reserved3[2];
  //char                          Ldr[8+(64*3)+(64*2)];
  peb_ldr_data*                  Ldr;             // In XP this was at offset 0xC - same?
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

typedef struct {
    list_entry InLoadOrderLinks;
    list_entry InMemoryOrderLinks;
    list_entry InInitializationOrderModuleList;
    uint64_t BaseAddress;
    uint64_t EntryPoint;
    uint64_t Reserved;
    unicode_string FullDllName;
    unicode_string BaseDllName;
} ldr_data_table_entry;


typedef struct  {
    long int ExitStatus;
    peb* PebBaseAddress;
    unsigned long* AffinityMask;
    unsigned long BasePriority;
    unsigned long* UniqueProcessId;
    unsigned long* InheritedFromUniqueProcessId;
} process_basic_information;


SyscCoroutine mytest(asid_details* details) {
  // Testing on file open - get PEB, print modules, then run orig syscall
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // XXX We'll pass RSP-based pointers - need to manually adjust stack
  long unsigned int *stack;
  long unsigned int old_stack[2];
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

  unsigned long int buffer = stack[0];
  // Restore clobbered things from the stack
  memcpy(stack, &old_stack, sizeof(long unsigned int)*2);

  if (allocate_ret != 0) {
    printf("ERROR: Allocate returned %lx. BAIL\n", allocate_ret);
    co_return;
  }

  stack[0] = 0; // Clobber it again - will get output size here
  unsigned long query_ret = yield_syscall(details, NtQueryInformationProcess,
                                          -1, // Handle: -1 => self
                                          0, // ProcessBasicInformation
                                          buffer,
                                          sizeof(process_basic_information),
                                          regs.rsp); // output size pointer - not using

  //printf("QueryInfo with buffer %lx returns %lx with ReturnLength %lx\n",
  //     buffer,  query_ret, stack[0]);
  memcpy(stack, &old_stack, sizeof(long unsigned int)*2);

  if (query_ret == 0) {
    process_basic_information *pbi;
    map_guest_pointer(details, pbi, buffer);

    //printf("\nExitStatus %lx, Peb at %lx, PID %lx\n",
    //    pbi->ExitStatus,
    //    (unsigned long)pbi->PebBaseAddress,
    //    (unsigned long)pbi->UniqueProcessId);

    peb *p;
    map_guest_pointer(details, p, pbi->PebBaseAddress);
    //printf("PEB -> LDR is at %lx\n", (unsigned long)p->Ldr);

    peb_ldr_data *pld;
    map_guest_pointer(details, pld, p->Ldr);

    //printf("PEB_LDR_DATA: InMemoryOrder Forward %lx, backwards %lx\n",
    //    (long unsigned int)pld->InMemOrder.Flink,
    //    (long unsigned int)pld->InMemOrder.Blink);

    // XXX: something is broken down here - I suspect it's the offsets related
    // to the linked list-> struct base resolution? for LDTE?
    ldr_data_table_entry *ldte;

    long unsigned int flink = (long unsigned int)pld->InMemOrder.Flink;
    long unsigned int first = flink;
    bool is_first = true;

    int sanity = 0;
    while (flink != first || is_first) {
      is_first = false;

      assert(sanity++ < 1000);
      map_guest_pointer(details, ldte, flink);
      char dll_name[512];
      wchar_t* dll_name_w;

      //printf("FullDllName, length %x, max length %x buffer %lx\n",
      //    ldte->FullDllName.Length,
      //    ldte->FullDllName.MaximumLength,
      //    ldte->FullDllName.Buffer);
    
      if (ldte->FullDllName.Buffer == 0) {
        // Last entry has null buffer?
        break;
      }
      bool success;
      map_guest_pointer_status(details, dll_name_w, ldte->FullDllName.Buffer, &success);
      if (!success) {
        printf("Unable to read DLL name at %lx\n", ldte->FullDllName.Buffer);
      } else {
        wchar_to_char(dll_name, dll_name_w, MIN(512, ldte->FullDllName.Length));
        printf("Asid 0x%8x PID %4ld PPID %4ld has %16s loaded at 0x%lx\n",
            details->asid,
            (unsigned long)pbi->UniqueProcessId,
            (unsigned long)pbi->InheritedFromUniqueProcessId,
            dll_name, ldte->BaseAddress);
      }

      // Update Flink
      long unsigned int *next_flink;
      map_guest_pointer(details, next_flink, flink);
      flink = *next_flink;
    }
  }


  co_return;
}

#if 0
SyscCoroutine openproc(asid_details* details) {

  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // We will run the originally-requested syscall early here,
  // But first we'll extract the object_attributes struct from arg 3:

  object_attributes *oa_struct;
  unicode_string* path_struct;
  bool success;
  wchar_t* path;
  map_guest_pointer_status(details, oa_struct, regs.r8, &success);
  if (!success) {
    printf("Could not map r8 at %llx to an object_attributes struct\n", regs.r8);
    goto inject;
  }

  printf("Object_attributes (%ld bytes):\n\tLength = 0x%lx\n\tRootDirectory = 0x%lx\n\tObjectName = 0x%lx\n\tAttributes = 0x%lx\n\tSecurityDescriptor = 0x%lx\n\tSecurityQoS = %lx\n",
      sizeof(object_attributes),
      (unsigned long)oa_struct->Length,
      (unsigned long)oa_struct->RootDirectory,
      (unsigned long)oa_struct->ObjectName,
      (unsigned long)oa_struct->Attributes,
      (unsigned long)oa_struct->SecurityDescriptor,
      (unsigned long)oa_struct->SecurityQualityOfService
      );

  map_guest_pointer_status(details, path_struct, oa_struct->ObjectName, &success);
  if (!success) {
    printf("Could not map object_attribts->ObjectName at %lx\n", (unsigned long)oa_struct->ObjectName);
    goto inject;
  }
  map_guest_pointer_status(details, path, path_struct->Buffer, &success);
  if (!success) {
    printf("Could not map object buffer with length %u at %lx\n",
        path_struct->Length, (unsigned long)path_struct->Buffer);
    goto inject;
   }
  // Convert the windows wide char* to a linux c char* with our helper function
  char open_name[512];
  wchar_to_char(open_name, path, MIN(512, path_struct->Length));


inject:
  // Injected the requested syscall *now*, not when this co-opter finishes
  unsigned long int open_return = yield_syscall(details, NtOpenProcess,
                                                regs.r10, regs.rdx,
                                                regs.r8, regs.r9);
                                                

  // We already ran the requested syscall, don't run it again
  details->skip = true;
  details->orig_regs.rax = open_return;

  co_return;
}
#endif

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  switch (callno) {
    case NtOpenFile:
      return &mytest;
      break;
    //case NtClose:
    //  return &closefile;
    //  break;
  }
  return NULL;
}

