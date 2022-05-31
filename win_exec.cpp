#include <asm/unistd.h>
#include <cstring>
#include <stdio.h>
#include <set>
#include <tuple>
#include "hyde.h"
#include "windows.h"
#define MIN(a, b) (a < b ? a : b)


#if 0
// WIP - parse library
typedef struct  {
    uint64_t   VirtualAddress;
    uint64_t   Size;
} image_data_directory;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    uint64_t   Characteristics;
    uint64_t   TimeDateStamp;
    uint32_t   MajorVersion;
    uint32_t   MinorVersion;
    uint64_t   Name;
    uint64_t   Base;
    uint64_t   NumberOfFunctions;
    uint64_t   NumberOfNames;
    uint64_t   AddressOfFunctions;
    uint64_t   AddressOfNames;
    uint64_t   AddressOfNameOrdinals;
} image_export_directory;
#endif


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

  bool success;
  // PART 1: Get process name
  unsigned long fname_query_ret = yield_syscall(details, NtQueryInformationProcess,
                -1, // Handle: -1 => self
                27, // ProcessImageFileName
                buffer,
                0x1000,
                0); // output size pointer - not using

  char proc_name[512];
  sprintf(proc_name, "error");
  if (fname_query_ret == 0) {
    unicode_string *name_struct;
    map_guest_pointer(details, name_struct, buffer);
    
    wchar_t* name_w;
    map_guest_pointer_status(details, name_w, name_struct->Buffer, &success);
    if (success) {
      wchar_to_char(proc_name, name_w, MIN(512, name_struct->Length));
    }
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
    // PART 2: Read library mappings
    process_basic_information *pbi;
    map_guest_pointer(details, pbi, buffer);

    peb *p;
    map_guest_pointer(details, p, pbi->PebBaseAddress);
    //printf("PEB -> LDR is at %lx\n", (unsigned long)p->Ldr);

    peb_ldr_data *pld;
    map_guest_pointer(details, pld, p->Ldr);

    ldr_data_table_entry *ldte;

    long unsigned int flink = pld->InMemOrder.Flink;
    long unsigned int first = flink;
    bool is_first = true;

    printf("Asid 0x%8x PID %4ld PPID %4ld\n\tProcess name: '%s'\n",
        details->asid,
        (unsigned long)pbi->UniqueProcessId,
        (unsigned long)pbi->InheritedFromUniqueProcessId,
        proc_name);

    while (flink != first || is_first) {
      is_first = false;

      map_guest_pointer(details, ldte, flink-0x10);
      char dll_name[512];
      wchar_t* dll_name_w;

      if (ldte->FullDllName.Buffer == 0) {
        // Last entry has null buffer?
        break;
      }

#if 0
      printf("InLoadOrderLinks: Forward %lx, backward %lx\n", ldte->InLoadOrderLinks.Flink, ldte->InLoadOrderLinks.Blink);
      printf("InMemOrderLinks: Forward %lx, backward %lx\n", ldte->InMemoryOrderLinks.Flink, ldte->InMemoryOrderLinks.Blink);
      printf("InInitOrderLinks: Forward %lx, backward %lx\n", ldte->InInitializationOrderModuleList.Flink, ldte->InInitializationOrderModuleList.Blink);
      printf("BaseAddress %lx\n", ldte->BaseAddress);
      printf("FullDllName Length %x max %x Buf %lx\n", ldte->FullDllName.Length, ldte->FullDllName.MaximumLength, ldte->FullDllName.Buffer);
      hexdump((char*)ldte, sizeof(*ldte));
#endif

      // Update Flink before end to simplify control flow
      long unsigned int *next_flink;
      map_guest_pointer(details, next_flink, flink);
      flink = *next_flink;

      //FullDllName is the full path vs BaseDllName is just the filename

      unicode_string base_name = ldte->BaseDllName;
      map_guest_pointer_status(details, dll_name_w, base_name.Buffer, &success);
      if (!success) {
        printf("\tunable to read DLL name at %lx\n", ldte->BaseDllName.Buffer);
        continue;
      }

      wchar_to_char(dll_name, dll_name_w, MIN(512, ldte->BaseDllName.Length));
      uint64_t lib_base = ldte->BaseAddress;
      //uint64_t lib_base = ldte->BaseAddress + p->ImageBaseAddress;
      printf("\t%#16lx is base for %s\n", lib_base, dll_name);

      if (strcmp(dll_name, "C:\\Windows\\System32\\KERNEL32.DLL") == 0) { // Should be case ins?
        char* header;
        // XXX we can't read this - do we need to map with syscalls?
        map_guest_pointer(details, header, lib_base);
        printf("HEADER: %c %c %c %c\n", header[0], header[1], header[2], header[3]);
      }
    }
  }
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

