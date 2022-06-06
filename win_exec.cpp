#include <asm/unistd.h>
#include <cstring>
#include <stdio.h>
#include <set>
#include <tuple>
#include "hyde.h"
#include "windows.h"
#define MIN(a, b) (a < b ? a : b)
#define SCRATCH_SZ 0x1000

static int did_it = 0;

SyscCoroutine mytest(asid_details* details) {
  // Testing on file open - get PEB, print modules, then run orig syscall
  if (did_it > 3) {
    co_return;
  }

  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  __u64 target_addr = 0;
  bool is_first = true;
  long unsigned int flink;
  long unsigned int first;

  // XXX We'll pass RSP-based pointers - need to manually adjust stack
  long unsigned int *stack;
  long unsigned int old_stack[2];
  map_guest_pointer(details, stack, regs.rsp);

  // Save original values
  memcpy(&old_stack, stack, sizeof(long unsigned int)*2);

  // Clobber
  stack[0] = 0; // Args[1] points here for in/out DllBase. Input is 0, output is buffer
  stack[1] = SCRATCH_SZ; // Args[3] points here for RegionSize

  // Run the syscall - which will modify these stack-based values
  unsigned long allocate_ret = yield_syscall(details, NtAllocateVirtualMemory,
                -1,         // Handle: -1 => self
                regs.rsp,   // void** in out DllBase->ActualAddress
                0,          //
                regs.rsp+8, // int* in out requested size -> allocated size
                0x1000,     // Allocation type = MEM_COMMIT
                0x04);      // PAGE_READWRITE
  unsigned long int buffer = stack[0];
  // Restore clobbered things from the stack
  memcpy(stack, &old_stack, sizeof(long unsigned int)*2);

  if (allocate_ret != 0) {
    printf("ERROR in %x Allocate returned %lx with buffer %lx. BAIL\n", details->asid, allocate_ret, buffer);
    co_return; // No cleanup necessary
  }

  bool success;
  // PART 1: Get process name
  unsigned long fname_query_ret = yield_syscall(details, NtQueryInformationProcess,
                -1, // Handle: -1 => self
                27, // ProcessImageFileName
                buffer,
                0x500,
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

  if (query_ret != 0) {
    goto cleanup;
  } 

  // PART 2: Read library mappings
  process_basic_information *pbi;
  map_guest_pointer(details, pbi, buffer);

  peb *p;
  map_guest_pointer(details, p, pbi->PebBaseAddress);
  //printf("PEB -> LDR is at %lx\n", (unsigned long)p->Ldr);

  peb_ldr_data *pld;
  map_guest_pointer_status(details, pld, p->Ldr, &success);
  if (!success) {
    goto cleanup;
  }

  ldr_data_table_entry *ldte;

  flink = pld->InMemOrder.Flink;
  first = flink;

  if (strstr(proc_name, "Calculator.exe") == NULL) {
  //if (strstr(proc_name, "whoami.exe") == NULL) {
    goto cleanup;
  }

  //printf("Asid 0x%8x PID %4ld PPID %4ld\n\tProcess name: '%s'\n",
  //    details->asid,
  //    (unsigned long)pbi->UniqueProcessId,
  //    (unsigned long)pbi->InheritedFromUniqueProcessId,
  //    proc_name);

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
    printf("DllBase %lx\n", ldte->DllBase);
    printf("FullDllName Length %x max %x Buf %lx\n", ldte->FullDllName.Length, ldte->FullDllName.MaximumLength, ldte->FullDllName.Buffer);
    hexdump((char*)ldte, sizeof(*ldte));
#endif

    // Update next flink before end to simplify control flow
    long unsigned int *next_flink;
    map_guest_pointer(details, next_flink, flink);
    flink = *next_flink;

    //FullDllName is the full path vs BaseDllName is just the filename
    unicode_string base_name = ldte->BaseDllName;
    map_guest_pointer_status(details, dll_name_w, base_name.Buffer, &success);
    if (!success) {
      //printf("\tunable to read DLL name at %#lx\n", ldte->BaseDllName.Buffer);
      continue;
    }

    wchar_to_char(dll_name, dll_name_w, MIN(512, ldte->BaseDllName.Length));
    //printf("\t%#16lx is base for %s\n", ldte->DllBase, dll_name);

    // TODO make comparison case insensitive
    //if (strcmp(dll_name, "C:\\Windows\\System32\\KERNEL32.DLL") != 0)
    if (strcmp(dll_name, "C:\\Windows\\System32\\user32.dll") != 0)
    {
      continue;
    }
    // We're on the DLL we want - let's find the symbol we're looking for

    //printf("\tDLLbase: %#16lx for %s\n", ldte->DllBase, dll_name);

    // PARSE STAGE: Map _IMAGE_DOS_HEADER from the DllBase
    char* mz;
    map_guest_pointer(details, mz, ldte->DllBase);
    assert((mz[0] = 'M') && (mz[1] = 'Z')); // Found the PE file in memory!

    // PARSE STAGE: Map _IMAGE_NT_HEADERS from DllBase + DOS Header's e_lfanew
    uint32_t *e_lfanew;
    map_guest_pointer(details, e_lfanew, ldte->DllBase+0x3c); // Points to where the NT header is, 4 bytes

    // Get the first word out of OptionalHeader *before* we cast the full struct - we need this Magic to decide on 32/64 bit structs
    uint16_t* magic;
    map_guest_pointer(details, magic, ldte->DllBase + (*e_lfanew) + sizeof(image_file_header) + sizeof(uint32_t));
    //printf("Magic: 0x%x\n", *magic);

    assert(*magic == 0x20b); // For now we just support PE32+ executables, which use image_nt_header64

    image_nt_headers64 *header;
    //image_nt_headers32 *header;
    map_guest_pointer(details, header, ldte->DllBase + (*e_lfanew));

#if 0
    printf("NT HEADERS:\n\tMagic 0x%x\n\tMachine is 0x%x\n\tSubsystem %x\n\tTimeStamp %x\n",
        header->OptionalHeader.Magic,
        header->FileHeader.Machine,
        header->OptionalHeader.Subsystem,
        header->FileHeader.TimeDateStamp);

    printf("\tSizeOfHeapCommit 0x%lx\nLoader Flags 0x%x\n\tNumber RVA & Sizes 0x%x\n",
        header->OptionalHeader.SizeOfHeapCommit, 
        header->OptionalHeader.LoaderFlags, 
        header->OptionalHeader.NumberOfRvaAndSizes);

    for (int i=0; i < 16; i++) {
      image_data_directory img_dd = header->OptionalHeader.DataDirectory[i];
      printf("\tDataDir[%d] VA is %#8x Offset with +DLB is %#8lx sz is %x\n", i, img_dd.VirtualAddress, img_dd.VirtualAddress + ldte->DllBase, img_dd.Size);
    }
#endif

    // PARSE STAGE: Parse exports DataDirectory to get function info
    image_data_directory img_dd0 = header->OptionalHeader.DataDirectory[0];
    image_export_directory *ied;
    map_guest_pointer(details, ied, (uint64_t)img_dd0.VirtualAddress + ldte->DllBase);

#if 0
    printf("We have %x names starting at %x and %x functions starting at %x\n",
        ied->NumberOfNames,
        ied->AddressOfNames,
        ied->NumberOfFunctions,
        ied->AddressOfFunctions);
#endif

    // PARSE STAGE: Use exports to get function name -> Address mappings
    // Resource: https://resources.infosecinstitute.com/topic/the-export-directory/
    uint32_t *name_arr;
    map_guest_pointer_status(details, name_arr, ied->AddressOfNames + ldte->DllBase, &success);
    if (!success) {
      printf("In target library, unable to read names at %lx  - BAIL\n", ied->AddressOfNames + ldte->DllBase);
      goto cleanup;
    }

    uint32_t *addr_arr;
    map_guest_pointer(details, addr_arr, ied->AddressOfFunctions + ldte->DllBase);

    uint16_t *ordn_arr;
    map_guest_pointer(details, ordn_arr, ied->AddressOfNameOrdinals + ldte->DllBase);

    //char** f_names;
    //map_guest_pointer_status(details, f_names, ldte->DllBase + *name_arr, &success);

    if (success) {
      for (int i=0; i < ied->NumberOfNames; i++) {
        char* f_name;
        map_guest_pointer_status(details, f_name, ldte->DllBase + name_arr[i], &success);

        // Get i-th name -> Address mapping
        if (!success || strcmp(f_name, "MessageBoxA") != 0) {
          continue;
        }
        // Look up address using ordinal
        uint32_t f_addr = addr_arr[ordn_arr[i]];

        // Found it!
        printf("Ordinal %#03x: %s at 0x%x => %lx\n", ordn_arr[i], f_name, f_addr, f_addr + ldte->DllBase);
        target_addr = f_addr + ldte->DllBase;

        if (target_addr > header->OptionalHeader.DataDirectory[0].VirtualAddress && \
            target_addr < header->OptionalHeader.DataDirectory[0].VirtualAddress + header->OptionalHeader.DataDirectory[0].Size) {
          // Check if forwarded https://github.com/arbiter34/GetProcAddress/blob/master/GetProcAddress/GetProcAddress.cpp#L99
          printf("TODO: Handle forwarded string\n");
        }

        char* targ_buf;
        map_guest_pointer_status(details, targ_buf, target_addr, &success);
        if (success) {
          hexdump(targ_buf, 0x100);
        } else {
          printf("Error reading target function in memory  at %llx\n", target_addr);
        }

        break;
      }
    }
    break; // We found the DLL we were looking for - stop enumerating
  }

  // Done enumerating dlls!
  if (target_addr == 0) {
    //printf("Failed to find target\n");
    goto cleanup;
  }

  if (did_it++ < 2) {
    goto cleanup;
  }

  printf("Asid 0x%8x PID %4ld PPID %4ld\n\tProcess name: '%s'\n",
      details->asid,
      (unsigned long)pbi->UniqueProcessId,
      (unsigned long)pbi->InheritedFromUniqueProcessId,
      proc_name);
  printf("\tCall targ_func at %#llx\n", target_addr);

  /*
   * int MessageBoxA(
   * [in, optional] HWND   hWnd,
   * [in, optional] LPCSTR lpText,
   * [in, optional] LPCSTR lpCaption,
   * [in]           UINT   uType);
   */

  char* output;
  map_guest_pointer(details, output, buffer);
  sprintf(output, "Hello world");

  // Save original values
  memcpy(&old_stack, stack, sizeof(long unsigned int)*2);
  // Clobber
  stack[0] = 0; // Args[1] points here for in/out DllBase. Input is 0, output is buffer
  stack[1] = SCRATCH_SZ; // Args[3] points here for RegionSize
  // Allocate a new buffer, with shellcode
  {
  unsigned long allocate_ret = yield_syscall(details, NtAllocateVirtualMemory,
                -1,         // Handle: -1 => self
                regs.rsp,   // void** in out DllBase->ActualAddress
                0,          //
                regs.rsp+8, // int* in out requested size -> allocated size
                0x1000,     // Allocation type = MEM_COMMIT
                0x10);      // PAGE_EXECUTE
  unsigned long int shellcode_ptr = stack[0];
  // Restore clobbered things from the stack
  memcpy(stack, &old_stack, sizeof(long unsigned int)*2);

  printf("Shellcode buffer at %lx\n", shellcode_ptr);

  char* raw_shellcode;
  map_guest_pointer(details, raw_shellcode, shellcode_ptr);

  raw_shellcode[0] = '\xeb';
  raw_shellcode[1] = '\xfe';
  raw_shellcode[2] = '\xcc';

  // Push old details to the stack ????
  get_regs_or_die(details, &regs);
  // Stack: ret addr

  //map_guest_pointer(details, stack, regs.rsp);
  //unsigned long int old_pc = regs.rcx-4; // The original return is RCX-2, -4 would re-run the syscall insn
  unsigned long int old_pc = shellcode_ptr;

  printf("Return to PC %lx\n", old_pc);
#if 0
  stack[1] = old_pc;
  details->orig_regs.rsp -= 0x8;

  // Clobber orig regs to set our args
  details->orig_regs.rcx = 0;
  details->orig_regs.rdx = buffer; //buffer;
  details->orig_regs.r8  = buffer; //buffer;
  details->orig_regs.r9  = 0;
  details->orig_regs.rip = target_addr;
#else
  details->orig_regs.rip = shellcode_ptr;
#endif

  //details->modify_on_ret = 1; // XXX TODO
  printf("TODO\n");
  did_it = true;
  co_return;
  }

cleanup:

  // Clean up
  map_guest_pointer(details, stack, regs.rsp);
  memcpy(&old_stack, stack, sizeof(long unsigned int)*2);
  // Clobber
  stack[0] = buffer;
  stack[1] = SCRATCH_SZ;
  unsigned long free_ret = yield_syscall(details, NtFreeVirtualMemory,
                -1,         // Handle: -1 => self
                regs.rsp,   // void** in out BaseAddress
                regs.rsp+8, // *Region size
                0x8000);    // MEM_RELEASE - Will decommit then release
  if (free_ret != 0) {
    printf("WARN: Free returns %lx\n", free_ret);
  }

  memcpy(stack, &old_stack, sizeof(long unsigned int)*2);
}

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

