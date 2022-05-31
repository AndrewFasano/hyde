// Windows syscall number is in RAX, Argument order: R10, RDX, R8, R9, then stack
#define NtReadFile 0x06
#define NtOpenFile 0x33
#define NtClose 0x0f
#define NtCreateFile 0x55
#define NtCreateProcess 0xb9
#define NtOpenProcess 0x26 
#define NtCreateThread 0x4e
#define NtAllocateVirtualMemory 0x18
#define NtFreeVirtualMemory 0x1e
#define NtReadVirtualMemory 0x3f
#define NtQueryInformationProcess 0x19 

#include <stdint.h>

// We'll use these typedefs to parse guest memory at file opens
typedef struct {
  uint8_t Length;
  uint8_t MaximumLength;
  uint64_t Buffer;
} unicode_string;

typedef struct {
  uint32_t    Length;
  uint32_t    __pad;

  uint64_t    RootDirectory;
  uint64_t    ObjectName;
  uint32_t    Attributes;
  uint64_t    SecurityDescriptor;
  uint64_t    SecurityQualityOfService;
} object_attributes;

inline void wchar_to_char(char* out, wchar_t* in, size_t len) {
  // Helper to convert a windows wide char* to a normal linux char*
  for (int k=0; k < len-1; k++) {
    if (((char*)in)[k*2] == 0) {
      out[k] = 0;
      return;
    }
    out[k] = ((char*)in)[k*2];
  }
  out[len] = 0;
}

