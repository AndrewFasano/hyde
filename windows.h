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

typedef unsigned char byte;
typedef uint16_t word;
typedef uint32_t dword;

// We'll use these typedefs to parse guest memory at file opens
typedef struct {
  /* 0x00 */ uint8_t Length;
  /* 0x02 */ uint8_t MaximumLength;
  /* 0x08 */ uint64_t Buffer;
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

typedef struct _list_entry {
  /* 0x00 */ uint64_t Flink;
  /* 0x08 */ uint64_t Blink;
} list_entry;

typedef struct  {
    uint32_t Length;
    char Initialized[4];
    uint64_t SsHandle;
    list_entry InLoadOrder;
    list_entry InMemOrder;
    list_entry InInitOrder;
} peb_ldr_data;

typedef struct {
  byte                          Reserved1[2];
  byte                          BeingDebugged;
  byte                          Reserved2[1];
  uint64_t                      Reserved3;
  uint64_t                      ImageBaseAddress;
  peb_ldr_data*                 Ldr; // In XP this was at offset 0xC - same?
  // Ignoring remaining fields
} peb;


typedef struct {
    /* 0x00 */ list_entry InLoadOrderLinks;
    /* 0x10 */ list_entry InMemoryOrderLinks;
    /* 0x20 */ list_entry InInitializationOrderModuleList;
    /* 0x30 */ uint64_t DllBase; // XXX what about Entry point code/data base?
    /* 0x38 - really */ unicode_string FullDllName;
    /* 0x48 - really */ unicode_string BaseDllName; // XXX bad?

} ldr_data_table_entry;


typedef struct  {
    long int ExitStatus;
    peb* PebBaseAddress;
    unsigned long* AffinityMask;
    unsigned long BasePriority;
    unsigned long* UniqueProcessId;
    unsigned long* InheritedFromUniqueProcessId;
} process_basic_information;


// CURRENT WIP
typedef struct {
  uint32_t VirtualAddress;
  uint32_t Size;
} image_data_directory;

typedef struct {
  word                 Magic;
  byte                 MajorLinkerVersion;
  byte                 MinorLinkerVersion;
  dword                SizeOfCode;
  dword                SizeOfInitializedData;
  dword                SizeOfUninitializedData;
  dword                AddressOfEntryPoint;
  dword                BaseOfCode;
  uint64_t             ImageBase;
  dword                SectionAlignment;
  dword                FileAlignment;
  word                 MajorOperatingSystemVersion;
  word                 MinorOperatingSystemVersion;
  word                 MajorImageVersion;
  word                 MinorImageVersion;
  word                 MajorSubsystemVersion;
  word                 MinorSubsystemVersion;
  dword                Win32VersionValue;
  dword                SizeOfImage;
  dword                SizeOfHeaders;
  dword                CheckSum;
  word                 Subsystem;
  word                 DllCharacteristics;
  uint64_t             SizeOfStackReserve;
  uint64_t             SizeOfStackCommit;
  uint64_t             SizeOfHeapReserve;
  uint64_t             SizeOfHeapCommit;
  dword                LoaderFlags;
  dword                NumberOfRvaAndSizes;
  image_data_directory DataDirectory[16];
} image_optional_header64;

typedef struct {
  word  Machine;
  word  NumberOfSections;
  dword TimeDateStamp;
  dword PointerToSymbolTable;
  dword NumberOfSymbols;
  word  SizeOfOptionalHeader;
  word  Characteristics;
} image_file_header;

typedef struct {
  dword                   Signature;
  image_file_header       FileHeader;
  image_optional_header64 OptionalHeader;
} image_nt_headers64;

typedef struct {
  word                 Magic;
  byte                 MajorLinkerVersion;
  byte                 MinorLinkerVersion;
  dword                SizeOfCode;
  dword                SizeOfInitializedData;
  dword                SizeOfUninitializedData;
  dword                AddressOfEntryPoint;
  dword                BaseOfCode;
  //dword                BaseOfData;
  dword                ImageBase;
  dword                SectionAlignment;
  dword                FileAlignment;
  word                 MajorOperatingSystemVersion;
  word                 MinorOperatingSystemVersion;
  word                 MajorImageVersion;
  word                 MinorImageVersion;
  word                 MajorSubsystemVersion;
  word                 MinorSubsystemVersion;
  dword                Win32VersionValue;
  dword                SizeOfImage;
  dword                SizeOfHeaders;
  dword                CheckSum;
  word                 Subsystem;
  word                 DllCharacteristics;
  dword                SizeOfStackReserve;
  dword                SizeOfStackCommit;
  dword                SizeOfHeapReserve;
  dword                SizeOfHeapCommit;
  dword                LoaderFlags;
  dword                NumberOfRvaAndSizes;
  image_data_directory DataDirectory[16];
} image_optional_header32;

typedef struct {
  dword                   Signature;
  image_file_header       FileHeader;
  image_optional_header32 OptionalHeader;
} image_nt_headers32;


typedef struct {
    uint32_t   Characteristics;
    uint32_t   TimeDateStamp;
    uint16_t   MajorVersion;
    uint16_t   MinorVersion;
    uint32_t   Name;
    uint32_t   Base;
    uint32_t   NumberOfFunctions;
    uint32_t   NumberOfNames;
    uint32_t   AddressOfFunctions;
    uint32_t   AddressOfNames;
    uint32_t   AddressOfNameOrdinals;
} image_export_directory;



/////////////////

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

// For debugging
inline void hexdump(char* buf, size_t length) {
  printf("Hex dump of data at %p:\n", buf);
  printf("[off ]   0           4           8          12\n");
  for (size_t i=0;i < length; i++) {
    if (i > 0 && i % 16 == 0) {
      printf("\n");
    }
    if (i % 16 == 0) {
      printf("[%lx]\t", i);
    }
    printf("%2x ", buf[i]&0xff);
  }
  printf("\n-------------\n");
}
