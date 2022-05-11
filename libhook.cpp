#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/mman.h> // for mmap flags
#include <vector>
#include <linux/elf.h>
#include "hyde.h"

#if 0
# /bin/whoami

OPEN LIB
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3

READ LIB INTO MEMORY
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\237\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\211\303\313\205\371\345PFwdq\376\320^\304A"..., 68, 896) = 68
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=2216304, ...}, AT_EMPTY_PATH) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784

Now BUF (first read buf* arg) should contain entire library - program knows the different sections of it


Load the various sections of the library into the current executables memory...

mmap(NULL, 2260560, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f6b52e10000
mmap(0x7f6b52e38000, 1658880, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f6b52e38000
mmap(0x7f6b52fcd000, 360448, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1bd000) = 0x7f6b52fcd000
mmap(0x7f6b53025000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x214000) = 0x7f6b53025000

The functions we want to hook are in the PROT_EXEC section
  But how do we map from name to offset?


#endif

static char* last_libname = NULL;

bool should_coopt(void*cpu, long unsigned int callno) {
  // We inject syscalls starting at every execve
  return callno == __NR_open || callno == __NR_openat || callno == __NR_mmap;
}

SyscCoroutine start_coopter(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  int callno = CALLNO(regs);

  if (callno == __NR_open || callno == __NR_openat) {
    int dir_arg_no = (callno == __NR_openat) ? 1 : 0;

    char *host_targname;
    map_guest_pointer(details, host_targname, get_arg(regs, dir_arg_no));

    if (callno == __NR_openat && host_targname[0] != '/') {
      //printf("TODO: handle relative paths for %s\n", host_targname);
      //Just ignore for now...
      co_return;
    }

    char* suffix1 = strstr(host_targname, ".so");
    char* suffix2 = strstr(host_targname, ".so.");
    // Either match '.so' at end of string, or match '.so.' anywhere
    if ((suffix1 == nullptr || strlen(suffix1) != 3) && suffix2 == nullptr) {
        co_return;
    }

    printf("[HYDE] Saw open of a library: %s\n", host_targname);
    if (last_libname != NULL)
      free(last_libname);
    last_libname = strdup(host_targname);

  } else {
    // It's an mmap - let's see if there's an FD
    int len = get_arg(regs, 1);
    int prot = get_arg(regs, 2);
    int fd = get_arg(regs, 4);
    int off = get_arg(regs, 5);

    if (fd == -1) {
      co_return;
    }

#if 0
    if (off == 0) {
      // Let's read the full file
      __u64* scratch_guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
          /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
          /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

      __u64 bytes_read -1;
      char* host_data;
      char *data = (char*)malloc(10000);
      int i=0;
      
      while (bytes_read != 0)  {
        bytes_read = yield_syscall(details, __NR_read, (__u64)scratch_guest_buf, 1024);
        char* host_data;
        map_guest_pointer(details, host_data, &guest_buf[i]);
        memcpy(&data[i], &host_data, bytes_read); // XXX: untested
        i += bytes_read;
      }

      // TODO: something with data
      free(data);
      yield_syscall(details, __NR_lseek, fd, 0, SEEK_SET); // Restore cursor to start
    }
#endif

    // Let's yield the original syscall, then skip it later
    // This way we can analyze the data before the guest continues
    __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
        get_arg(regs, 0), get_arg(regs, 1), get_arg(regs, 2),
        get_arg(regs, 3), get_arg(regs, 4), get_arg(regs, 5));

    char* host_data;
    map_guest_pointer(details, host_data, guest_buf);

    if (memcmp(host_data, "\x7F" "ELF", 4) == 0) {
      Elf64_Ehdr ehdr;
      memcpy(&ehdr, host_data, sizeof(ehdr)); // Hoping it doesn't change pages

      unsigned long phnum = ehdr.e_phnum;
      unsigned long phoff = ehdr.e_phoff;
      printf("Found dynamic section: loaded at %llx with %ld entries in program header table\n",
          (__u64)guest_buf, phnum);

      bool found_dynamic = false;
      Elf32_Phdr *dynamic_phdr; // XXX why is this elf32?
      for (int j=0; j < phnum; j++) {
        // Should be able to make this work as an &...[j] style array access
        //map_guest_pointer(details, dynamic_phdr, guest_buf + phoff + (j*sizeof(Elf64_Phdr)));
        int offset = j*ehdr.e_phentsize;
        map_guest_pointer(details, dynamic_phdr, guest_buf + phoff + offset); // XXX this is just ptr sz?
        //printf("Offset 0x%x p_type=0x%x, p_flags=0x%x, p_offset=0x%x vaddr=0x%x\n", offset,
        //      dynamic_phdr->p_type, dynamic_phdr->p_flags, dynamic_phdr->p_offset, dynamic_phdr->p_vaddr);

        // Found dynamic section!
        if (dynamic_phdr->p_type == PT_DYNAMIC){
          found_dynamic = true;
          break;

        // Reached end, no dynamic section - let's bail
        }else if (dynamic_phdr->p_type == PT_NULL){
          //printf("PT NULL\n");
          break;
        }else if (j == phnum -1) {
          //printf("PHNUM-1\n");
          break;
        }
      }

      if (found_dynamic) {
        Elf64_Dyn *tag;
        int numelements_dyn = dynamic_phdr->p_filesz / sizeof(Elf64_Dyn);

        unsigned long strtab = 0, symtab = 0, strtab_size = 0, dt_hash = 0, gnu_hash = 0;
        int j = 0;

        for (int j=0; j < numelements_dyn; j++) {
          map_guest_pointer(details, tag, guest_buf + dynamic_phdr->p_vaddr + (j*sizeof(tag)));
          //printf("Tag %d has type: %lld\n", j, tag->d_tag);
					if (tag->d_tag == DT_STRTAB){
						//printf("Found DT_STRTAB\n");
						strtab = tag->d_un.d_ptr;
					}else if (tag->d_tag == DT_SYMTAB){
						//printf("Found DT_SYMTAB\n");
						symtab = tag->d_un.d_ptr;
					}else if (tag->d_tag == DT_STRSZ ){
						//printf("Found DT_STRSZ\n");
						strtab_size = tag->d_un.d_ptr;
					}else if (tag->d_tag == DT_HASH){
						//printf("Found DT_HASH\n");
						dt_hash = tag->d_un.d_ptr;
					}else if (tag->d_tag == DT_HASH){ // DT_GNU_HASH?
						//printf("Found DT_GNU_HASH\n");
						gnu_hash = tag->d_un.d_ptr;
					}else if (tag->d_tag == DT_NULL){
						//printf("Found DT_NULL \n");
						j = numelements_dyn;
						//break;
					}
        }

		    if (strtab   < (__u64)guest_buf)   strtab   += (__u64)guest_buf;
		    if (symtab   < (__u64)guest_buf)   symtab   += (__u64)guest_buf;
		    if (dt_hash  < (__u64)guest_buf)   dt_hash  += (__u64)guest_buf;
		    if (gnu_hash < (__u64)guest_buf)   gnu_hash += (__u64)guest_buf;

        //printf("strtab: %llx symtab: %llx hash: %llx\n", (long long unsigned int) strtab,
        //(long long unsigned int)symtab, (long long unsigned int) dt_hash);

        struct dt_hash_section{
            uint32_t nchains;
            uint32_t nbuckets;
        } *dt;
        int numelements = 0;
        // Get_numelements_symtab
        if ((__u64)guest_buf != dt_hash) {
          bool success;
          map_guest_pointer_status(details, dt, dt_hash, &success);
          if (success) numelements = dt->nbuckets;
        }

        // Get_numelements_hash
        if ((__u64)guest_buf != gnu_hash) {
          printf("TODO: use GNU hash method\n");
        }
        Elf64_Sym* symtabs;
        char* strtabs;

        if (numelements > 0x1000) {
          printf("[HYDE] Warning: found too many elements - ignoring\n");
        }else if (numelements > 0) {
          for (int i=0; i < numelements; i++) {
            Elf64_Sym *onesymtab;
            map_guest_pointer(details, onesymtab, symtab+(sizeof(Elf64_Sym)*i));
            if (onesymtab->st_name < strtab_size && onesymtab->st_value != 0) {
              char* sym_name;
              map_guest_pointer(details, sym_name, strtab+onesymtab->st_name);
              __u64 sym_addr = (__u64)guest_buf + onesymtab->st_value;
              printf("%llx: %s\n", sym_addr, sym_name);
            }
          }
        }
      }
    }

    if (prot & PROT_EXEC) {
      char *data = (char*)malloc(len);

#if 0
      for (int i=0; i < len; i++) {
        // Read in page-sized chunks
        //printf("Map guest %llx to host\n", (__u64)&guest_buf[i]);
        map_guest_pointer(details, host_data, &guest_buf[i]);
        int valid_sz = std::min((__u64)(host_data) - ((((__u64)host_data >> 12) << 12) + 0x1000)-1, (__u64)len-i);
        //printf("Can read 0x%x bytes: [%llx, %llx]\n", valid_sz, (__u64)host_data, (__u64)host_data+valid_sz);
        memcpy(&data[i], &host_data, valid_sz);
        i+= valid_sz;
      }

      // Write the library to host disk
      std::string libpath(last_libname);
      std::size_t found = libpath.find_last_of("/");
      std::string libname = libpath.substr(found+1);
      std::ofstream myfile;
      myfile.open(libname, std::ios::out | std::ios::binary);
      myfile.write(data, len);
      myfile.close();

      free(data);
#endif

      printf("Library %s has executable section loaded at %llx\n", last_libname, (__u64)guest_buf);
    }

    // restore all regs, then set desired return value
    details->skip = true;
    memcpy(&details->orig_regs, &regs, sizeof(regs));
    set_RET(details->orig_regs, (__u64)guest_buf);
  }

#if 0
  __u64 *guest_envp = (__u64*)get_arg(regs, 2); // Can't dereference on host, just use for addrs

  // Create guest and host envp references and use to read arguments out
  __u64 *host_envp; // Can dereference on host
  __u64 *guest_envp = (__u64*)get_arg(regs, 2); // Can't dereference on host, just use for addrs
  for (int i=0; i < 255; i++) {
    map_guest_pointer(host_envp, details, &guest_envp[i]);
    if (*host_envp == 0) break;
    char* env_val;
    map_guest_pointer(env_val, details, *host_envp);

    if (strncmp(inject.c_str(), env_val, inject.find('=')+1) == 0) {
      // Existing env var duplicates the one we're injecting - don't save it
      continue;
    }
    guest_arg_ptrs.push_back(*host_envp);
    arg_list.push_back(std::string(env_val));
  }
  // Note these have to happen at the very end, otherwise subsequent injects will clobber
  //set_ARG2(details->orig_regs, (__u64)guest_buf);
  //details->modify_original_args = true;
#endif
}
