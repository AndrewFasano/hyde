#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/mman.h> // for mmap flags
#include <map>
#include <vector>
#include <linux/elf.h>
#include <capstone/capstone.h>
#include "hyde.h"

// We effectively use two breakpoint to do a single-step after the first one is hit
// so we can restore it. SC1 is the real syscall, while Sc2 is just our helper

// Orig 1   Setup Sc1         ->Orig 1              Setup Sc1
// Orig 2   Setup Sc1           Orig 2              Setup Sc1
// Orig 3   Syscall     *hit*   Orig 3              Syscall1
// Orig 4   Orig 4              Setup Sc2         ->Orig 4
// Orig 5   Orig 5              Setup Sc2           Orig 5
// Orig 6   Orig 6              Syscall     *hit*   Orig 6

//#define TARG_F "bindtextdomain"
//#define TARG_F "exit"
//#define TARG_F "strrchr"
//#define TARG_F "puts"

// TODO: need to make these dynamic, per-asid
// but they probably should work!

static char* last_libname = NULL; // XXX: per asid, store fd->name
//static unsigned long last_match_addr = 0;

static char payload[] = "\x0f\x05";
static char payload2[] = "\xeb\xfe";
//static char payload[] = "\x50\x48\xC7\xC0\xFF\xFF\x00\x00\x0F\x05"; // callno 0xFFFF

typedef struct {
  char* libname;
  char* symname;
  unsigned long address;
} lib_t;

// For each asid, we store library name -> load address
typedef std::map<std::string, __u64> asid_lib_info_t; // name -> offset
std::unordered_map<unsigned int, asid_lib_info_t*> asid_map; // asid -> info

// For each asid we store an approximate FD -> filename map
std::unordered_map<unsigned int, std::map<int, char*>*> fd_map; // asid->fd -> filename

typedef struct {
  std::string name;
  char orig_data[sizeof(payload)];
  char orig_next_data[sizeof(payload)];
  unsigned short next_offset; // Relative from base offset
  bool is_first_hooked;
  bool is_next_hooked;
} lib_hook_t;

// library offset -> lib_hook
typedef std::unordered_map<unsigned int, lib_hook_t*> offset_lib_hook_t;

// library path -> offset_lib_hook_t
std::unordered_map<std::string, offset_lib_hook_t*> lib_details;

// Lib name -> offset -> {orig_data, orig_next_data, next_offset, is_first_hooked, is_next_hooked}

// Need a map per aisd to store hooked addresses and clobbered data1/2

SyscCoroutine start_coopter_open(asid_details* details) {
  // Let's store the library name -> FD mapping per asid. For now just print it

  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  int callno = CALLNO(regs);
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

  if (last_libname != NULL)
    free(last_libname);
  last_libname = strdup(host_targname);

  co_yield *(details->orig_syscall);
  int fd = (int)details->retval;
  //printf("\nLibrary %s -> FD %d in %x\n", host_targname, fd, details->asid);

  if (!fd_map.contains(details->asid)) {
    fd_map.insert(std::pair(details->asid, new std::map<int, char*>));
  }
  fd_map.insert(std::pair(details->asid, new std::map<int, char*>));
  (*fd_map[details->asid])[fd] = strdup(host_targname);
  details->orig_regs.rax = (__u64)fd;
}

SyscCoroutine start_coopter_mmap(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  int callno = CALLNO(regs);
  // It's an mmap - let's see if there's an FD
  int len = get_arg(regs, 1);
  int prot = get_arg(regs, 2);
  int fd = get_arg(regs, 4);
  int off = get_arg(regs, 5);

  int numelements_dyn;
  Elf64_Dyn *tag;
  Elf64_Sym* symtabs;
  int numelements = 0;
  unsigned long phnum;
  unsigned long phoff;
  unsigned long strtab = 0, symtab = 0, strtab_size = 0, dt_hash = 0, gnu_hash = 0;
  bool found_dynamic = false;
  bool success;
  std::string this_libname = std::string("");

  // Let's yield the original syscall, then skip it later
  // This way we can analyze the data before the guest continues

  //__u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
  //    get_arg(regs, 0), get_arg(regs, 1), get_arg(regs, 2),
  //    get_arg(regs, 3), get_arg(regs, 4), get_arg(regs, 5));

  co_yield *(details->orig_syscall);
  __u64* guest_buf = (__u64*)details->retval;

  if (fd == -1) {
    // can't be something we care about - bail
    goto finish;
  }

  if ((long signed int)guest_buf < 0) {
    // Error
    goto finish;
  }

  if (!fd_map.contains(details->asid) || !(*fd_map[details->asid]).contains(fd)) {
    // XXX: we're duplicating kernel state here, this will fail is FD is dup'd or inherited
  }else{
    this_libname = std::string((*fd_map[details->asid])[fd]);
  }

  if (!prot & PROT_EXEC) {
    // non-executable object being loaded
    goto finish;
  }

  char* host_data;
  map_guest_pointer(details, host_data, guest_buf);

  if (memcmp(host_data, "\x7F" "ELF", 4) != 0) {
    goto finish;
  }

  Elf64_Ehdr ehdr;
  memcpy(&ehdr, host_data, sizeof(ehdr)); // Hoping it doesn't change pages
  phnum = ehdr.e_phnum;
  phoff = ehdr.e_phoff;
  //printf("Found dynamic section: loaded at %llx with %ld entries in program header table\n",
  //    (__u64)guest_buf, phnum);
  //
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

  if (!found_dynamic) {
    goto finish;
  }

  numelements_dyn = dynamic_phdr->p_filesz / sizeof(Elf64_Dyn);

  //printf("Check tags for FD %d in %x\n", fd, details->asid);
  for (int j=0; j < numelements_dyn; j++) {
    map_guest_pointer(details, tag, guest_buf + dynamic_phdr->p_vaddr + (j*sizeof(tag)));
    //printf("Tag %d has type: %lld\n", j, tag->d_tag);
    if (tag->d_tag == DT_STRTAB) {
      //printf("idx %d: DT_STRTAB at %llx\n", j, tag->d_un.d_ptr);
      //if (tag->d_un.d_ptr != 0) {
        strtab = tag->d_un.d_ptr;
      //}
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
      //j = numelements_dyn;
      break;
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
  if ((__u64)guest_buf != dt_hash) {
    map_guest_pointer_status(details, dt, dt_hash, &success);
    if (success) numelements = dt->nbuckets;
    else {
      //printf("No DT\n");
      goto finish;
    }
  }

  // Get_numelements_hash
  if ((__u64)guest_buf != gnu_hash) {
    printf("TODO: use GNU hash method\n");
  }

  if (numelements <= 0) {
    //printf("No elements\n");
    goto finish;
  }

  for (int i=0; i < numelements; i++) {
    Elf64_Sym *cur_symtab;

    map_guest_pointer(details, cur_symtab, &((Elf64_Sym*) symtab)[i]);
    if (cur_symtab->st_name < strtab_size && cur_symtab->st_value == 0) {
      continue;
    }

    // Sanity checks
    // Non-zero size?
    if (cur_symtab->st_size == 0) {
      continue;
    }


    if (cur_symtab->st_value < 0x100) {
      continue;
    }


    char* sym_name;
    map_guest_pointer_status(details, sym_name, strtab + cur_symtab->st_name, &success);
    if (!success) {
      //printf("Couldn't read symname at %#lx + %#x -> %#lx - skip\n", strtab, cur_symtab->st_name, strtab+cur_symtab->st_name);
      continue;
    }


    //if (strcmp(sym_name, TARG_F) != 0) {
    //  continue;
    //}

    if (ELF64_ST_TYPE(cur_symtab->st_info) != STT_FUNC) {
      //printf("Nofunc: %d\n",ELF64_ST_TYPE(cur_symtab->st_info) );
      continue;
    }

    if (ELF64_ST_BIND(cur_symtab->st_info) > 2) {
      // 0: local, 1: global, 2: weak. others ignore?
      //printf("bind wrong: %d\n",ELF64_ST_BIND(cur_symtab->st_info) );
      continue;
    }

    if (strlen(sym_name) > 32 || strlen(sym_name) < 2) {
      // a couple symbols end up with source code. Yuck. Do we actually need to filter these?
      continue;
    }

    // These ones cause problems - XXX, why!? Why can't we do more?
    if (strcmp(sym_name, "getdelim") == 0 || 
        strcmp(sym_name, "getopt_long") == 0
      ) {
      //printf("Maybe bad: %s in %s\n", sym_name, this_libname.c_str());
      continue;
    }
    if (sym_name[0] < 'a' || sym_name[0] >= 'h') { // broke
      continue;
    }

    __u64 sym_addr = (__u64)guest_buf + cur_symtab->st_value;

    if (this_libname.length() == 0) {
      printf("WARNING: unable to resolve library name at MMAP\n");
    }

    // We found a symbol! First check if we have this library name in lib_details
    if (!lib_details.contains(this_libname)) {
      lib_details.insert(std::pair(this_libname, new offset_lib_hook_t));
    }

    if ((*lib_details[this_libname]).contains(cur_symtab->st_value)) {
      // We already know about this offset in the library
      //printf("\tAlready know about %s\n", sym_name);
      continue;
    }

    //printf("Found new symbol %s: %s at offset %llx, absolute %llx in asid %x\n", this_libname.c_str(), sym_name, cur_symtab->st_value, sym_addr, details->asid);
    lib_hook_t* symbol_details = new lib_hook_t;
    (*lib_details[this_libname]).insert(std::pair(cur_symtab->st_value, symbol_details));

    symbol_details->name = std::string(sym_name);
    symbol_details->next_offset = 2; // XXX TODO calculate dynamically
    symbol_details->is_first_hooked = true;
    symbol_details->is_next_hooked = false;

    char *target_data;
    map_guest_pointer_status(details, target_data, sym_addr, &success);
    if (!success) {
      printf("\tFailed to map symbol %s\n", sym_name);
      continue;
    }
    assert(memcmp(target_data, payload, sizeof(payload)-1) != 0); // Impossible, would already be in our map - unless guest has syscall here already?

    //printf("Insert layer1 at offset %llx and store as first_hook\n", cur_symtab->st_value);
    memcpy(symbol_details->orig_data, target_data, sizeof(payload)-1);
    memcpy(symbol_details->orig_next_data, target_data+symbol_details->next_offset, sizeof(payload)-1);

    if (!asid_map.contains(details->asid)) {
      asid_map.insert(std::pair(details->asid, new asid_lib_info_t));
    }
    if (!(*asid_map[details->asid]).contains(this_libname)) {
      (*asid_map[details->asid])[this_libname] = (__u64)guest_buf;
    }

    memcpy(target_data, payload, sizeof(payload)-1);
  }

  // Ensure correct RV is set
finish:
  details->orig_regs.rax = (__u64)guest_buf;
}

SyscCoroutine layer2_coopt(asid_details* details) {
#if 0
  assert(asid_map.contains(details->asid));
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  unsigned long int layer1pc = regs.rcx-(sizeof(payload)+sizeof(payload)-2);
  printf(">>> Hit layer2 breakpoint at PC %llx, layer 1 is at %lx\n", regs.rcx, layer1pc);

  char* target_data;
  bool success;

  // Switch back to first hook
  asid_map[details->asid]->is_first_hooked = true;

  map_guest_pointer_status(details, target_data, layer1pc, &success);
  //char *layer1_clobbered = strndup(singlehook.clobbered_data, sizeof(payload)-1);
  char *layer1_clobbered = strndup(asid_map[details->asid]->orig_data, sizeof(payload)-1);

  if (success) {
    if (memcmp(target_data, payload, sizeof(payload)-1) != 0) {

      // Switch back to hook1
      printf("REInsert layer1 at %lx\n", layer1pc);
      //singlehook.hooked_pc = layer1pc+2;
      //singlehook.is_first_hook = true;
      asid_map[details->asid]->is_first_hooked = true;

      // Store data we clobber and then log it
      //memcpy(singlehook.clobbered_data, target_data, sizeof(payload)-1);
      //memcpy(asid_map[details->asid]->clobbered_data, target_data, sizeof(payload)-1);

      printf("\tClobbering %ld bytes of data: ", sizeof(payload)-1);
      for (int i=0; i < 10; i++) {
        printf("%02x ", target_data[i]&0xff);
      }
      printf("\n\t             with new data: ");
      for (int i=0; i < sizeof(payload)-1; i++) {
        printf("%02x ", payload[i]&0xff);
      }
      printf("\n");

      // Clobber the data
      memcpy(target_data, payload, sizeof(payload)-1);
    }
  }else{
    printf("Failed to map guest pointer for symbol: %lx\n", layer1pc);
  }

  printf("Restoring original layer2 data at 0x%llx and rerun\n", regs.rcx-(sizeof(payload)-1));

  char* host_ptr;
  map_guest_pointer(details, host_ptr, regs.rcx-(sizeof(payload)-1));
  memcpy(host_ptr, layer1_clobbered, sizeof(payload)-1);
  free(layer1_clobbered);
  // Have hyde run a no-op syscall, and on return jump back to the original (now-restored) instruction

  // Jump back to original PC: read out of RCX, decrement by the payload size +1
  details->custom_return = regs.rcx-(sizeof(payload)-1);
  printf("Revert2 to restored data at %lx\n", details->custom_return);

#endif
  // Do we need this?
  yield_syscall(details, __NR_getuid); // Junk syscall - need this at the end, otherwise some of our changes don't take? (not sure which?)
}

SyscCoroutine layer1_coopt(asid_details* details) {
  assert(asid_map.contains(details->asid));

  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  char* s;
  bool success;

  // Read arguments when hook triggers
  char arg0[64];
  char arg1[64];
  map_guest_pointer_status(details, s, regs.rdi, &success);
  if (success) sprintf(arg0, "%s", s);
  else         sprintf(arg0, "[Could not read %llx]", regs.rdi);

  map_guest_pointer_status(details, s, regs.rsi, &success);
  if (success)  sprintf(arg1, "%s", s);
  else          sprintf(arg1, "[Could not read %llx]", regs.rsi);
  //printf(">>> Hit hook at %llx: (%s, %s) original RAX is %llx\n", regs.rcx, arg0, arg1, regs.rax);
  printf("\t\t%#lx, %s, %#lx, %s\n", regs.rdi, arg0, regs.rsi, arg1);
  // End of arg logging

  //printf("Restoring original data at 0x%llx and rerun\n", regs.rcx-(sizeof(payload)-1));
  char* host_ptr;
  map_guest_pointer(details, host_ptr, regs.rcx-(sizeof(payload)-1));

  // Need to look up original data with libname -> lib_hook_t (TODO use a closure, pass from main)
  lib_hook_t* info = NULL;
  for (const auto &lib_info : *asid_map[details->asid]) {
    if (!lib_details.contains(lib_info.first)) continue;
    for (const auto &sym_info : *lib_details[lib_info.first]) {
      unsigned long abs_addr = sym_info.first + lib_info.second + sizeof(payload)-1;
      // RCX holds old PC
      if (details->orig_regs.rcx == abs_addr && sym_info.second->is_first_hooked) {
        info = sym_info.second;
        break;
      }
    }
  }

  if (info == NULL) {
    printf("Failed to find original data - abort\n");
    assert(0);
  }

  // Restore original data
  //memcpy(host_ptr, singlehook.clobbered_data, sizeof(payload)-1);
  //memcpy(host_ptr, asid_map[details->asid]->clobbered_data, sizeof(payload)-1);
  memcpy(host_ptr, info->orig_data, sizeof(payload)-1);
  // Have hyde run a no-op syscall, and on return jump back to the original (now-restored) instruction

  // Jump back to original PC: read out of RCX, decrement by the payload size +1
  details->custom_return = regs.rcx-(sizeof(payload)-1);

#if 0
  printf("Insert breakpoint2 at %llx\n", regs.rcx);
  char* target_data2;
  map_guest_pointer_status(details, target_data2, regs.rcx, &success);
  //singlehook.hooked_pc = regs.rcx+2;
  //singlehook.is_first_hook = false;
  //asid_map[details->asid]->hooked_pc = regs.rcx+2;
  asid_map[details->asid]->is_first_hooked = false;
  asid_map[details->asid]->is_next_hooked = true;
#endif

#if 0
  if (success) {
    // Store data we clobber and then log it
    //memcpy(singlehook.clobbered_data, target_data2, sizeof(payload)-1);
    memcpy(asid_map[details->asid]->clobbered_data, target_data2, sizeof(payload)-1);
    printf("\tClobbering %ld bytes of data: ", sizeof(payload)-1);
    for (int i=0; i < 10; i++) {
      printf("%02x ", target_data2[i]&0xff);
    }
    printf("\n\t             with new data: ");
    for (int i=0; i < sizeof(payload)-1; i++) {
      printf("%02x ", payload[i]&0xff);
    }
    printf("\n");
    // Clobber the data
    memcpy(target_data2, payload, sizeof(payload)-1);
  }else{
    printf("Failed to insert\n");
  }
#endif

  //printf("Revert to restored layer1 at %lx\n", details->custom_return);

  // Do we need this? - I think so?
  yield_syscall(details, __NR_getuid); // Junk syscall - need this at the end, otherwise some of our changes don't take? (not sure which?)

}

#define MIN(a, b) a>b ? b : a

create_coopt_t* should_coopt(void *cpu, long unsigned int callno, long unsigned int pc, unsigned int asid) {
  if (callno == __NR_open || callno == __NR_openat) {
    return &start_coopter_open;
  } else if (callno == __NR_mmap) {
    return &start_coopter_mmap;
  }

  if (asid_map.contains(asid)) {
    // For each library we know about, we need to check all the hooked PCs (note we use PC, not callno)
    for (const auto &lib_info : *asid_map[asid]) {
      //printf("Library %s loaded at %llx in %x\n", lib_info.first.c_str(), lib_info.second, asid);

      if (!lib_details.contains(lib_info.first)) continue;

      for (const auto &sym_info : *lib_details[lib_info.first]) {
        unsigned long abs_addr = sym_info.first + lib_info.second + sizeof(payload)-1;

        if (pc == abs_addr && sym_info.second->is_first_hooked) {
          //printf("\tHit L1: Library %s, symbol %s at offset %x, absolute %llx\n", lib_info.first.c_str(), sym_info.second->name.c_str(), sym_info.first, sym_info.first+lib_info.second);
          printf("\t[HyDE ltrace %x] %s:%s\n", asid, lib_info.first.c_str(), sym_info.second->name.c_str());
          return &layer1_coopt;
        } else if (pc == abs_addr+sym_info.second->next_offset && sym_info.second->is_next_hooked) {
          return &layer2_coopt;
        }
      }
    }
  }
  return NULL;
}
