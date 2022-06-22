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
#include <filesystem>
#include <sstream>
#include <capstone/capstone.h>
#include "hyde.h"

// We effectively use two breakpoint to do a single-step after the first one is hit
// so we can restore it. SC1 is the real syscall, while Sc2 is just our helper

//#define DEBUG

#ifdef DEBUG
#define HEXDUMP(target_data, n) for (int i=0; i < n; i++) { printf("%02x ", target_data[i]&0xff); } puts("");
#else
#define HEXDUMP(target_data, n) {}
#endif

void dprintf(const char *fmt, ...) {
#ifdef DEBUG
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
#endif
}
static int foo = 0;

static char payload[] = "\x0f\x05";
#define SHIFT 2

static csh handle;

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


// Store mapping of function name -> type info
// We'll only support string and int for now
typedef struct {
  size_t n_args; // max 4
  short types[3];  // 0-> int, 1->string
} type_info_t;
std::unordered_map<std::string, type_info_t> type_info;

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
    if (cur_symtab->st_size == 0) continue;
    if (cur_symtab->st_value < 0x100) continue;


    char* sym_name;
    map_guest_pointer_status(details, sym_name, strtab + cur_symtab->st_name, &success);
    if (!success) {
      //printf("Couldn't read symname at %#lx + %#x -> %#lx - skip\n", strtab, cur_symtab->st_name, strtab+cur_symtab->st_name);
      continue;
    }

#if 0
    // Still hangs, even without hooking forks
    if (strcmp(sym_name, "__libc_fork") == 0 ||
        strcmp(sym_name, "__fork") == 0 ||
        strcmp(sym_name, "fork") == 0
      ) {
      printf("IGNORE fork\n");
      continue;
    }
#endif

#if 0
  foo++;
  if (foo % 4096 == 16) {
    printf("Skip %s\n", sym_name);
    continue;
  }
#endif


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
      // XXX: but we still need to safe the load address for this asid!

      if (!asid_map.contains(details->asid)) {
        asid_map.insert(std::pair(details->asid, new asid_lib_info_t));
      }
      if (!(*asid_map[details->asid]).contains(this_libname)) {
        (*asid_map[details->asid])[this_libname] = (__u64)guest_buf;
      }
      continue;
    }

    lib_hook_t* symbol_details = new lib_hook_t;

    symbol_details->name = std::string(sym_name);
    symbol_details->is_first_hooked = true;
    symbol_details->is_next_hooked = false;

    char *target_data;
    map_guest_pointer_status(details, target_data, sym_addr, &success);
    if (!success) {
      //printf("\tFailed to map symbol %s at %llx\n", sym_name, sym_addr); // Crazy addresses
      continue;
    }

    // Use capstone to disassemble the first instruction to get its size. Also check if it could change control flow - if so, we should ignore it/warn on use
    cs_insn *insn;
    size_t count;
    count = cs_disasm(handle, (const uint8_t*)target_data, 20, cur_symtab->st_value, 0, &insn);
    if (count <= 1) {
      printf("Impossibly low insn count: %ld\n", count);
      continue; // XXX bail
      symbol_details->next_offset = 0; // This indicates a failure
    }else {
      symbol_details->next_offset = insn[1].address - insn[0].address;
    }
    // XXX DEBUG
    //symbol_details->next_offset = 0; // This indicates a failure
    (*lib_details[this_libname]).insert(std::pair(cur_symtab->st_value, symbol_details));

    if (memcmp(target_data, payload, sizeof(payload)-1) == 0) {
      // Impossible, would already be in our map - unless guest has syscall here already?
      printf("We're in %x with lib %s sym %s but it's already BKPT'd\n", details->asid,
             this_libname.c_str(), symbol_details->name.c_str());

      assert(0);
    }

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
  assert(asid_map.contains(details->asid));
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  unsigned long int pc = regs.rcx-SHIFT;

  // Need to look up original data with libname -> lib_hook_t (TODO use a closure, pass from main)
  lib_hook_t* info = NULL;
  for (const auto &lib_info : *asid_map[details->asid]) {
    if (!lib_details.contains(lib_info.first)) continue;
    for (const auto &sym_info : *lib_details[lib_info.first]) {
      unsigned long abs_addr = sym_info.first + lib_info.second + sym_info.second->next_offset;
      // RCX holds old PC
      if (pc == abs_addr && sym_info.second->is_next_hooked) {
        info = sym_info.second;
        break;
      }
    }
  }

  if (info == NULL) {
    printf("Failed to find original data - abort\n");
    assert(0);
  }
  // Now we have info object: restore old data
  unsigned long int layer1pc = regs.rcx - info->next_offset - SHIFT; // -2 to go before syscall, then offset
  unsigned long int layer2pc = regs.rcx - SHIFT; // -2 to go before syscall instruction

  char* target_data;
  bool success;
  bool skip = true;

  // First restore original layer 2
  info->is_next_hooked = false;
  dprintf("\tRestoring original layer2 data at 0x%lx which we're about to run\n", layer2pc);
  map_guest_pointer_status(details, target_data, layer2pc, &success);
  if (success) {
    //dprintf("Unmodified data\n\t%016lx: ", layer1pc);
    //HEXDUMP(target_data, 100);

    memcpy(target_data, info->orig_next_data, sizeof(payload)-1);

    map_guest_pointer_status(details, target_data, layer1pc, &success);
    if (success) {
      //dprintf("Unmodified data\n\t%016lx: ", layer1pc);
      //HEXDUMP(target_data, 100);
    } else {
      puts("Debug read failed");
    }
  } else {
    dprintf("Failed to restore original layer2 data at %lx\n", layer2pc);
    assert(0); // XXX: fatal - guest will run a bad syscall
  }

  // Then, while we're still stopped, reinsert hook at layer 1! XXX this is causing problems
  if (!skip) {
  map_guest_pointer_status(details, target_data, layer1pc, &success);
  if (success) {
    dprintf("Added layer 1 breakpoint, layer 2 restored:\n\t%016lx: ", layer1pc);
    info->is_first_hooked = true;

    if (memcmp(target_data, info->orig_data, sizeof(payload)-1) != 0) {
      puts("\n****Mem changed at layer1pc data is now: ");

      for (int i=0; i < sizeof(payload)-1; i++) {
        dprintf("%02x vs %02x", target_data[i]&0xff, info->orig_data[i]);
      }
      puts("");
    }

    // Clobber the (previously-saved) data with our payload
    memcpy(target_data, payload, sizeof(payload)-1);
    //HEXDUMP(target_data, 100);

  } else {
    printf("Failed to reinsert breakpoint at %lx\n", layer1pc);
  }
  }

  // Jump back to original PC: read out of RCX
  details->custom_return = layer2pc;
  details->use_orig_regs = true; // after our next no-op syscall returns, restore RCX/R11

  // Necessary so we finish up the syscall and hit the sysret
  yield_syscall(details, __NR_getuid);
}

SyscCoroutine layer1_coopt(asid_details* details) {
  assert(asid_map.contains(details->asid));

  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  char* s;
  bool success;

  // Read arguments when hook triggers
  char arg0[256] = "";
  char arg1[256] = "";
  map_guest_pointer_status(details, s, regs.rdi, &success);
  if (success && strlen(s) > 1) snprintf(arg0, 256, " => '%s'", s);

  map_guest_pointer_status(details, s, regs.rsi, &success);
  if (success && strlen(s) > 1)  snprintf(arg1, 256, " => '%s'", s);
  //printf(">>> Hit hook at %llx: (%s, %s) original RAX is %llx\n", regs.rcx, arg0, arg1, regs.rax);
  printf("%#llx%s, %#llx%s)\n", regs.rdi, arg0, regs.rsi, arg1);
  // End of arg logging

  // Need to look up original data with libname -> lib_hook_t (TODO use a closure, pass from main)
  lib_hook_t* info = NULL;
  for (const auto &lib_info : *asid_map[details->asid]) {
    if (!lib_details.contains(lib_info.first)) continue;
    for (const auto &sym_info : *lib_details[lib_info.first]) {
      unsigned long abs_addr = sym_info.first + lib_info.second + SHIFT;
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

  // Restore original data to layer1
  char* target_data;
  map_guest_pointer(details, target_data, regs.rcx-SHIFT);
  //printf("Restoring data %02x%02x to %llx which has %02x%02x\n", info->orig_data[0], info->orig_data[1], regs.rcx-(sizeof(payload)-1), target_data[0], target_data[1]);
  memcpy(target_data, info->orig_data, sizeof(payload)-1);

#if 0
  printf("Restored layer1 is:\n %016llx", regs.rcx-SHIFT);
  for (int i=0; i < 10; i++) {
    printf("%02x ", target_data[i]&0xff);
  }
  puts("");
#endif

  details->use_orig_regs = true; // after our next no-op syscall returns, restore RCX/R11

  // Jump back to original PC: read out of RCX, decrement by the payload size +1
  details->custom_return = regs.rcx-SHIFT;

  if (info->next_offset == 0) {
    printf("ERROR: we hit a breakpoint for something we identified as invalid code\n");
    goto end;
  }

  // Insert breakpoint 2 at this insn's offset and update map info
  dprintf("\tInsert breakpoint2 at %llx (base+%x)\n", regs.rcx-SHIFT + info->next_offset, info->next_offset);

  // Layer 2 should go at PC+offset, so rcx-SHIFT+
  map_guest_pointer_status(details, target_data, regs.rcx-SHIFT+info->next_offset, &success);
  info->is_first_hooked = false;
  info->is_next_hooked = true;
  // Clobber the data
  memcpy(target_data, payload, sizeof(payload)-1);

  dprintf("\tRevert to restored layer1 at %lx with layer 2 at %llx\n", details->custom_return, regs.rcx-SHIFT+info->next_offset);

end:

  // We need this just to sysret from the 'syscall' we've already entered
  yield_syscall(details, __NR_getuid); // Junk syscall - need this at the end, otherwise some of our changes don't take? (not sure which?)
}

std::vector<std::pair<int, int>> pending_clones; // ASID -> child PID

SyscCoroutine start_coopter_execve(asid_details* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  char *pathname;
  map_guest_pointer(details, pathname, ARG0(regs));

  printf("Asid %x does execve of %s\n", details->asid, pathname);

  co_yield *(details->orig_syscall);
  __u64 result = details->retval;
  details->orig_regs.rax = result;
}

SyscCoroutine start_coopter_clone(asid_details* details) {
  co_yield *(details->orig_syscall);
  __u64 child_tgid = details->retval;

  // Only care if we're tracking this process - XXX: order is not guaranteed, child could start before parent returns :(
  if (asid_map.contains(details->asid)) {
    pending_clones.push_back(std::make_pair(details->asid, child_tgid));
    printf("Clone returns %llx\n", child_tgid);
  }
  details->orig_regs.rax = child_tgid;
}

SyscCoroutine ignore_coopter(asid_details* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  int callno = CALLNO(regs);
  __u64 this_pid = yield_syscall(details, __NR_getpid);
  unsigned long pc = regs.rcx-2; // sizeof(syscall insn)

  for (auto it = pending_clones.begin(); it != pending_clones.end(); it++) {
    if (asid_map.contains(it->first)) {
      if (it->second == this_pid) {
        printf("SPECIAL CHILD FOUND asid %x has child %x (with pid %lld)\n", it->first, details->asid, this_pid);
        // We're in the first syscall here
        // it's probably (definitely?) not a fake one we added, so we can let it run without issue

        asid_map.insert(std::pair(details->asid, asid_map[it->first]));

        pending_clones.erase(it);
        break;
      }
    }
  }

  co_yield *(details->orig_syscall);
  __u64 result = details->retval;

  details->orig_regs.rax = result;
}

void parse_config_file(std::string s) {
  std::ifstream input(s.c_str());
  for (std::string line; getline(input, line);) {
    if (line.length() == 0) continue;
    if (line.starts_with("import") || line.starts_with("#") || line.starts_with("typedef")) {
      continue;
    }

    char* line_c = (char*)line.c_str();
    char* name = strstr(line_c, " ");
    char* args = strstr(name, "(");
    args[0] = 0;
    args++;
    printf("debug: %s\n", args);
    strstr(args, ");")[0] = 0;
    printf("Function %s with args: %s\n", name, args);
  }
}

static void _con() __attribute__((constructor));
void _con() {
  // Constructor: initialize capstone and any ltrace function details
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) assert(0);
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  // Read host /usr/share/ltrace/*.conf for some signatures
#if 0
  std::string path = "/usr/local/share/ltrace/";
  for (const auto & entry : std::filesystem::directory_iterator(path)) {
    std::string s = entry.path();
    if (s.ends_with(".conf")) {
      parse_config_file(s);
    }
  }
#endif
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno, long unsigned int pc, unsigned int asid) {
  //printf("Syscall %d with bug. PC=%x. Asid %lx\n", callno, pc, asid);
  if (asid_map.contains(asid)) {
    // For each library we know about, we need to check all the hooked PCs (note we use PC, not callno)
    for (const auto &lib_info : *asid_map[asid]) {
      //printf("Library %s loaded at %llx in %x\n", lib_info.first.c_str(), lib_info.second, asid);

      if (!lib_details.contains(lib_info.first)) continue;

      for (const auto &sym_info : *lib_details[lib_info.first]) {
        unsigned long abs_addr = sym_info.first + lib_info.second + SHIFT;
        //printf("Check if %lx is a match for symbol %s\n", pc, sym_info.second->name.c_str());

        if (pc == abs_addr) {
          if ( sym_info.second->is_first_hooked) {
            //printf("\tHit L1: Library %s, symbol %s at offset %x, absolute %llx\n", lib_info.first.c_str(), sym_info.second->name.c_str(), sym_info.first, sym_info.first+lib_info.second);
            printf(">> hltrace %x %30s:%s(", asid, lib_info.first.c_str(), sym_info.second->name.c_str());
            return &layer1_coopt;
          } else {
            printf("Warning: possibly missed hook in asid %x at %lx\n", asid, pc);
          }
        } else if (pc == abs_addr+sym_info.second->next_offset && sym_info.second->is_next_hooked) {
          return &layer2_coopt;
        }
      }
    }
  }

  if (callno == __NR_open || callno == __NR_openat) {
    return &start_coopter_open;
  } else if (callno == __NR_mmap) {
    return &start_coopter_mmap;
  } else if (callno == __NR_clone) {
    return &start_coopter_clone;
  } else if (callno == __NR_execve) {
    return &start_coopter_execve;
  }

  return &ignore_coopter;


  return NULL;
}
