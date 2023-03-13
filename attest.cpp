#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <sys/types.h> // O_RDONLY
#include <sys/stat.h>  // O_RDONLY
#include <fcntl.h>     // O_RDONLY
#include <vector>
#include "hyde.h"
#include <boost/uuid/detail/sha1.hpp> // apt-get install libboost-all-dev

SyscCoroutine start_coopter(asid_details* details) {
  // Before we exec a binary, read it off disk and calculate its hash
  // OPTIONAL: read it into a MEMFD, hash that, then execfd it

  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  std::vector<__u64> guest_arg_ptrs;
  std::vector<std::string> arg_list;

  // Create guest and host envp references and use to read arguments out
  char *host_pathname; // Can dereference on host
  char *guest_pathname = (char*)get_arg(regs, 0); // Can't dereference on host, just use for addrs
  map_guest_pointer(details, host_pathname, guest_pathname);

  // Allocate scratch buffer
  __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  //printf("Guest buffer is at %p\n", guest_buf);


  // Open target binary for reading
  int guest_fd = yield_syscall(details, __NR_open, (long unsigned int)guest_pathname, O_RDONLY);
  //printf("Guest FD is %d\n", guest_fd);

  assert(guest_fd >= 0);

  __u64 bytes_read = -1;
  #define BUF_SZ 1024
  char *host_data = (char*)malloc(BUF_SZ);

  boost::uuids::detail::sha1 sha1;
  
  while (bytes_read != 0)  {
    bytes_read = yield_syscall(details, __NR_read, guest_fd, (__u64)guest_buf, BUF_SZ);
    map_guest_pointer(details, host_data, guest_buf);
    sha1.process_bytes(host_data, bytes_read);
  }

  unsigned hash[5] = {0};
  sha1.get_digest(hash);
  // Back to string
  char buf[41] = {0};
  for (int i = 0; i < 5; i++) {
    std::sprintf(buf + (i << 3), "%08x", hash[i]);
  }
  std::string myhash = std::string(buf);
  printf("[HyDE] About to execute %s with sha1sum of %s\n", host_pathname, myhash.c_str());

  // Finally, we run the original (execve) syscall, but with a different arg2 pointing to our buffer
  //details->orig_syscall->args[2] = (__u64)guest_buf;
  co_yield *(details->orig_syscall); // noreturn
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  // We inject syscalls starting at every execve
  if (callno == __NR_execve)
    return &start_coopter;
  return NULL;
}


