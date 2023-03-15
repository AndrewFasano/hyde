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

#define BUF_SZ 1024
SyscCoro start_coopter(asid_details* details) {
  // Before we exec a binary, read it off disk and calculate its hash
  // OPTIONAL: read it into a MEMFD, hash that, then execfd it

  // Get guest registers so we can examine the first argument
  int rv = 0;
  std::string buffer;
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  int guest_fd;

  std::vector<__u64> guest_arg_ptrs;
  std::vector<std::string> arg_list;
  boost::uuids::detail::sha1 sha1;
  unsigned hash[5] = {0};
  char buf[41] = {0};
  char path[256];

  ga *path_ptr = (ga*)get_arg(regs, 0); 
  if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
      printf("[Attest] Unable to read filename at %lx\n", (uint64_t)path_ptr);
      rv = -1;
  } else {
    ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap,
        /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
        /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

    // Open target binary for reading
    guest_fd = (int)yield_syscall(details, __NR_open, path_ptr, O_RDONLY);
    if (guest_fd < 0) {
      printf("[Attest] Could not open %s", path);
      rv = -1;
    } else {

      // Read file until we hit EOF, update sha1sum as we go
      bool fail = false;
      while (true) {
        char host_data[BUF_SZ];
        int bytes_read = yield_syscall(details, __NR_read, guest_fd, (__u64)guest_buf, BUF_SZ);
        if (bytes_read == 0) break;

        if (yield_from(ga_memcpy, details, host_data, guest_buf, sizeof(struct stat)) == -1) {
          printf("[Attest] Unable to read file data at %lx\n", (uint64_t)guest_buf);
          fail = true;
          break;
        }

        printf("Update sha1 sum with %ld bytes\n", bytes_read);
        sha1.process_bytes(host_data, bytes_read);
      }

      if (!fail) {
        sha1.get_digest(hash);
        // Back to string
        for (int i = 0; i < 5; i++) {
          std::sprintf(buf + (i << 3), "%08x", hash[i]);
        }

        std::string myhash = std::string(buf);
        printf("[HyDE] About to execute %s with sha1sum of %s\n", path, myhash.c_str());
      }

      yield_syscall(details, __NR_close, guest_fd);
    }

    yield_syscall(details, __NR_munmap, guest_buf, BUF_SZ);
  }

  co_yield *(details->orig_syscall);
  co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  // We inject syscalls starting at every execve
  if (callno == __NR_execve)
    return &start_coopter;
  return NULL;
}


