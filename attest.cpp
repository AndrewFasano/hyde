#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <sys/types.h> // O_RDONLY
#include <sys/stat.h>  // O_RDONLY
#include <fcntl.h>     // O_RDONLY
#include <vector>
#include <map>
#include "hyde.h"
#include <openssl/sha.h>

// Store mapping of filenames to sha1sums
const std::vector<const char*> known_files = {"/usr/bin/sha1sum"};
const std::vector<const char*> known_hashes = {"0648f41a6c74f78414a330c299fda56b1c4b327d"};


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
  unsigned hash[5] = {0};
  char buf[41] = {0};
  char path[256];
  SHA_CTX context;
  bool fail = false;
  ga* guest_buf;
  ga* path_ptr;

  if (!SHA1_Init(&context)) {
    printf("[Attest] Unable to initialize sha context\n");
    rv = -1;
    goto out;
  }

  path_ptr = (ga*)get_arg(regs, 0); 
  if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
      printf("[Attest] Unable to read filename at %lx\n", (uint64_t)path_ptr);
      rv = -1;
      goto out;
  }
  guest_buf = (ga*)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  // Open target binary for reading
  guest_fd = (int)yield_syscall(details, __NR_open, path_ptr, O_RDONLY);
  if (guest_fd < 0) {
    printf("[Attest] Could not open %s", path);
    rv = -1;
  } else {

    // Read file until we hit EOF, update sha1sum as we go
    while (true) {
      char host_data[BUF_SZ];
      int bytes_read = yield_syscall(details, __NR_read, guest_fd, (__u64)guest_buf, BUF_SZ);
      if (bytes_read == 0) break;

      if (yield_from(ga_memcpy, details, host_data, guest_buf, bytes_read) == -1) {
        printf("[Attest] Unable to read file data at %lx\n", (uint64_t)guest_buf);
        fail = true;
        break;
      }

      if (!SHA1_Update(&context, host_data, bytes_read)) {
        printf("[Attest] Unable to update sha context\n");
        fail = true;
        break;
      }
    }

    if (!fail) {
      unsigned char hash[SHA_DIGEST_LENGTH];
      if (!SHA1_Final(hash, &context)) {
        printf("[Attest] Unable to finalize sha context\n");
        rv = -1;
      } else {
        // Turn our sha1sum into a digest string
        char digest[SHA_DIGEST_LENGTH*2];
        int i = 0;
        for (i=0; i < SHA_DIGEST_LENGTH; i++) {
            sprintf((char*)&(digest[i*2]), "%02x", hash[i]);
        }

        // CHeck if this is a known file, if so does the hash match?
        for (int i = 0; i < known_files.size(); i++) {
          if (strcmp(path, known_files[i]) == 0) {
            if (strcmp(digest, known_hashes[i]) != 0) {
              printf("[Attest] BLOCKING EXECUTION OF %s. Has sha1sum of %s which is not expected %s\n", path, digest, known_hashes[i]);
              goto hash_mismatch;
            } else {
              //printf("[Attest] Executing %s with good sha1sum of %s\n", path, digest);
            }
          }
        }
      }
    }

    yield_syscall(details, __NR_close, guest_fd);
  }

  yield_syscall(details, __NR_munmap, guest_buf, BUF_SZ);

out:
  co_yield *(details->orig_syscall);
  co_return rv;

hash_mismatch:
  details->orig_syscall->callno = __NR_getpid; // We can't leave the original since execve is noreturn
  details->orig_syscall->has_retval = true;
  details->orig_syscall->retval = -ENOEXEC;

  co_yield *(details->orig_syscall);
  co_return 1;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  // We inject syscalls starting at every execve
  if (callno == __NR_execve)
    return &start_coopter;
  return NULL;
}


