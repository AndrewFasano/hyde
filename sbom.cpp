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

#define BUF_SZ 1024

SyscCoro hash_file(asid_details *details, char* path, unsigned char *outbuf) {
  // Hash a file at the specified pointer
  int rv = 0;
  std::string buffer;
  int guest_fd;

  std::vector<__u64> guest_arg_ptrs;
  std::vector<std::string> arg_list;
  unsigned hash[5] = {0};
  char buf[41] = {0};
  SHA_CTX context;
  bool fail = false;
  ga* guest_buf;
  ga* path_ptr;

  if (!SHA1_Init(&context)) {
    printf("[SBOM] Unable to initialize sha context\n");
    rv = -1;
    goto out;
  }

  guest_buf = (ga*)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  // Write path into guest memory
  if (yield_from(ga_memwrite, details, guest_buf, (void*)path, strlen(path)+1) == -1) {
    printf("[SBOM] Error: could not to write path into to guest memory\n");
    rv = -1;
    goto out;
  };

  // Open target binary for reading
  guest_fd = (int)yield_syscall(details, __NR_open, guest_buf, O_RDONLY);
  if (guest_fd < 0) {
    //printf("[SBOM] Could not open %s, got %d\n", path, guest_fd);
    rv = guest_fd;
  } else {

    // Read file until we hit EOF, update sha1sum as we go
    while (true) {
      char host_data[BUF_SZ];
      int bytes_read = yield_syscall(details, __NR_read, guest_fd, (__u64)guest_buf, BUF_SZ);
      if (bytes_read == 0) break;

      if (yield_from(ga_memcpy, details, host_data, guest_buf, bytes_read) == -1) {
        printf("[SBOM] Unable to read file data at %lx\n", (uint64_t)guest_buf);
        fail = true;
        break;
      }

      if (!SHA1_Update(&context, host_data, bytes_read)) {
        printf("[SBOM] Unable to update sha context\n");
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
        int i = 0;
        for (i=0; i < SHA_DIGEST_LENGTH; i++) {
            sprintf((char*)&(outbuf[i*2]), "%02x", hash[i]);
        }
      }
    }

    yield_syscall(details, __NR_close, guest_fd);
  }

  yield_syscall(details, __NR_munmap, guest_buf, BUF_SZ);

out:
  co_return rv;

hash_mismatch:
  details->orig_syscall->callno = __NR_getpid; // We can't leave the original since execve is noreturn
  details->orig_syscall->has_retval = true;
  details->orig_syscall->retval = -ENOEXEC;

  co_return 1;
}

SyscCoro fd_to_filename(asid_details* details, int fd, char* outbuf) {
  int rv = 0;
  int readlink_rv;
  // allocate a buffer for the filename
  ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap, 0, 128, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  // Write /proc/self/fd/<fd> into guest memory
  char fd_path[128];
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
  if (yield_from(ga_memwrite, details, guest_buf, (void*)fd_path, strlen(fd_path)) == -1) {
      printf("[SecretFile] Error: could not to write fd_path into to guest memory\n");
      rv = -1;
      goto out;
  }

  // Use readlink to read /proc/self/fd/<fd>
  readlink_rv = yield_syscall(details, __NR_readlink, guest_buf, guest_buf, 128);

  if (readlink_rv < 0) {
      printf("[SBOM] readlink fails\n");
      rv = -1;
      goto out;
  }

  // Read the result of readlink into a buffer
  if (yield_from(ga_memcpy, details, outbuf, guest_buf, readlink_rv+1) == -1) { // Get null term
      printf("[SBOM] Error: could not get readlink result\n");
      rv = -1;
      goto out;
  }

  out:
  // Free memory
  yield_syscall(details, __NR_munmap, guest_buf, 128);

  co_return rv;

}

SyscCoro pre_execve_at(asid_details* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  char *path_ptr = (ga*)get_arg(regs, 0); 
  char path[256];
  char dir_path[128];
  char full_path[256];
  int rv = 0;
  int readlink_rv;
  unsigned char hashbuf[SHA_DIGEST_LENGTH*2];
  int fd = get_arg(regs, 0); 
  int hash_result;

  // Read pathname
  if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
      printf("[SBOM] Unable to read filename at %lx\n", (uint64_t)path_ptr);
      rv = -1;
      goto out;
  }

  if (fd == AT_FDCWD) {
    // Ignore dirfd
    snprintf(full_path, sizeof(full_path), "%s", path);

  } else if (yield_from(fd_to_filename, details, fd, (char*)dir_path) == -1) {
    printf("[SBOM] Unable to get filename for fd %d\n", fd);
    rv = -1;
    goto out;
  } else {
    // Use dir_path we just got based on the FD
    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, path);
  }

  hash_result = yield_from(hash_file, details, full_path, (unsigned char*)hashbuf);

  if (hash_result == -20 || hash_result == -2) { // No such file
    rv = 0;
  } else if (hash_result < 0) {
    printf("[SBOM] Unable to hash file %s: %d\n", path, hash_result);
    rv = -2;
  } else {
    printf("Hash of %s: %s\n", path, hashbuf);
  }

out:
  // yield original syscall
  co_yield *(details->orig_syscall);
  co_return rv;
}

SyscCoro pre_execve(asid_details* details) {
  struct kvm_regs regs;
  char path[256];
  int rv=0;
  get_regs_or_die(details, &regs);
  ga* path_ptr = (ga*)get_arg(regs, 0); 

  if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
      printf("[SBOM] Unable to read filename at %lx\n", (uint64_t)path_ptr);
      rv = -1;
  } else {
    //printf("Exec filename; %s\n", path);
    unsigned char hashbuf[SHA_DIGEST_LENGTH*2] = {0};
    if (yield_from(hash_file, details, path, (unsigned char*)hashbuf) == -1) {
      printf("[SBOM] Unable to hash file %s\n", path);
      rv = -2;
    } else {
      printf("[SBOM] Hash of %s: %s\n", path, hashbuf);
    }
  }

  // yield original syscall
  co_yield *(details->orig_syscall);
  co_return rv;
}

SyscCoro pre_mmap(asid_details* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  int rv=0;
  char lib_path[128];

  // mmap arg 5 may be an FD - ignored if arg 4 is MAP_ANONYMOUS (get_arg 0-indexes though)
  int flags  = (int)get_arg(regs, 3);
  int fd = (int)get_arg(regs, 4); 

  if (flags & MAP_ANONYMOUS) {
    // We don't care about this! Since it's not a file mapping
    goto out;
  } else if (yield_from(fd_to_filename, details, fd, (char*)lib_path) == -1) {
    printf("[SBOM] Unable to get filename for fd %d\n", fd);
    rv = -1;
    goto out;
  } else {
    // Successfully got filename, let's use it!
    unsigned char hashbuf[SHA_DIGEST_LENGTH*2];
    if (yield_from(hash_file, details, lib_path, (unsigned char*)hashbuf) == -1) {
      printf("[SBOM] Unable to hash file %s from fd %d\n", lib_path, fd);
      rv = -2;
    } else {
      printf("[SBOM] map %s with hash of %s\n", lib_path, hashbuf);
    }
  }

out:
  // yield original syscall
  co_yield *(details->orig_syscall);
  co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

  // We care about execve, execve_at and mmap
  if (callno == __NR_execve)
    return &pre_execve;
  else if (callno == __NR_execveat)
    return &pre_execve_at;
  else if (callno == __NR_mmap)
    return &pre_mmap;

  return NULL;
}


