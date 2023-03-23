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
#include <openssl/sha.h>

#include "hyde.h"
#include "file_helpers.h"

#define BUF_SZ 1024 // Size to use for read chunks
#define PATH_LENGTH 256 // Max size of paths
#define INTERNAL_ERROR -99999

template <std::size_t N>
SyscCoroHelper hash_file(asid_details *details, char(&path)[N], unsigned char (&outbuf)[SHA_DIGEST_LENGTH*2+1]) {
  // Hash a file at the specified pointer. write ascii digest into outbuf
  int rv = 0;
  std::string buffer;
  int guest_fd;

  std::vector<__u64> guest_arg_ptrs;
  std::vector<std::string> arg_list;
  unsigned hash[5] = {0};
  char buf[41] = {0};
  SHA_CTX context;
  bool fail = false;

  if (!SHA1_Init(&context)) {
    printf("[SBOM] Unable to initialize sha context\n");
    co_return INTERNAL_ERROR; // Internal error, not a guest syscall error
  }

  char path_buf[N];
  memcpy(path_buf, path, strlen(path)+1);

  // Open target binary for reading
  guest_fd = yield_syscall(details, open, path_buf, O_RDONLY);
  if (guest_fd < 0) {
    co_return guest_fd; // Failed to open file - no need to cleanup, have negative value here
  }

  // Read file until we hit EOF, update sha1sum as we go
  while (true) {
    char host_data[BUF_SZ];
    int bytes_read = yield_syscall(details, read, guest_fd, host_data, BUF_SZ);
    if (bytes_read == 0) break;

    if (!SHA1_Update(&context, host_data, bytes_read)) {
      printf("[SBOM] Unable to update sha context\n");
      fail = true;
      rv = INTERNAL_ERROR;
      break;
    }
  }

  if (!fail) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    if (!SHA1_Final(hash, &context)) {
      printf("[Attest] Unable to finalize sha context\n");
      rv = -1; // Still need to close
    } else {
      // Turn our sha1sum into a digest string
      int i = 0;
      for (i=0; i < SHA_DIGEST_LENGTH; i++) {
          sprintf((char*)&(outbuf[i*2]), "%02x", hash[i]);
      }
    }
  }

  yield_syscall(details, close, guest_fd);
  co_return rv;
}

SyscCoro pre_execve_at(asid_details* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  char full_path[256];
  int readlink_rv;
  int fd = get_arg(regs, RegIndex::ARG0); 
  int hash_result;

  ExitStatus rv = ExitStatus::SUCCESS;

  // Read pathname from arg 1
  char path[256];
  if (yield_from(ga_memcpy, details, path, get_arg(regs, RegIndex::ARG1), sizeof(path)) == -1) {
      printf("[SBOM] Unable to read filename\n");
      rv = ExitStatus::SINGLE_FAILURE;
      goto out;
  }

  if (fd == AT_FDCWD) {
    // Ignore dirfd when fd is AT_FDCWD
    // Set full_path to just be pathname
    snprintf(full_path, sizeof(full_path), "%s", path);

  } else {
    char dir_path[PATH_LENGTH];
    int fd_status = yield_from(fd_to_filename, details, fd, dir_path);
    if (fd_status < 0) {
      printf("[SBOM] Unable to get filename for fd %d\n", rv);
      rv = ExitStatus::SINGLE_FAILURE;
      goto out;
    }
    // Set full_path to be dir_path / path
    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, path);
  }

  unsigned char hashbuf[SHA_DIGEST_LENGTH*2+1];
  hash_result = yield_from(hash_file, details, full_path, hashbuf);

  if (hash_result == INTERNAL_ERROR) {
    // We failed
    printf("[SBOM] Unable to hash file %s: %d\n", full_path, hash_result);
    rv = ExitStatus::SINGLE_FAILURE; // Not our failure
  } else if (hash_result < 0) {
    // Not our failure, leave RV as success
  } else {
    // Actual success, we calculated the hash
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
  ExitStatus rv = ExitStatus::SUCCESS;
  get_regs_or_die(details, &regs);
  uint64_t path_ptr = get_arg(regs, RegIndex::ARG0); 

  if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
      printf("[SBOM] Unable to read filename at %lx\n", path_ptr);
      rv = ExitStatus::SINGLE_FAILURE;
  } else {
    //printf("Exec filename; %s\n", path);
    unsigned char hashbuf[SHA_DIGEST_LENGTH*2+1] = {0};
    int hash_result = yield_from(hash_file, details, path, hashbuf);
    if (hash_result == INTERNAL_ERROR) {
      // We failed
      printf("[SBOM] Unable to hash file %s\n", path);
      rv = ExitStatus::SINGLE_FAILURE;
    } else if (hash_result < 0) {
      // Not our failure, leave RV as success
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
  ExitStatus rv = ExitStatus::SUCCESS;
  char lib_path[128];

  // fifth arg may be an FD, but it's ignored if the fourth arg is MAP_ANONYMOUS (note get_arg 0-indexes)
  int flags  = (int)get_arg(regs, RegIndex::ARG3);
  int fd = (int)get_arg(regs, RegIndex::ARG4); 

  if (!(flags & MAP_ANONYMOUS)) {
    if (yield_from(fd_to_filename, details, fd, lib_path) == -1) {
      printf("[SBOM] Unable to get filename for fd %d\n", fd);
      rv = ExitStatus::SINGLE_FAILURE;
    } else {
      // Successfully got filename, let's use it!
      unsigned char hashbuf[SHA_DIGEST_LENGTH*2+1] = {0};
      int hash_result = yield_from(hash_file, details, lib_path, hashbuf);
      if (hash_result == INTERNAL_ERROR) {
        // We failed
        printf("[SBOM] Unable to hash mapped file %s\n", lib_path);
        rv = ExitStatus::SINGLE_FAILURE;
      } else if (hash_result < 0) {
        // Not our failure, leave RV as success
      } else {
        printf("[SBOM] Mapped file %s with hash %s\n", lib_path, hashbuf);
      }
    }
  }

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


