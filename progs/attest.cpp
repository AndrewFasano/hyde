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

// Store mapping of filenames to sha1sums
const std::vector<const char*> known_files = {"/usr/bin/sha1sum", "/lib/x86_64-linux-gnu/libc-2.27.so"};
const std::vector<const char*> known_hashes = {"0648f41a6c74f78414a330c299fda56b1c4b327d", "18292bd12d37bfaf58e8dded9db7f1f5da1192cb"};

#define BUF_SZ 1024 // Size to use for read chunks
#define INTERNAL_ERROR -99999

bool hash_match(const char *path, const char *digest) {
  // Check if this is a known file, if so does the hash match?
  for (int i = 0; i < known_files.size(); i++) {
    if (strcmp(path, known_files[i]) == 0) {
      if (strcmp(digest, known_hashes[i]) != 0) {
        return false;
      } else {
        // Matches and hash is good
        //printf("[Attest] Executing %s with good sha1sum of %s\n", path, digest);
        return true;
      }
    }
  }
  // No match - fail open or closed?
  return true;
}

// Duplicate from sbom.cpp
template <std::size_t N>
SyscCoroHelper hash_file(syscall_context *details, char(&path)[N], unsigned char (&outbuf)[SHA_DIGEST_LENGTH*2+1]) {
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
    printf("[Attest] Unable to initialize sha context\n");
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
      printf("[Attest] Unable to update sha context\n");
      fail = true;
      rv = INTERNAL_ERROR;
      break;
    }
  }

  if (!fail) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    if (!SHA1_Final(hash, &context)) {
      printf("[Attest] Unable to finalize sha context\n");
      rv = INTERNAL_ERROR; // Still need to close
    } else {
      // Turn our sha1sum into a digest string
      int i = 0;
      for (i=0; i < SHA_DIGEST_LENGTH; i++) {
          sprintf((char*)&(outbuf[i*2]), "%02x", hash[i]);
      }
    }
  }
 co_return rv;
}


SyscallCoroutine pre_execve_at(syscall_context* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  char full_path[256];
  int readlink_rv;
  int fd = get_arg(regs, RegIndex::ARG0); 
  int hash_result;

  ExitStatus rv = ExitStatus::SUCCESS;

  // Read pathname from arg 1
  char path[256];
  if (yield_from(ga_memread, details, path, get_arg(regs, RegIndex::ARG1), sizeof(path)) == -1) {
      printf("[Attest] Unable to read filename\n");
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
      printf("[Attest] Unable to get filename for fd %d\n", rv);
      rv = ExitStatus::SINGLE_FAILURE;
      goto out;
    }
    // Set full_path to be dir_path / path
    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, path);
  }

  unsigned char digest[SHA_DIGEST_LENGTH*2+1];
  hash_result = yield_from(hash_file, details, full_path, digest);

  if (hash_result == INTERNAL_ERROR) {
    // We failed
    printf("[Attest] Unable to hash file %s: %d\n", full_path, hash_result);
    rv = ExitStatus::SINGLE_FAILURE; // Not our failure
  } else if (hash_result < 0) {
    // Not our failure, leave RV as success
  } else {
    // Actual success, we calculated the hash
    if (!hash_match(full_path, (char*)digest)) {
      printf("[Attest] BLOCKING EXECUTION OF %s. Has sha1sum of %s which is not allowed\n", full_path, digest);
      details->orig_syscall->callno = SYS_getpid; // We can't leave original since execve is noreturn
      details->orig_syscall->has_retval = true;
      details->orig_syscall->retval = -ENOEXEC;
      co_return ExitStatus::SUCCESS; // Successfully blocked it
    }
  }

out:
  // yield original syscall (execve_at)
  co_yield *(details->orig_syscall);
  co_return rv;
}

SyscallCoroutine pre_execve(syscall_context* details) {
  struct kvm_regs regs;
  char path[256];
  ExitStatus rv = ExitStatus::SUCCESS;
  get_regs_or_die(details, &regs);
  uint64_t path_ptr = get_arg(regs, RegIndex::ARG0); 

  if (yield_from(ga_memcpy, details, path, path_ptr, sizeof(path)) == -1) {
      printf("[Attest] Unable to read filename at %lx\n", path_ptr);
      rv = ExitStatus::SINGLE_FAILURE;
  } else {
    //printf("Exec filename; %s\n", path);
    unsigned char digest[SHA_DIGEST_LENGTH*2+1] = {0};
    int hash_result = yield_from(hash_file, details, path, digest);
    if (hash_result == INTERNAL_ERROR) {
      // We failed
      printf("[Attest] Unable to hash file %s\n", path);
      rv = ExitStatus::SINGLE_FAILURE;
    } else if (hash_result < 0) {
      // Not our failure, leave RV as success
    } else {
      if (!hash_match(path, (char*)digest)) {
        printf("[Attest] BLOCKING EXECUTION OF %s. Has sha1sum of %s which is not allowed\n", path, digest);
        details->orig_syscall->callno = SYS_getpid; // We can't leave original since execve is noreturn
        details->orig_syscall->has_retval = true;
        details->orig_syscall->retval = -ENOEXEC;
        co_return ExitStatus::SUCCESS; // Successfully blocked it
      }
    }
  }

  // yield original syscall
  co_yield *(details->orig_syscall);
  co_return rv;
}

SyscallCoroutine pre_mmap(syscall_context* details) {
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  ExitStatus rv = ExitStatus::SUCCESS;
  char lib_path[128];

  // fifth arg may be an FD, but it's ignored if the fourth arg is MAP_ANONYMOUS (note get_arg 0-indexes)
  int flags  = (int)get_arg(regs, RegIndex::ARG3);
  int fd = (int)get_arg(regs, RegIndex::ARG4); 

  if (!(flags & MAP_ANONYMOUS)) {
    if (yield_from(fd_to_filename, details, fd, lib_path) == -1) {
      printf("[Attest] Unable to get filename for fd %d\n", fd);
      rv = ExitStatus::SINGLE_FAILURE;
    } else {
      // Successfully got filename, let's use it!
      unsigned char digest[SHA_DIGEST_LENGTH*2+1] = {0};
      int hash_result = yield_from(hash_file, details, lib_path, digest);
      if (hash_result == INTERNAL_ERROR) {
        // We failed
        printf("[Attest] Unable to hash mapped file %s\n", lib_path);
        rv = ExitStatus::SINGLE_FAILURE;
      } else if (hash_result < 0) {
        // Not our failure, leave RV as success
      } else {
        printf("[Attest] Mapped file %s with hash %s\n", lib_path, digest);
      if (!hash_match(lib_path, (char*)digest)) {
        printf("[Attest] BLOCKING MAP OF %s. Has sha1sum of %s which is not allowed\n", lib_path, digest);
        details->orig_syscall->callno = SYS_getpid; // We can't leave original since execve is noreturn
        details->orig_syscall->has_retval = true;
        details->orig_syscall->retval = -ENOMEM;
        co_return ExitStatus::SUCCESS; // Successfully blocked it
      }
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