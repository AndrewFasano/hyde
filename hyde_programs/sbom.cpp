#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <sys/types.h> // O_RDONLY
#include <sys/stat.h>  // O_RDONLY
#include <fcntl.h>     // O_RDONLY
#include <vector>
#include <unordered_set>
#include <map>
#include <openssl/sha.h>

#include "hyde_sdk.h"
#include "file_helpers.h"

#define BUF_SZ 1024 // Size to use for read chunks
#define INTERNAL_ERROR -99999
FILE *fp;

std::unordered_set<std::string> read_files;

// Duplicated in attest.cpp
template <std::size_t N>
SyscCoroHelper hash_file(SyscallCtx *details, char(&path)[N], unsigned char (&outbuf)[SHA_DIGEST_LENGTH*2+1]) {
  // Hash a file at the specified pointer. write ascii digest into outbuf
  int rv = 0;
  std::string buffer;
  int guest_fd;

  std::vector<__u64> guest_arg_ptrs;
  std::vector<std::string> arg_list;
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

  // Read file until we hit EOF, or 1024*1000 bytes update sha1sum as we go
  int loop_count = 0;
  while (loop_count++ < 1000000) {
    if (loop_count == 999999) [[unlikely]] {
      printf("Bailing early on %s - inifnite loop?\n", path_buf); // Unlikely
      fail = true;
      break;
    }

    char host_data[BUF_SZ];
    int bytes_read = yield_syscall(details, read, guest_fd, host_data, BUF_SZ);
    if (bytes_read == 0) break;
    if (bytes_read < 0) {
      printf("[SBOM] Unable to read file %s: %d\n", path_buf, bytes_read);
      fail = true;
      break;
    }

    if (!SHA1_Update(&context, host_data, bytes_read)) {
      printf("[SBOM] Unable to update sha context\n");
      fail = true;
      break;
    }
  }

  if (fail) {
    rv = INTERNAL_ERROR;
  } else {
    unsigned char hash[SHA_DIGEST_LENGTH];
    if (!SHA1_Final(hash, &context)) {
      printf("[SBOM] Unable to finalize sha context\n");
      rv = INTERNAL_ERROR; // Still need to close
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

template <std::size_t N>
SyscCoroHelper hash_if_new(SyscallCtx* details, char (&lib_path)[N]) {
  if (read_files.count(std::string(lib_path)) == 0) {
    read_files.insert(std::string(lib_path));

    unsigned char hashbuf[SHA_DIGEST_LENGTH*2+1] = {0};
    int hash_result = yield_from(hash_file, details, lib_path, hashbuf);
    if (hash_result == INTERNAL_ERROR) {
      // We failed
      printf("[SBOM] Unable to hash mapped file %s\n", lib_path);
      co_return -1;
    } else if (hash_result < 0) {
      // Not our failure, leave RV as success
    } else {
      fprintf(fp, "%s, %s\n", lib_path, hashbuf);

      // Just to get automated testing to work:
      if (strncmp(lib_path, "date", N) != 0) [[unlikely]] {
          fflush(fp);
      }
    }
  }
  co_return 0;
}


SyscallCoroutine pre_execveat(SyscallCtx* details) {
  char full_path[PATH_LENGTH];
  int readlink_rv;
  int fd = details->get_arg(0);
  int hash_result;

  ExitStatus rv = ExitStatus::SUCCESS;

  // Read pathname from arg 1
  char path[PATH_LENGTH];
  if (yield_from(ga_memread, details, path, details->get_arg(1), sizeof(path)) == -1) {
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

  if (strlen(full_path) > 0) {
    if (yield_from(hash_if_new, details, full_path) == -1) {
      rv = ExitStatus::SINGLE_FAILURE;
    }
  }

out:
  // yield original syscall
  yield_and_finish(details, *(details->get_orig_syscall()), rv);
}

SyscallCoroutine pre_execve(SyscallCtx* details) {
  char path[256];
  ExitStatus rv = ExitStatus::SUCCESS;
  uint64_t path_ptr = details->get_arg(0);

  if (yield_from(ga_strncpy, details, path, path_ptr, sizeof(path)) < 0) {
      printf("[SBOM] Unable to read filename at %lx\n", path_ptr);
      rv = ExitStatus::SINGLE_FAILURE;
  } else if (strlen(path)) {
      if (yield_from(hash_if_new, details, path) == -1) {
        rv = ExitStatus::SINGLE_FAILURE;
      }
  }

  // yield original syscall
  yield_and_finish(details, *(details->get_orig_syscall()), rv);
}

SyscallCoroutine pre_mmap(SyscallCtx* details) {
  ExitStatus rv = ExitStatus::SUCCESS;
  char lib_path[PATH_LENGTH];

  // fifth arg may be an FD, but it's ignored if the fourth arg is MAP_ANONYMOUS (note get_arg 0-indexes)
  int flags  = details->get_arg(3);
  int fd = details->get_arg(4);

  if (!(flags & MAP_ANONYMOUS)) {
    if (yield_from(fd_to_filename, details, fd, lib_path) == -1) {
      printf("[SBOM] Unable to get filename for fd %d\n", fd);
      rv = ExitStatus::SINGLE_FAILURE;
    } else if (strlen(lib_path)) {
      // Successfully got filename, let's use it!
      if (yield_from(hash_if_new, details, lib_path) == -1) {
        rv = ExitStatus::SINGLE_FAILURE;
      }
    }
  }

  // yield original syscall
  yield_and_finish(details, *(details->get_orig_syscall()), rv);
}


void __attribute__ ((destructor)) teardown(void) {
    fclose(fp);
}

bool init_plugin(CoopterMap map) {
  fp = fopen("sbom.log", "w");
  map[SYS_execve] = pre_execve;
  map[SYS_execveat] = pre_execveat;
  map[SYS_mmap] = pre_mmap;
  return true;
}
