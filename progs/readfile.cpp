#include <sys/stat.h> // for open flags
#include <sys/types.h> // for open flags
#include <fcntl.h> // for open flags
#include <iostream>
#include <mutex>
#include <sys/random.h>
#include "hyde_sdk.h"

#define SZ 1024

SyscallCoroutine pre_mmap(SyscallCtx* details) {
  // Fifth arg may be an FD, but it's ignored if the fourth arg is MAP_ANONYMOUS (note get_arg 0-indexes)
  int flags  = details->get_arg(3);

  if (!(flags & MAP_ANONYMOUS)) {
    // Allocate scratch
    uint64_t scratch = yield_syscall_raw(details, mmap, 0, SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((int64_t)scratch < 0 && (int64_t)scratch > -4096) {
        printf("MMAP FAILURE: %ld\n", (int64_t)scratch);
        assert(0);
    }
    // Force guest to write to the scratch buffer which makes the kernel actually allocate the memory for us to use
    yield_syscall(details, getrandom, scratch, SZ, 0);
    // XXX at this point the buffer could still be aliased, but we just asked for SZ random bytes so let's assume the odds of a collision are 0
    // Otherwise we'd have issues with race conditions if other processes accessed this aliased memory while we were going, and we'd need to restore at the end

    // NOW SAFE TO USE HOST_BUF
    void* host_buf;
    assert(yield_from(ga_map, details, scratch, &host_buf, SZ) == 0);

    // Let's readlink /proc/self/fd/X
    snprintf((char*)host_buf, SZ, "/proc/self/fd/%ld", details->get_arg(4));

    int readlink_sz = yield_syscall(details, readlink, scratch, scratch+512, 512);

    // Now read result
    char result[512];
    yield_from(ga_memread, details, result, scratch+512, readlink_sz);
    result[readlink_sz] = 0;
    printf("FD %ld is %s\n", details->get_arg(4), result);

    yield_from(ga_memwrite, details, scratch, result, strlen(result)+1);
    // Now let's open that file
    int fd = yield_syscall(details, open, scratch, O_RDONLY);

    if (fd >= 0) {
      int read_rv = yield_syscall(details, read, fd, scratch, SZ);

      char filebuf[SZ];
      yield_from(ga_memread, details, filebuf, scratch, read_rv);
      filebuf[read_rv] = 0;
      yield_syscall(details, close, fd);

      printf("File contents: %s\n", filebuf);
    }else {
      printf("Failed to read file: %d\n", fd);
    }

    // Cleanup - restore scratch
    yield_syscall(details, munmap, scratch, SZ);
  }
  
  // yield original syscall
  co_yield_noreturn(details, *(details->get_orig_syscall()), ExitStatus::SUCCESS);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_mmap]  = pre_mmap;
  return true;
}