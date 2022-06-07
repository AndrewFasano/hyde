#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <vector>
#include "hyde.h"

SyscCoroutine start_coopter(asid_details* details) {
  printf("First get the PID\n");
  int ogpid = yield_syscall(details, __NR_getpid);
  printf("PID is %x. Now allocate\n", ogpid);

  __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
      /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
      /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

  if ((signed long long int)guest_buf <= 0 && (signed long long int)guest_buf > -0x1000) {
    printf("[HYDE] ERROR allocating scratch buffer got: %lld\n", (signed long long int) guest_buf);
    co_return;
  }
  printf("Buffer is at %lx\n", (unsigned long)guest_buf);

  char* host_buf;
  bool success;
  map_guest_pointer_status(details, host_buf, guest_buf, &success);
  if (!success) {
    printf("FAILURE to map guest pointer at %llx\n", (__u64)guest_buf);
    co_return;
  }
  size_t message_size = sprintf(host_buf, "Hello world message in guest at %#llx\n", (__u64)guest_buf);

  // Call write(1, buf, sizeof(buf));
  __u64 bytes_written = yield_syscall(details, __NR_write,
      /*fd=*/ 1,
      /*buf=*/ (__u64)guest_buf,
      /*size=*/ message_size);

  // Finally, we run the original syscall
  //details->orig_syscall->nargs = 0;
  co_yield *(details->orig_syscall); // noreturn
}

create_coopt_t* should_coopt(void*cpu, long unsigned int callno) {
  // We inject syscalls starting at every execve
  if (callno == __NR_getuid || callno == __NR_geteuid)
    return &start_coopter;
  return NULL;
}


