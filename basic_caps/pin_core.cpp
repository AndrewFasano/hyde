#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include <time.h> // nanosleep
#include <cstring> // memcpy
#include <sys/mman.h> // for mmap flags
#include <sched.h> // For sched and CPU_...
#include "hyde.h"


SyscCoroutine injector(asid_details* details) {

  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  // PIN to current CPU
  __u64 *stack_cpy = (__u64*)malloc(sizeof(cpu_set_t));
  unsigned *stack_ptr;
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(stack_cpy, stack_ptr, sizeof(cpu_set_t));
  printf("Read one word from stack at %llx, got %llx\n", regs.rsp, *stack_cpy);

  yield_syscall(details, __NR_getcpu, regs.rsp, 0);
  unsigned int cpu_id;
  memcpy(&cpu_id, stack_ptr, sizeof(unsigned int));
  printf("Current cpu is %x\n", cpu_id);

  // Get current affinity so we can later restore it
  assert(yield_syscall(details, __NR_sched_getaffinity, sizeof(cpu_set_t), regs.rsp) == 0);
  cpu_set_t orig_aff;
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(&orig_aff, stack_ptr, sizeof(cpu_set_t));

  // Calculate cpu_set_t for the current CPU
  cpu_set_t c;
  CPU_SET(cpu_id, &c);
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(stack_ptr, &c, sizeof(cpu_set_t));
  int af_rv = yield_syscall(details, __NR_sched_setaffinity, 0, sizeof(cpu_set_t), regs.rsp);
  printf("AFRV %d\n", af_rv);
  assert(af_rv == 0);

  // Restore RSP
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(stack_ptr, stack_cpy, sizeof(cpu_set_t));

  __u64 buf_g = get_arg(regs, 1);
  int length = get_arg(regs, 2);

  char *buf;
  map_guest_pointer(details, buf, buf_g);

  unsigned long tid = yield_syscall(details, __NR_gettid);
  unsigned long pid = yield_syscall(details, __NR_getpid);

  char *host_copy = (char*)malloc(length);
  memcpy(host_copy, buf, length);
  host_copy[length-1] = 0; // Drop last character, it's probably \n

  char TARGET[] = {"Thread number"};
  if (strstr(host_copy, (char*)&TARGET) != NULL) {
    printf("[HyDE] Found proc %ld.%ld about to write '%s'. Let's sleep it for 1s\n", pid, tid, host_copy);

    // Allocate a scratch buffer for sleeping
    __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
        /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
        /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

    timespec* req_h;
    map_guest_pointer(details, req_h, guest_buf);
    req_h->tv_sec  = 1;
    req_h->tv_nsec = 0;
    __u64 req_guest = (__u64)guest_buf;
    __u64 rem_guest = (__u64)guest_buf + sizeof(timespec);

    // Sleep
    yield_syscall(details, __NR_nanosleep, req_guest, rem_guest);

    // Cleanup scratch buffer
    yield_syscall(details, __NR_munmap, (__u64)guest_buf, 1024);
  }

  // CLEANUP
  // Backup RSP
#if 0
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(stack_cpy, stack_ptr, sizeof(cpu_set_t));

  // Clober RSP in guest with orig_aff
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(stack_ptr, &orig_aff, sizeof(cpu_set_t));
  // Restore affinity

  af_rv = yield_syscall(details, __NR_sched_setaffinity, 0, sizeof(cpu_set_t), regs.rsp);
  printf("AFRV2 restoring %llx, got %d\n", *(__u64*)&orig_aff, af_rv);
  assert(af_rv == 0);

  // Restore RSP
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(stack_ptr, stack_cpy, sizeof(cpu_set_t));
#endif
  free(stack_cpy);

  co_yield *(details->orig_syscall);
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  if (callno == __NR_write)
    return &injector;
  return NULL;
}
