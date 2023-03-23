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
  unsigned long *stack_ptr;
  unsigned long tid = yield_syscall(details, __NR_gettid);

  // Copy data out of RSP
  // stack_cpy = backup of stack
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(stack_cpy, stack_ptr, sizeof(cpu_set_t));

  // cpu_id = getcpu(), clobber rsp
  map_guest_pointer(details, stack_ptr, regs.rsp);
  yield_syscall(details, __NR_getcpu, regs.rsp, 0);
  unsigned long cpu_id;
  memcpy(&cpu_id, stack_ptr, sizeof(unsigned long));
  cpu_id &= 0xffffffff; // Actual RV is signed, throw away sign bits? This isn't right, but it works?

  // orig_aff = sched_getaffinity()
  int af_get = yield_syscall(details, __NR_sched_getaffinity, 0, sizeof(unsigned long), regs.rsp);
  assert(af_get >= 0);

  map_guest_pointer(details, stack_ptr, regs.rsp);
  unsigned long orig_aff;
  memcpy(&orig_aff, stack_ptr, sizeof(stack_ptr));

  unsigned long old_pin;

  map_guest_pointer(details, stack_ptr, regs.rsp);
  old_pin = *stack_ptr;

  if (old_pin != 1) {
    //*stack_ptr = 0;
    asm volatile("bts %1,%0" : "+m" (*(volatile long *) (stack_ptr)) : "Ir" (cpu_id) : "memory");

    int af_rv = yield_syscall(details, __NR_sched_setaffinity, 0, sizeof(unsigned long), regs.rsp);
    if (af_rv != 0) printf("AF_RV %d\n", af_rv);
    assert(af_rv == 0);
  }



main:
  // Do something useful here? Actual injection body
  char TARGET[] = {"Thread number"};

  __u64 buf_g = get_arg(regs, 1);
  int length = get_arg(regs, 2);

  char *buf;
  map_guest_pointer(details, buf, buf_g);
  char *host_copy = (char*)malloc(length);
  memcpy(host_copy, buf, length);
  host_copy[length-1] = 0; // Drop last character, it's probably \n


  if (strstr(host_copy, (char*)&TARGET) != NULL) {
    // Allocate a scratch buffer for sleeping
    __u64* guest_buf = (__u64*)yield_syscall(details, __NR_mmap,
        /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
        /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

    yield_syscall(details, __NR_getcpu, (unsigned long)guest_buf, 0);
    unsigned long inner_cpu_id;
    unsigned long* ul;
    map_guest_pointer(details, ul, guest_buf);
    memcpy(&inner_cpu_id, ul, sizeof(unsigned long));

    timespec* req_h;
    map_guest_pointer(details, req_h, guest_buf);
    req_h->tv_sec  = 2;
    req_h->tv_nsec = 0;
    __u64 req_guest = (__u64)guest_buf;
    __u64 rem_guest = (__u64)guest_buf + sizeof(timespec);

    int pre_tid = yield_syscall(details, __NR_gettid);
    int pre_pid = yield_syscall(details, __NR_getpid);

    printf("[HyDE cpu.%ld coopter@%p] Found proc %d.%d about to write '%s'. Let's sleep it for 2s\n", inner_cpu_id,
          details, pre_pid, pre_tid, host_copy);

    // Sleep (good chance of moving threads after this one)
    yield_syscall(details, __NR_nanosleep, req_guest, rem_guest);

    int post_tid = yield_syscall(details, __NR_gettid);
    int post_pid = yield_syscall(details, __NR_getpid);
    memcpy(&inner_cpu_id, req_h, sizeof(unsigned long));
    
    printf("[HyDE cpu.%ld coopter@%p] Found proc %d.%d after sleep\n", inner_cpu_id, details, post_pid, post_tid);

    yield_syscall(details, __NR_munmap, (__u64)guest_buf, 1024);
  }

orig_sc:
  co_yield *(details->orig_syscall);
  details->orig_syscall->retval = details->retval;

unpin:
  if (old_pin != 1) {
    // Copy our previously-saved orig_aff object onto the stack
    map_guest_pointer(details, stack_ptr, regs.rsp);
    memcpy(stack_ptr, &old_pin, sizeof(old_pin));

    // Restore our affinity
    int af_rv3 = yield_syscall(details, __NR_sched_setaffinity, 0, sizeof(unsigned long), regs.rsp);
    if (af_rv3 != 0) printf("AF_RV3: %d\n", af_rv3);
    assert(af_rv3 == 0);
  }

  // Restore RSP
  // stack = backup of stack
  map_guest_pointer(details, stack_ptr, regs.rsp);
  memcpy(stack_ptr, stack_cpy, sizeof(cpu_set_t));

  // Final result?
  details->orig_syscall->has_retval = true;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  if (callno == __NR_write)
    return &injector;
  return NULL;
}
