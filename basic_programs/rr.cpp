#include <asm/unistd.h> // Syscall numbers
#include <stdio.h>
#include <cstring>
#include <signal.h>
#include "hyde.h"

static bool REPLAY = true;
static bool RECORD = !REPLAY;

static int mmap_ctr = 0;
long mmap_cache[] = {0x7ffff7ff0000, 0x7ffff7fee000, 0x7ffff79e2000, 0x7ffff7e53000, 0x7ffff7ff6000, 0x7ffff7e4c000, 0x7ffff7ff5000, 0x7ffff7ff4000, 0x7ffff7ff3000, 0x7ffff7ff2000, 0x7ffff7ff1000, 0x7ffff7ff0000, 0x7ffff7e4b000, 0x7ffff786f000, 0x7ffff7e4a000, 0x7ffff7e49000, 0x7ffff7e18000, 0x7ffff7e11000, 0x7ffff7665000, 0x7ffff7e11000, 0x7ffff7459000, 0x7ffff723f000, 0x7ffff702d000, 0x7ffff7e17000};

static int read_ctr = 0;
int read_cache_sz[] = {1, 1, 1, 1, 1, 1, 1};
const char* read_cache_data[] = {"w", "h", "o", "a", "m", "i", "\n"};

static bool continued_all = false;

SyscCoroutine mmap_rr(asid_details* details) {
  if (REPLAY && details->orig_syscall->args[0] == 0) {
    // Need to request allocation at previously-known address
    bool cached = false;
    if (mmap_ctr < sizeof(mmap_cache)/sizeof(mmap_cache[0])) {
      cached = true;
    }

    if (cached) {
      details->orig_syscall->args[0] = mmap_cache[mmap_ctr];
      mmap_ctr++;
    }

    co_yield *(details->orig_syscall);
    details->orig_regs.rax = (__u64)details->retval;

    if (cached) {
      assert(details->retval == mmap_cache[mmap_ctr-1]);
    }
  }

  if (RECORD) {
    co_yield *(details->orig_syscall);
    details->orig_regs.rax = (__u64)details->retval;

    // Non-det IFF addr is NULL
    if (details->orig_syscall->args[0] == 0) {
      printf("%lx,\n", details->retval);
    }
  }

#if 0
  printf("Asid %x runs syscall %d args %lx %lx %lx %lx %lx %lx => %ld\n",
    details->asid, 
    details->orig_syscall->callno,
    details->orig_syscall->args[0],
    details->orig_syscall->args[1],
    details->orig_syscall->args[2],
    details->orig_syscall->args[3],
    details->orig_syscall->args[4],
    details->orig_syscall->args[5],
    details->retval);
#endif
}

SyscCoroutine read_rr(asid_details* details) {
  if (REPLAY) {
    // Need to return same buffer as cache
    bool cached = false;
    if (read_ctr < sizeof(read_cache_sz)/sizeof(read_cache_sz[0])) {
      cached = true;
    }

    if (cached && details->orig_syscall->args[0] == 0) { // XXX: debug, only FD 0
      // Copy data into out buffer and set size - don't run the read syscall at all
      // Maybe seek FD?
      printf("Replay %d read from FD %ld: %s\n", read_ctr, details->orig_syscall->args[0], read_cache_data[read_ctr]);
      char* out;
      if (read_cache_sz[read_ctr] > 0) {
        map_guest_pointer(details, out, details->orig_syscall->args[1]);
        memcpy(out, read_cache_data[read_ctr], read_cache_sz[read_ctr]);
      }
      details->orig_regs.rax = (__u64)read_cache_sz[read_ctr];
      yield_syscall(details, __NR_lseek, details->orig_syscall->args[0], read_cache_sz[read_ctr], SEEK_CUR);
      read_ctr++;
    }else{
      // Uncached
      co_yield *(details->orig_syscall);
      details->orig_regs.rax = (__u64)details->retval;
    }
  }

  if (RECORD) {
    printf("Read up to %ld bytes from FD %ld\n",
      details->orig_syscall->args[2], 
      details->orig_syscall->args[0]);

    co_yield *(details->orig_syscall);
    details->orig_regs.rax = (__u64)details->retval;
    char* data;
    map_guest_pointer(details, data, details->orig_syscall->args[1]);
    printf("Read %ld bytes: %.*s\n", details->retval, (int)details->retval, data);
  }
}

SyscCoroutine signal_all(asid_details* details) {
  if (REPLAY && !continued_all) {
    printf("Check UID\n");
    if (yield_syscall(details, __NR_getuid, 0, 0) == 0) {
      printf("Found root proc for continue_all\n");
      yield_syscall(details, __NR_kill, -1, SIGSYS);
      printf("Did it\n");
      continued_all = true;
    }
  }

  assert(details->orig_syscall != NULL);
  co_yield *(details->orig_syscall);
  details->orig_regs.rax = (__u64)details->retval;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno, long unsigned int pc, unsigned int asid) {

  return NULL; // XXX always a no-op

  if (callno ==  __NR_mmap) {
    return &mmap_rr;
  }else if (callno == __NR_read) {
    return &read_rr;
  //}else if (!continued_all) {
  //  return &signal_all;
  }

  //return &record_syscall;
  return NULL;
}

