#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <vector>
#include <set>
#include <map>

#include <sys/types.h>
#include <sys/stat.h> // File accesses
#include <fcntl.h>

#include <unistd.h> // read, seek

#include "hyde.h"

// openat(AT_FDCWD, "/missing", O_RDONLY)  = -1 ENOENT (No such file or directory)
// Change path to /etc, get FD
// read(FD, 0x7f49b8d40000, 131072)         = -1 EISDIR (Is a directory)
// Change RV to size, write payload into buffer up to size


typedef struct {
  unsigned int pos;
} fd_info;

std::map<std::pair<int, int>, fd_info*> asid_fds;


#define TARGET "/missing"
#define FAKE_NAME "/etc\x00"
#define HOST_FILE "/etc/passwd"

SyscCoroutine start_coopter_openat(asid_details* details) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  bool match = false;
  char *host_fname; // Can dereference on host
  __u64 guest_fname = (__u64)get_arg(regs, 1); // Can't dereference on host, just use for addrs
  map_guest_pointer(details, host_fname, guest_fname);

  if (strcmp(host_fname, TARGET) != 0)
    goto runit;

  match = true;

  // Let's instead open a file that we know exists so there's an actual FD we can track
  // We'll use /etc and on read we'll detect EISDIR as a sanity check
  memcpy(host_fname, FAKE_NAME, strlen(FAKE_NAME)+1); // Include null byte!
   
runit:
  // Run the original syscall, we may have changed the path in memory, but the syscall remains the same
  //int fd = yield_syscall(details, details->orig_syscall->callno, get_arg(regs, 0), get_arg(regs, 1), get_arg(regs, 2));

  co_yield *(details->orig_syscall);
  unsigned int fd = (int)details->retval;

  if (match) {
    printf("Got FD: %d\n", fd);
    fd_info *f = new fd_info;
    f->pos = 0;
    asid_fds[std::make_pair(details->asid, fd)] = f;
  }

  //details->orig_syscall->retval = fd;
  //details->orig_syscall->has_retval = true;
}

SyscCoroutine start_coopter_read(asid_details* details) {
  co_yield *(details->orig_syscall);
  unsigned long rv = details->retval;
  details->orig_syscall->retval = details->retval;

  if (rv != -EISDIR) {
    details->orig_syscall->has_retval = true; // Necessary?
    co_return;
  }

  // it's probably ours, let's check
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  int req_fd  = get_arg(regs, 0);
  __u64 req_buf = (__u64)get_arg(regs, 1);
  int req_cnt = get_arg(regs, 2);

  auto key = std::make_pair(details->asid, req_fd);
  if (asid_fds.find(key) == asid_fds.end()) {
    printf("Not our EISDIR\n");
    details->orig_syscall->has_retval = true; // Necessary?
    co_return;
  }

  fd_info *f = asid_fds[key];
  printf("Guest read returns EISDIR for something of ours. Seeking to %d\n", f->pos);

  int fd = open(HOST_FILE, O_RDONLY);
  lseek(fd, f->pos, SEEK_SET);
  char *host_buf = (char*)malloc(req_cnt);
  int bytes_read = read(fd, host_buf, req_cnt);
  close(fd);


  // Now we need to copy bytes_read
  for (int i=0; i < bytes_read; i++) {
    char* host_guestbuf;
    *host_guestbuf = host_buf[i];
  }

  free(host_buf);

  int uid = yield_syscall(details, __NR_getuid);

  details->orig_syscall->has_retval = true; // Redundant?
  details->orig_syscall->retval = bytes_read;
  f->pos += bytes_read;
}

SyscCoroutine start_coopter_close(asid_details* details) {
  co_yield *(details->orig_syscall);
  int rv = (int)details->retval;
  details->orig_syscall->retval = details->retval;

  // it's probably ours, let's check
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);

  int req_fd  = get_arg(regs, 0);
  __u64 req_buf = (__u64)get_arg(regs, 1);
  int req_cnt = get_arg(regs, 2);

  auto key = std::make_pair(details->asid, req_fd);
  if (asid_fds.find(key) == asid_fds.end()) {
    details->orig_syscall->has_retval = true; // Necessary?
    co_return;
  }

  fd_info *f = asid_fds[key];
  free(f);
  asid_fds.erase(key);

  details->orig_syscall->has_retval = true; // Necessary?
}

SyscCoroutine start_coopter_exit(asid_details* details) {
  for (auto it=asid_fds.begin(); it!= asid_fds.end(); ++it) {
    if (it->first.first == details->asid) {
      printf("EXIT with active asid_fd: cleanup\n");
      asid_fds.erase(it);
    }
  }
  co_yield *(details->orig_syscall);
  printf("Just ran orig exit SC\n");
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  if (callno == __NR_openat)
    return &start_coopter_openat;
  else if (callno == __NR_read)
    return &start_coopter_read;
  else if (callno == __NR_close)
    return &start_coopter_close;
  else if (callno == __NR_exit)
    return &start_coopter_exit;
  else if (callno == __NR_exit_group)
    return &start_coopter_exit;

  return NULL;
}
