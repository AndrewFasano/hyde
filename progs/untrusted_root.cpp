#include <sys/syscall.h> // for SYS_
#include <iostream> // cout, cerr
#include <set>
#include <fcntl.h>
#include "file_helpers.h" // read_file

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <tuple>

#include "hyde_common.h"

//Two coroutines: deny (things we never allow) and validate (things we allow)
const char deny_msg[] = "Negative ghost rider\n";

enum class DeviceType {
  CHAR,
  BLOCK
};
//Devices we allow to be opened (major, minor, char|block)
//DeviceType is last since we sort by major like this list:
//https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/devices.txt
const std::vector<std::tuple<int, int, DeviceType>> AllowedDevices ={
  {1, 3, DeviceType::CHAR}, // /dev/null
  {1, 5, DeviceType::CHAR}, // /dev/zero
  {1, 8, DeviceType::CHAR}, // /dev/urandom
  {1, 9, DeviceType::CHAR}, // /dev/random
  {5, -1, DeviceType::CHAR}, // tty,console
  {10, -1, DeviceType::CHAR}, // catch-all for lots of features, could get more specific
};
//Used to Deny, but the list got long:
//If minor is -1, we will deny all devices of that major
  /*
  {1, 1, DeviceType::CHAR}, // /dev/mem
  {1, 2, DeviceType::CHAR}, // /dev/kmem - should never see
  {1, 6, DeviceType::CHAR}, // /dev/core - should never see
  {2, -1, DeviceType::BLOCK}, // Floppy drive: VM Escapes happen here
  {3, -1, DeviceType::BLOCK}, // /dev/hd - prevent loading of CDs
  {4, -1, DeviceType::BLOCK}, // /dev/root
  {8, -1, DeviceType::BLOCK}, // Direct Access to /dev/sd
  ...
  */
    
  


SyscallCoroutine deny(SyscallCtx* details) {
  yield_syscall(details, write, 1, deny_msg, sizeof(deny_msg));
  details->get_orig_syscall()->has_retval = true;
  details->get_orig_syscall()->retval = -1;
  co_return ExitStatus::SUCCESS;
}

SyscallCoroutine filter_open(SyscallCtx* details) {
  struct kvm_regs regs;
  char path[PATH_MAX];
  uint64_t path_ptr;
  int dirfd;
  struct statx statbuf;
  dev_t minor,major;

  if (details->get_orig_syscall()->callno == SYS_open) {
    path_ptr = details->get_arg(0);
    dirfd = -100;
  } else if (details->get_orig_syscall()->callno == SYS_openat) {
    dirfd = details->get_arg(0);
    path_ptr = details->get_arg(1);
  } else {
    std::cerr << "filter_open called with non-open syscall" << std::endl;
    co_return ExitStatus::SINGLE_FAILURE;
  }
  yield_syscall(details, statx, dirfd, path_ptr, 0, STATX_ALL, &statbuf);
  if (S_ISCHR(statbuf.stx_mode) || S_ISBLK(statbuf.stx_mode)) {
      if(yield_from(ga_memcpy, details, path, path_ptr, PATH_MAX) == -1) {
        printf("Unable to read filename at %p\n", (void *) path_ptr);
      } else {
        strcpy(path, "(error)");
      }
      printf("statx(%s): %lu\n", path, details->get_result());
      minor = statbuf.stx_rdev_minor;
      major = statbuf.stx_rdev_major;
      printf("  statx.stx_rdev_major: %lu\n", minor);
      printf("  statx.stx_rdev_minor: %lu\n", major);
      if (major == 1) {
          if (minor == 1) {
            printf("Tried to open /dev/mem!\n");
          }
      }
  }
  co_yield *(details->get_orig_syscall());
  co_return ExitStatus::SUCCESS;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_init_module] = deny;
  map[SYS_finit_module] = deny;
  map[SYS_delete_module] = deny;
  map[SYS_ptrace] = deny;
  /*
  map[SYS_open] = filter_open;
  map[SYS_openat] = filter_open;
  */
  return true;
}
