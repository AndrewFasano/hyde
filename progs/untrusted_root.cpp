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
  {1, 7, DeviceType::CHAR}, // /dev/full
  {1, 8, DeviceType::CHAR}, // /dev/urandom
  {1, 9, DeviceType::CHAR}, // /dev/random
  {1, 10, DeviceType::CHAR}, // /dev/aio
  {1, 11, DeviceType::CHAR}, // /dev/kmsg
  {1, -1, DeviceType::BLOCK}, // /dev/ramX
  {5, -1, DeviceType::CHAR}, // tty,console
  {10, -1, DeviceType::CHAR}, // catch-all for lots of features, could get more specific if we wanted to block some
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

#define skip_and_finish(rv) \
  ctx->set_nop(rv); \
  co_yield ctx->pending_sc(); \
  finish(ctx, ExitStatus::SUCCESS)

    
SyscallCoroutine deny(SyscallCtx* ctx) {
  printf("[UntrustedRoot] Denying syscall %lu\n", ctx->get_orig_syscall()->callno);
  skip_and_finish(-EPERM);
}

SyscallCoroutine filter_open(SyscallCtx* ctx) {
  struct kvm_regs regs;
  char path[PATH_MAX];
  uint64_t path_ptr;
  int dirfd;
  struct statx statbuf;
  dev_t minor,major;

  if (ctx->get_orig_syscall()->callno == SYS_open) {
    path_ptr = ctx->get_arg(0);
    dirfd = -100;
  } else if (ctx->get_orig_syscall()->callno == SYS_openat) {
    dirfd = ctx->get_arg(0);
    path_ptr = ctx->get_arg(1);
  } else {
    std::cerr << "filter_open called with non-open syscall" << std::endl;
    yield_and_finish(ctx, ctx->pending_sc(), ExitStatus::SINGLE_FAILURE);
  }

  try {
      if (yield_from(ga_strncpy, ctx, path, path_ptr, sizeof(path)) != -1) {
        //Block /proc/kcore - only file that's a device that we can't stat
        if(strcmp(path, "/proc/kcore") == 0) {
          skip_and_finish(-ENOENT);
        }
        yield_syscall(ctx, statx, dirfd, path_ptr, 0, STATX_ALL, &statbuf);
        if (ctx->get_result()==0) {
          if (S_ISCHR(statbuf.stx_mode) || S_ISBLK(statbuf.stx_mode)) {
            DeviceType dev_type = S_ISCHR(statbuf.stx_mode) ? DeviceType::CHAR : DeviceType::BLOCK;
            minor = statbuf.stx_rdev_minor;
            major = statbuf.stx_rdev_major;
            std::tuple<int, int, DeviceType> searchTuple = std::make_tuple(major, minor, dev_type);
            bool allowed = false;
            //Bad manual search to support wildcard
            for (auto & element : AllowedDevices) {
              if (std::get<0>(element) == major) {
                if (std::get<1>(element) == minor || std::get<1>(element) == -1) {
                  if (std::get<2>(element) == dev_type) {
                    //Found it
                    allowed = true;
                    break;
                  }
                }
              }
            }
            //printf("  statx.stx_rdev_major: %lu\n", minor);
            //printf("  statx.stx_rdev_minor: %lu\n", major);
            if (!allowed) {
              //Not in our list
              printf("Forbidding open of device: %s\n", path);
              skip_and_finish(-ENOENT);
            }
          }
        }
        /*
        else {
          printf("  statx failed on %s: %d\n", path, (int)ctx->get_result());
        }
        */
      } else { 
        printf("Unable to read filename at %p\n", (void *) path_ptr);
        strcpy(path, "(error)");
      }
  } catch (const NoStackExn& e) {
    printf("[UntrustedRoot] Unable to allocate guest stack for analysis of opens\n");
  }
  yield_and_finish(ctx, ctx->pending_sc(), ExitStatus::SUCCESS);
}

//Check execve for LD_PRELOAD, for now just report it (could clear or block)
SyscallCoroutine filter_execve(SyscallCtx* ctx) {
  uint64_t envp, env_var_p;
  char env_var_str[PATH_MAX];

  for(envp = ctx->get_arg(2); envp; envp += sizeof(envp)) {
    if(yield_from(ga_memread, ctx, &env_var_p, envp, sizeof(env_var_p)) != -1) {
      if((void *)env_var_p == NULL) {
        break;
      }
      yield_from(ga_strncpy, ctx, env_var_str, env_var_p, sizeof(env_var_str));
      if(strncmp(env_var_str, "LD_PRELOAD=", 11) == 0) {
        printf("LD_PRELOAD found: %s\n", env_var_str);
      }
    } else {
      printf("Unable to read envp at %p\n", (void *) envp);
      break;
    }
  }
  yield_and_finish(ctx, ctx->pending_sc(), ExitStatus::SUCCESS);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_init_module] = deny;
  map[SYS_finit_module] = deny;
  map[SYS_delete_module] = deny;
  map[SYS_ptrace] = deny;
  map[SYS_open] = filter_open;
  map[SYS_openat] = filter_open;
  map[SYS_execve] = filter_execve;
  return true;
}
