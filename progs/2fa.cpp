#include <sys/syscall.h> // for SYS_
#include <iostream> // cout, cerr
#include <set>
#include "file_helpers.h" // read_file

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>

#include "hyde.h"
bool alive = true;
bool validated = false;

// When a process tries to switch it's UID/GID to 0, we output a code
// from the VMM and require the user to type it
// Unfortunately sudo ends up doing this in 2 processes, the grandparent
// and the grandchild. So we don't see the relationship between the two
// and have to prompt twice

// When a process requests a change, we store it's name, PID and the
// last timestamp when we got a response. We don't reprompt for ~5s
// in the same process. This prevents us from having to answer like 10x.
// If there's a process switch, we invalidate this simple cache
std::string pending_proc;
int pending_pid = -1;
time_t last_resp_time = 0; 

#if 0
      // Check the response
      if (input == "y" || input == "n") {
        validated = input == "y";
        last_resp_time = time(NULL);

        send(newsockfd, ok_msg.c_str(), ok_msg.size(), 0);
      } else {
        send(newsockfd, error_msg.c_str(), error_msg.size(), 0);
      }
    }
#endif


SyscCoroHelper stall_for_input(asid_details* details, int pid) {
  // If we've already validated this process, don't prompt again, just return same
  if (pid == pending_pid && time(NULL) - last_resp_time < 10) {
    // Don't prompt for the same process too often
    co_return (validated) ? 0 : -1;
  }

  while (1) {
    // Generate a 6 digit random value - print on VMM
    int code = rand() % 1000000;
    std::cout << "[2FA VMM] Process " << pending_proc << "(" << pid << ") tries to switch to root. Code: " << code << std::endl;

    const char prompt[] = "2FA: Enter code to allow process to run as root (or press enter to cancel): ";
    char response[100];
    // Print the prompt in the guest with yield_syscall, then get a response
    // from the user with yield_from. This is a bit hacky, but it works.
    yield_syscall(details, write, 1, prompt, sizeof(prompt));
    yield_syscall(details, read, 0, response, sizeof(response));
    // Can we make this read timeout?

    std::cout << "[2FA VMM] Got response: " << response << std::endl;
    int resp_code = atoi(response);

    if (resp_code == -1) {
      // No integer (e.g., empty) - bail
      std::cout << "[2FA VMM] - non-integer response, blocking process" << std::endl;
      break;
    }

    pending_pid = pid;
    last_resp_time = time(NULL);
    validated = (resp_code == code);

    if (validated) {
      std::cout << "[2FA VMM] Code accepted" << std::endl;
      break;
    }else {
      std::cout << "[2FA VMM] Invalid code - reprompting" << std::endl;
    }
  }

  co_return (validated) ? 0 : -1;
}

SyscCoro validate(asid_details* details) {
  // sudo is a suid binary, so it's running with an EUID of 0.
  // can we get the original value though?

  // Get arguments
  struct kvm_regs regs;
  get_regs_or_die(details, &regs);
  int real = get_arg(regs, RegIndex::ARG0); 
  int effective = get_arg(regs, RegIndex::ARG1); 
  int saved = get_arg(regs, RegIndex::ARG2); 

  int pid = yield_syscall0(details, getpid);

  // if we're switching anything to 0, we care
  if (real == 0 || effective == 0 || saved == 0) {
    // Maybe procfs to get original command?
    const char path[] = "/proc/self/cmdline";
    std::string buffer;
    int buffer_size = yield_from(read_file, details, path, &buffer);
    
    // Replace null bytes in buffer string with spaces up to buffer_size
    for (int i = 0; i < buffer_size; i++) {
      if (buffer[i] == '\0') buffer[i] = ' ';
    }

    pending_proc = buffer;

    // Request interactive user input. Have guest stall while we wait for input.
    //std::cout << "[2FA] Guest process " << buffer << " attempt changing " << 
    //  (get_arg(regs, RegIndex::CALLNO) == SYS_setresuid ? "uid" : "gid")
    //   << " to (" << real << ", " << effective << ", " << saved << ")" << std::endl;

    if (yield_from(stall_for_input, details, pid) == -1) {
      set_arg(regs, RegIndex::ARG0, -1u);
      set_arg(regs, RegIndex::ARG1, -1u);
      set_arg(regs, RegIndex::ARG2, -1u);
    }

  }

  co_yield *(details->orig_syscall);
  co_return ExitStatus::SUCCESS;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
/*
       int setresuid(uid_t ruid, uid_t euid, uid_t suid);
       int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
*/
  if (callno == SYS_setresuid || callno == SYS_setresgid) return &validate;
  return NULL;
}
