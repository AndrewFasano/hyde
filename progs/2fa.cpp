#include <sys/syscall.h> // for SYS_
#include <iostream> // cout, cerr
#include <set>
#include "file_helpers.h" // read_file

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>

#include "hyde_common.h"
bool alive = true;
bool validated = false;

std::mutex mtx;

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


SyscCoroHelper stall_for_input(SyscallCtx* details, int pid) {
  // If we've already validated this process, don't prompt again, just return same
  if (pid == pending_pid && time(NULL) - last_resp_time < 10) {
    // Don't prompt for the same process too often
    co_return (validated) ? 0 : -1;
  }

  // If two processes are concurrently asking to escalate, we can only prompt a user for one at a time
  while (!mtx.try_lock()) {
    struct timespec ts;
    ts.tv_sec = 1;
    ts.tv_nsec = 0; //100000000; // 100ms
    printf("Stall %d for 1s while waiting on user to answer another prompt\n", pid);
    yield_syscall(details, nanosleep, &ts);
  }

  // We need STDIN/STDOUT handles - might not have them so we get our own??
  int g_stdin = yield_syscall(details, open, "/dev/stdin", O_RDONLY);
  int g_stdout = yield_syscall(details, open, "/dev/stdout", O_WRONLY);


  while (1) {
    // generate a 6 digit random value - print on VMM
    int code = rand() % 1000000;
    std::cout << "[2FA VMM] Process " << pending_proc << "(" << pid << ") tries to switch to root. Code: " << code << std::endl;

    const char prompt[] = "2FA: Enter code to allow process to run as root (or press enter to cancel): ";
    char response[100] = {0};
    // Print the prompt in the guest with yield_syscall, then get a response
    // from the user with yield_from. This is a bit hacky, but it works.
    int bytes_written = yield_syscall(details, write, g_stdout, prompt, sizeof(prompt));
    int bytes_read = yield_syscall(details, read, g_stdin, response, sizeof(response)); // Can we make this read timeout?
    if (bytes_read > 0 && bytes_read < sizeof(response)) {
      response[bytes_read] = '\0';
    }

    char outbuf[100] = {0};
    char inbuf[100] = {0};

    assert(bytes_read != sizeof(response)); // XXX Testing - this is probably a bug?

    int resp_code = atoi(response);

    if (resp_code == -1) {
      // No integer (e.g., empty) - bail
      std::cout << "[2FA VMM] - non-integer response, blocking process" << std::endl;
      break;
    }

    pending_pid = pid;
    last_resp_time = time(NULL);
    validated = (resp_code == code);
    bool cancel = (bytes_read == 0);

    if (validated) {
      std::cout << "[2FA VMM] Code accepted" << std::endl;
      break;
    } else if (cancel) {
      std::cout << "[2FA VMM] Canceling" << std::endl;
      validated = false;
      break;
    } else {
      std::cout << "[2FA VMM] Invalid code. Got: " << response << " =>" << resp_code << " expected; " << code << ". reprompting" << std::endl;
    }
  }

  mtx.unlock();

  yield_syscall(details, close, g_stdin);
  yield_syscall(details, close, g_stdout);

  co_return (validated) ? 0 : -1;
}

SyscallCoroutine validate(SyscallCtx* details) {
  // sudo is a suid binary, so it's running with an EUID of 0.
  // can we get the original value though?

  // Get arguments
  int real = details->get_arg(0);
  int effective = details->get_arg(1);
  int saved = details->get_arg(2);

  int pid = yield_syscall(details, getpid);

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

    if (yield_from(stall_for_input, details, pid) == -1) {
      details->get_orig_syscall()->set_arg(0, -1u);
      details->get_orig_syscall()->set_arg(1, -1u);
      details->get_orig_syscall()->set_arg(2, -1u);
    }
  }

  yield_and_finish(details, *(details->get_orig_syscall()), ExitStatus::SUCCESS);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  srand(time(NULL));
  map[SYS_setresuid] = validate;
  map[SYS_setresgid] = validate;
  return true;
}