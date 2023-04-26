#include <sys/syscall.h> // for SYS_
#include <iostream> // cout, cerr
#include <set>
#include "file_helpers.h" // read_file

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>

#include "hyde_sdk.h"
#include "hyde_common.h"

bool alive = true;
bool wait_for_oob_validate = false;
bool validated = false;

// When a process tries to switch it's UID/GID to 0, we ask via
// a TCP socket if we should allow it. This is a simple way to
// implement 2FA for root escalation.

// When a process requests a change, we store it's name, PID and the
// last timestamp when we got a response. We don't reprompt for ~5s
// in the same process. This prevents us from having to answer like 10x.
// If there's a process switch, we invalidate this simple cache
std::string pending_proc;
int pending_pid = -1;
time_t last_resp_time = 0; 

SyscCoroHelper stall_for_input(SyscallCtx* details, int pid) {
  // Block until user input. We should inject sleeps in the guest but eh.
  if (pid == pending_pid && time(NULL) - last_resp_time < 5) {
    // Don't prompt for the same process too often
    co_return (validated) ? 0 : -1;
  }

  wait_for_oob_validate = true;
  pending_pid = pid;

  int stall_count = 0;

  #define WAIT_NSEC 100000000 // Set the desired wait interval in nanoseconds, e.g., 100,000,000 ns (100 ms)

  while (wait_for_oob_validate) {

    if (stall_count++ > (10 * 1e9 / WAIT_NSEC)) { // Calculate the number of iterations for 10 seconds
      std::cout << "No user input for " << pending_proc << " (" << pending_pid << ") after 10s, blocking..." << std::endl;
      wait_for_oob_validate = false;
      last_resp_time = time(NULL);
      co_return -1;
    }
    struct timespec ts = {0, WAIT_NSEC};
    yield_syscall(details, nanosleep, &ts);
  }

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

    // Request interactive user input. Have guest stall while we wait for input.
    //std::cout << "[2FA] Guest process " << buffer << " attempt changing " << 
    //  (get_arg(regs, RegIndex::CALLNO) == SYS_setresuid ? "uid" : "gid")
    //   << " to (" << real << ", " << effective << ", " << saved << ")" << std::endl;

    if (yield_from(stall_for_input, details, pid) == -1) {
      std::cout << "BLOCKING " << pending_proc << " (" << pid << ")" << std::endl;
      details->get_orig_syscall()->set_arg(0, -1u);
      details->get_orig_syscall()->set_arg(1, -1u);
      details->get_orig_syscall()->set_arg(2, -1u);
    }
  }

  co_yield *(details->get_orig_syscall());
  co_return ExitStatus::SUCCESS;
}

// Function to bind and listen on a socket for TCP connections
int bind_and_listen(int port) {
  int sockfd;
  struct sockaddr_in serv_addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    printf("ERROR opening socket %d\n", sockfd);
    return -1;
  }

  // Now bind the host address using bind() call.
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(port);

  // Next, we bind the socket to the address and port number
  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
    printf("ERROR on binding %d\n", sockfd);
    return -1;
  }

  // Now start listening for the clients, here process will
  // go in sleep mode and will wait for the incoming connection
  listen(sockfd, 5);
  return sockfd;
}

void handle_input(int sockfd) {
  std::string input;
  std::string error_msg = "Invalid input. Please enter 'y' or 'n'.\n";
  std::string ok_msg = "Got it\n";
  char prompt[1024];

  const int buffer_size = 256;
  char buffer[buffer_size];


  while (alive) {

    int newsockfd = accept(sockfd, (struct sockaddr *) NULL, NULL);
    if (newsockfd < 0) {
      printf("ERROR on accept %d\n", newsockfd);
      close(newsockfd);
      continue;
    }

    while (alive) {

      // Wait until guest is waiting for input
      while (!wait_for_oob_validate) sleep(1);

      snprintf(prompt, sizeof(prompt), "Guest process %s (%d) attempts to sudo. Allow? y/n: ", pending_proc.c_str(), pending_pid);

      ssize_t sent_bytes = send(newsockfd, prompt, strlen(prompt), 0);
      assert(sent_bytes > 0);

      ssize_t received_bytes = recv(newsockfd, buffer, buffer_size - 1, 0);
      assert(received_bytes > 0);

      buffer[received_bytes] = '\0';  // Add a null terminator
      input = std::string(buffer).substr(0, received_bytes - 1); // Remove newline

      // Check the response
      if (input == "y" || input == "n") {
        validated = input == "y";
        last_resp_time = time(NULL);

        wait_for_oob_validate = false;
        send(newsockfd, ok_msg.c_str(), ok_msg.size(), 0);
      } else {
        send(newsockfd, error_msg.c_str(), error_msg.size(), 0);
      }
    }

    close(newsockfd);
  }
}


std::thread *t = NULL;
void __attribute__ ((destructor)) teardown(void) {
  alive = false;
  if (t != NULL && t->joinable()) {
    t->join();
  }
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  srand(time(NULL));
  map[SYS_setresuid] = validate;
  map[SYS_setresgid] = validate;

    // Create a listening socket and launch a thread to handle connections
    int port = 4444;
    if (getenv("TWOFA_PORT") != NULL && atoi(getenv("TWOFA_PORT")) != 0) {
      port = atoi(getenv("TWOFA_PORT"));
    } else {
      printf("WARN: environ var TWOFA_PORT not set using default %d\n", port);
    }
    int sockfd = bind_and_listen(port);
    if (sockfd < 0) return false;

    std::thread t1(handle_input, sockfd);
    // We have to detach the thread, otherwise it will think it was abandoned and terminate
    t1.detach();

    // But we need to keep a reference to it so we can join it on shutdown
    t = &t1;
    return true;
}