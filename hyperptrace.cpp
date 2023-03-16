#include <asm/unistd.h> // Syscall numbers
#include <sys/mman.h> // for mmap flags
#include <stdio.h>
#include <time.h> // nanosleep
#include <sys/wait.h> // for waitid
#include <errno.h> // EINTR
#include <sys/ptrace.h> // PTRACE_
#include <sys/user.h> // GETREGS layout for x86_64
#include <mutex>
#include <string.h>


// Headers for webserver
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>

#include "hyde.h"


int target_pid = 1137; // TODO - bash

static bool done = false;
static bool did_fork = false;
static bool found_child = false;
static bool tracing_target = false;
static int pending_parent_pid = -1;
static std::mutex running_in_root_proc;

static bool pending_fork = false;
static int parent_pid = -1;

static hsyscall pending_sc;

SyscCoro drive_child(asid_details* details) {
  signed long wait_rv;

  // We drive the child process we created, making it attach to the target process with ptrace,
  // then we allow the target process to run up to the next syscall.

  // First allocate scratch buffer
  ga* guest_buf = (ga*)yield_syscall(details, __NR_mmap, NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

  // Next, request to attach to our target process.
  // Yield a syscall to attach with ptrace to target_pid
  // This will cause the target process to stop (SIGSTOP) soon, and we'll see it with waitid
  int ptrace_rv = yield_syscall(details, __NR_ptrace, PTRACE_ATTACH, target_pid, 0, 0);
  //printf("Ptrace attach to %d returns %d\n", target_pid, ptrace_rv);

  // Wait until the target is stopped
  do {
    // We'll see -EINTR a lot (telling us to retry) so let's handle that
    wait_rv = yield_syscall(details, __NR_waitid, P_PID, target_pid, (long unsigned)guest_buf, WSTOPPED, 0);
    //printf("Waitid returns %ld\n", wait_rv);
  } while (wait_rv == -EINTR);

  if (wait_rv < 0) {
    printf("FATAL? wait failed: %ld\n", wait_rv);
    assert(0);
  }
  tracing_target = true;

  // "Debug loop" - either we have a command pending or we sleep (and make the debugee stall)
  // Right now we have no way to specify commands, so we just run between syscalls

  int ctr = 0;
  while (true) {
    ctr++;
    if (ctr % 2 == 1) { // Log on return, callno + retval
      // First get registers into guest memory
      long int greg_rv = (long int)yield_syscall(details, __NR_ptrace, PTRACE_GETREGS, target_pid, 0, (long unsigned)guest_buf);
      //printf("Getregs returns %ld\n", greg_rv);

      // Read registers out of guest memory
      user_regs_struct gregs;
      if (yield_from(ga_memread, details, &gregs, guest_buf, sizeof(user_regs_struct)) != 0) {
        printf("Failed to read gregs struct from guest memory\n");
        assert(0);
      }
      printf("%2d syscall: %lld  => %llx\n", ctr/2, gregs.orig_rax, gregs.rax); // Maybe we want orig_rax?
    }

    // Run the ptrace(PTRACE_SYSCALL, target) in order to continue the target process until the next syscall
    //printf("Continue target...\n");
    int pt_sc_rv = yield_syscall(details, __NR_ptrace, PTRACE_SYSCALL, target_pid, 1, 0);
    //printf("PTRACE_SYSCALL returns %d\n", pt_sc_rv);

    do {
      wait_rv = yield_syscall(details, __NR_waitid, P_PID, target_pid, (long unsigned)guest_buf, WSTOPPED|WEXITED, 0);
      //printf("Waitid2 returns %ld\n", wait_rv);
    } while (wait_rv == -EINTR);

    //printf("Wait RV returned %ld\n", wait_rv);

    if (wait_rv < 0) {
      printf("Bad wait_rv: %ld\n", wait_rv);
      assert(0);
    }

    int tmp_peek = yield_syscall(details, __NR_ptrace, PTRACE_PEEKUSER, target_pid, 0, (long unsigned)guest_buf);

    //printf("Peek returns %d\n", tmp_peek);

    if (tmp_peek == -ESRCH) {
      printf("Debuggee exited\n");
      break;
    }
    
    continue;
  #if 0

    // sleep no-op
    timespec req_h = {
      .tv_sec = 1,
      .tv_nsec = 0
    };
    // Write req_h into guest memory at guest_buf
    if (yield_from(ga_memwrite, details, guest_buf, &req_h, sizeof(timespec)) != 0) {
      printf("Failed to write timespec to guest memory\n");
      assert(0);
    }

    __u64 req_guest = (__u64)guest_buf;
    __u64 rem_guest = (__u64)guest_buf + sizeof(timespec);

    yield_syscall(details, __NR_nanosleep, guest_buf, (ga*)(uint_64t)guest_buf + sizeof(timespec));
#endif
  }

  // Finish? XXX want core platform to discard this asid? - should inejct exit
  yield_syscall(details, __NR_exit, 0);
  co_return 0;
}

SyscCoro find_child_proc(asid_details* details) {

    int pid = yield_syscall(details, __NR_getpid);
    int ppid = yield_syscall(details, __NR_getppid);
    int tid = yield_syscall(details, __NR_gettid);

    if (ppid == pending_parent_pid) {
        printf("Found child: %d %d parent is %d\n", pid, tid, ppid);
        found_child = true;

        yield_from(drive_child, details);
        //assert(0 && "Unreachable");
        co_return 0;
    }

    co_yield *(details->orig_syscall);
    co_return 0;
}

SyscCoro fork_root_proc(asid_details* details) {
    int rv = 0;
    int fd;
    int pid;

    if (!done) {
      if (yield_syscall(details, __NR_geteuid)) {
          rv = -1;
      }else {
        if (!running_in_root_proc.try_lock()) {
            // Lock unavailable, bail on this coopter
            // Note we don't want to wait since that would block a guest proc
            rv = -1;
        } else if (!done) {
          pid = yield_syscall(details, __NR_getpid);
          pending_parent_pid = pid;

          did_fork = true;
          yield_syscall(details, __NR_fork);

          done=true;
          running_in_root_proc.unlock();
        }
      }
    }

    co_yield *(details->orig_syscall); // noreturn
    co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

    if (did_fork && !found_child) {
        return &find_child_proc;
    }

    if (!done)
        return &fork_root_proc;

  return NULL;
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

bool alive = true;
#define PACKET_SIZE 1000

int generate_response(char* inbuffer, char*outbuffer) {
  // Format a response for gdb
  // $<data>#<checksum> where data has all # and } escaped
  // and checksum is the sum of all bytes in data

  uint8_t checksum = 0;
  char* outp = outbuffer;
  char* inp = inbuffer;

  *outp++ = '$';

  for (int i=0; i<strlen(inbuffer); i++) {
    checksum += inbuffer[i];
    if (inbuffer[i] == '}') {
      // Escape
      *outp++ = '}';
      *outp++ = '}';
    } else if (inbuffer[i] == '#') {
      // Escape
      *outp++ = '}';
      *outp++ = '#';
    } else {
      *outp++ = inbuffer[i];
    }
  }

  // Add checksum to output
  *outp++ = '#';
  sprintf(outp, "%02x", checksum);

  printf("Generated response is %s\n", outbuffer);

  return strlen(outbuffer);
}

int handle_message(char* buffer, size_t buffer_size, char* response) {
  buffer[buffer_size] = 0;
  //printf("Got message %s\n", buffer);
  uint8_t checksum = 0;

  // Scratch to write (unescaped, unchecksummed response)
  bool has_checksum = false;
  char* packet;

  bool gdbcommand = false;
  // parse GDB remote serial protocol messages and checksum
  for (int i=0; i<buffer_size; i++) {
    if (gdbcommand) {
      if (buffer[i] == '#') {
        // End of message
        has_checksum = true; // Note it could still be wrong

        buffer[i] = 0; // Null terminate normal message
        buffer[i+3] = 0; // and after checksum
        uint8_t given_checksum = strtol(&buffer[i+1], NULL, 16);
        if (given_checksum != checksum) {
          // checksum is wrong - nack
          printf("Bad checksum: %d vs %d\n", given_checksum, checksum);
          response[0] = '-';
          return 1;
        }
        break;
      } else {
        // update checksum
        checksum += buffer[i]; // Overflows
      }

    } else if (buffer[i] == '$') {
      // start of message
      gdbcommand = true;
      packet = &buffer[i+1];

    } else if (buffer[i] == 0x03) {
      // ctrl-c - terminate
      return -1;
    }
  }

  if (!has_checksum) {
    printf("Ignoring %s since it has no checksum\n", buffer);
    return 0;
  }

  // We got here which means our checksum validated and packet is in packet
  //printf("Valid packet: %s\n", packet);

  // Handle the packet - read the command and arguments
  char command[256];
  char* commandp = command;
  char* argp = NULL;
  for (int i=0; i<strlen(packet); i++) {
    if (packet[i] == ':') {
      // End of command, start of arguments
      *commandp = 0;
      argp = &packet[i+1];
      break;
    } else {
      *commandp++ = packet[i];
    }
  }

  printf("Command: %s\n", command);
  printf("Args: %s\n", argp);

  // Single-letter commands we support
  char * single_cmds = { "PpcsMmHXGt" };
  char cmd[2] = { command[0], 0 };

  if (strstr(single_cmds, cmd) != NULL) {
    // Cool - it's one of these single-character commands
    switch(command[0]) {
      case 'P':
        // Write a register
        int reg = strtol(&command[1], NULL, 16);
        printf("Writing register %d\n", reg);
        break;
      case 'c':
        // Continue
        printf("Continue\n");
        break;
      case 's':
        // Step
        printf("Step %d\n", strtol(argp, NULL, 16));
        break;
      case 'm':
        // Read memory
        printf("Read memory %d\n", strtol(argp, NULL, 16));
        break;
      case 'M':
        // Write memory
        printf("Write memory %d\n", strtol(argp, NULL, 16));
        break;
      case 'H':
        // Set thread
        printf("Set thread %d\n", strtol(argp, NULL, 16));
        break;
      case 'X':
        // Write memory
        printf("Write memory %d\n", strtol(argp, NULL, 16));
        break;
      case 'G':
        // Write registers
        printf("Write registers %s %d\n", argp, strlen(argp));
        break;
      case 't':
        // Is thread alive?
        printf("Is thread alive %d\n", strtol(argp, NULL, 16));
        break;
    }
  }else {
    // ... other commands - multi-character
  }

  // TODO merge with above
  // Handle the command
  if (strcmp(command, "qSupported") == 0) {
    // We support the vCont command, I guess
    sprintf(response, "PacketSize=%d;multiprocess+", PACKET_SIZE);
  } else if (command[1] == 'v') {
    // v things - make sure we leave vMustReplyEmpty empty and that should be the default for unsupported packets

  } else if (strcmp(command, "vCont") == 0) {
    // TODO
  }

  printf("Response is %s\n", response);

  return generate_response(packet, response);
}

void handle_connections(int sockfd) {
  while (alive) {
    // Accept actual connection from the client
    int newsockfd = accept(sockfd, (struct sockaddr *) NULL, NULL);
    if (newsockfd < 0) {k
      printf("ERROR on accept %d\n", newsockfd);
      close(newsockfd);
      continue;
    }

    // If connection is established then start communicating
    while (alive) {
      // We accepted a connection, now read the message
      char buffer[PACKET_SIZE];
      bzero(buffer, PACKET_SIZE);
      int n = read(newsockfd, buffer, PACKET_SIZE);
      if (n < 0) {
        printf("ERROR reading from socket %d\n", n);
        close(newsockfd);
        break;
      }

      printf("Got buffer: %s\n", buffer);

      // Always ack
      char plus[2] = "+";
     int write_n = write(newsockfd, plus, 1);
      if (write_n < 0) {
        printf("ERROR writing to socket %d\n", n);
        close(newsockfd);
        break;
      }

      // We got a message, it's in buffer
      char response[256] = {0};
      int response_size = handle_message(buffer, n, (char*)response);

      // Write a response to the client
      printf("Sending %d byte response: %s\n", response_size, response);
      n = write(newsockfd, response, response_size);
      if (n < 0) {
        printf("ERROR writing to socket %d\n", n);
        close(newsockfd);
        break;
      }
    }
    printf("Finished processing requests from a client\n");
    close(newsockfd);
  }
}

std::thread *t = NULL;
void __attribute__ ((constructor)) setup(void) {
    printf("Started HyperPtrace\n");

    // Create a listening socket and launch a thread to handle connections
    int port = atoi(getenv("HP_PORT"));
    if (port == 0) {
      printf("WARN: environ var HP_PORT not set using default 1234\n");
      port = 1234;
    }
    int sockfd = bind_and_listen(port);
    std::thread t1(handle_connections, sockfd);
    // We have to detach the thread, otherwise it will think it was abandoned and terminate
    t1.detach();

    // But we need to keep a reference to it so we can join it on shutdown
    t = &t1;
}

void __attribute__ ((destructor)) teardown(void) {
  alive = false;
}