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

static bool finished = false;
static bool done = false;
static bool did_fork = false;
static bool found_child = false;
static bool tracing_target = false;
static int pending_parent_pid = -1;
static std::mutex running_in_root_proc;

static bool pending_fork = false;
static int parent_pid = -1;

static hsyscall pending_sc;

char pending_command[1] = {0}; // 'g' or 'm'
uint64_t pending_mem_addr = 0;
uint64_t pending_mem_size = 0;
char* pending_mem_buf = NULL;

user_regs_struct gregs; // Guest registers. Populated for g command


//  uint64_t for each of 'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RIP'
// Then uint32_t for 'EFLAGS', 'CS', 'SS', 'DS', 'ES', 'FS', 'GS'
struct regs_struct {
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t rbp;
  uint64_t rsp;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rip;
  uint32_t eflags;
  uint32_t cs;
  uint32_t ss;
  uint32_t ds;
  uint32_t es;
  uint32_t fs;
  uint32_t gs;
};

SyscCoroHelper drive_child(asid_details* details) {
  signed long wait_rv;

  // We drive the child process we created, making it attach to the target process with ptrace,
  // then we allow the target process to run up to the next syscall.

  // First allocate scratch buffer
  uint64_t guest_buf = yield_syscall(details, mmap, NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

  // Next, request to attach to our target process.
  // Yield a syscall to attach with ptrace to target_pid
  // This will cause the target process to stop (SIGSTOP) soon, and we'll see it with waitid
  int ptrace_rv = yield_syscall(details, ptrace, PTRACE_ATTACH, target_pid, 0, 0);
  //printf("Ptrace attach to %d returns %d\n", target_pid, ptrace_rv);

  // Wait until the target is stopped
  do {
    // We'll see -EINTR a lot (telling us to retry) so let's handle that
    wait_rv = yield_syscall(details, waitid, P_PID, target_pid, (long unsigned)guest_buf, WSTOPPED, 0);
    //printf("Waitid returns %ld\n", wait_rv);
  } while (wait_rv == -EINTR);

  if (wait_rv < 0) {
    printf("FATAL? wait failed: %ld\n", wait_rv);
    assert(0);
  }
  tracing_target = true;

  // "Debug loop" - either we have a command pending or we sleep (and make the debugee stall)
  // Right now we have no way to specify commands, so we just run between syscalls

  while (true) {
    // We have a chance to run a command in our guest process that will
    // control the debugee. Should we do anything or just sleep?

    // If we have a command, process it, then check if we have another
    printf("Pending_command is %c\n", pending_command[0]);

    if (pending_command[0] == 'g') {
      long int greg_rv = (long int)yield_syscall(details, ptrace, PTRACE_GETREGS, target_pid, 0, (long unsigned)guest_buf);
      if (yield_from(ga_memread, details, &gregs, guest_buf, sizeof(user_regs_struct)) != 0) {
        printf("Failed to read gregs struct from guest memory\n");
        assert(0);
      }
      pending_command[0] = (char)0;
    } else if (pending_command[0] == 'm') {
      //printf("Read memory from %lx, size %lx\n", pending_mem_addr, pending_mem_size);
      // Read raw bytes into raw_buf, then convert to ascii in pending_mem_buf
      char* raw_buf = (char*)malloc(pending_mem_size*2);
      if (yield_from(ga_memread, details, raw_buf, pending_mem_addr, pending_mem_size) != 0) {
        printf("Failed to read memory from guest memory\n");
        free(raw_buf);
        pending_mem_buf = NULL;
      } else {
        // Successfully read guest memory, convert it to ascii in pending_mem_buf
        pending_mem_buf = (char*)malloc(pending_mem_size*2);
        for (int i = 0; i < pending_mem_size; i++) {
          sprintf(pending_mem_buf + i*2, "%02x", (unsigned char)raw_buf[i]);
        }
      }

      // Indicate that we're done
      pending_command[0] = (char)0;
    } else if (pending_command[0] == (char)0) {
      // Do a sleep for 01s
      timespec req_h = {
        .tv_sec = 1,
        .tv_nsec = 0,
      };
      timespec remain;
      yield_syscall(details, nanosleep, &req_h, &remain);
    } else {
      printf("Unsupported pending command: %c. IGNORING (TODO)\n", pending_command[0]);
      pending_command[0] = (char)0;
    }

    // Resume debugee execution until it next stops XXX is this just continue?
    #if 0
    do {
      wait_rv = yield_syscall(details, waitid, P_PID, target_pid, (long unsigned)guest_buf, WSTOPPED|WEXITED, 0);
      //printf("Waitid2 returns %ld\n", wait_rv);
    } while (wait_rv == -EINTR);

    if (wait_rv < 0) {
      printf("Bad wait_rv: %ld\n", wait_rv);
      assert(0);
    }

    int tmp_peek = yield_syscall(details, ptrace, PTRACE_PEEKUSER, target_pid, 0, (long unsigned)guest_buf);

    //printf("Peek returns %d\n", tmp_peek);

    if (tmp_peek == -ESRCH) {
      printf("Debuggee exited\n");
      break;
    }
  #endif
  }

  // All done - set finished and kill this process - note we won't continue execution
  finished = true;
  yield_syscall(details, exit, 0);
  assert(0 && "Unreachable");
}

SyscCoro find_child_proc(asid_details* details) {

    int pid = yield_syscall0(details, getpid);
    int ppid = yield_syscall0(details, getppid);
    int tid = yield_syscall0(details, gettid);

    if (ppid == pending_parent_pid) {
        printf("Found child: %d %d parent is %d\n", pid, tid, ppid);
        found_child = true;

        if (yield_from(drive_child, details) != 0) { // No return on success
          co_return ExitStatus::SINGLE_FAILURE;
      }
    }

    co_yield *(details->orig_syscall);
    co_return ExitStatus::SUCCESS;
}

SyscCoro fork_root_proc(asid_details* details) {
    int rv = 0;
    int fd;
    int pid;

    if (!done) {
      if (yield_syscall0(details, geteuid) == 0) {
        if (!running_in_root_proc.try_lock()) {
            // Lock unavailable, bail on this coopter
            // Note we don't want to wait since that would block a guest proc
            rv = -1;
        } else if (!done) {
          pid = yield_syscall0(details, getpid);
          pending_parent_pid = pid;

          did_fork = true;
          yield_syscall0(details, fork);

          done=true;
          running_in_root_proc.unlock();
        }
      }
    }
    co_yield *(details->orig_syscall);
    co_return ExitStatus::SUCCESS;
}

SyscCoro indicate_success(asid_details* details) {
    // Simple coro to change nothing, but indicate that we're done
    // This runs after we execve'd and abandoned that child
    co_yield *(details->orig_syscall);
    co_return ExitStatus::FINISHED;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

    if (did_fork && !found_child) {
        return &find_child_proc;
    }

    if (!done)
        return &fork_root_proc;

    if (finished)
        return &indicate_success;

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

  //printf("Generated response is %s\n", outbuffer);

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

  if (!has_checksum and strlen(buffer)) {
    if (strlen(buffer) > 1) printf("Ignoring %s since it has no checksum\n", buffer);
    return 0;
  }

  // We got here which means our checksum validated and packet is in packet
  //printf("Valid packet: %s\n", packet);

  // Handle the packet - read the command and arguments
  char command[256] = {0};
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

  printf("GOT COMMAND: %s with args %s\n", command, argp);

  // Single-letter commands we support
  //char * single_cmds = { "PpcsMmHXGt" };
  //char cmd[2] = { command[0], 0 };

  if (strlen(command) == 0) {
    // Ignore empty packet?
    response[0] = 0;
    return 0;
  }


  switch (command[0]) {
    case 'q': {
      if (strcmp(command, "qSupported") == 0) {
        snprintf(response, PACKET_SIZE, "PacketSize=%x,qXfer:exec-file:read,multiprocess+", PACKET_SIZE);
      } else if (strcmp(command, "qTStatus") == 0) {
        // Respond with nothing
      } else if (strcmp(command, "qfThreadInfo") == 0) {
        // Respond with target PID
        sprintf(response, "%d", target_pid);
      } else if (strcmp(command, "qAttached") == 0) {
        // TODO: needs updating if we support multiple processes
        sprintf(response, "%d", 0);

      } else {
        printf("TODO:  unsupported q command: %s\n", command);
      }
      break;
    }

    case 'v':  {
      // v things - make sure we leave vMustReplyEmpty empty and that should be the default for unsupported packets
      if (strcmp(command, "vCont") == 0) {
        // TODO
      } else if (strcmp(command, "vMustReplyEmpty") == 0) {
        // Nothing to reply with :)
      }else {
        printf("Unsupported v cmd: %s\n", command);
      }
      break;
    }
    case 'H':
      // Set thread - TODO: would this allow us to change processes?
      // For now we don't really support it
      //printf("Set thread %d\n", strtol(argp, NULL, 16));
        sprintf(response, "OK");
      break;

    case '?':
      // Last signal
      // LIE: always say it's sigstop, tell the guest the PID
      //sprintf(response, "S05");
      sprintf(response, "T05 swbreak;thread:%d;", target_pid);
      break;

    case 'm': {
      // Read memory. Return as hex or indicate error with E01
      // Extract argument: from 2nd character to coma, then to end

      // Replace comma with null
      argp  = strchr(command, ',');
      *argp = 0;
      argp++;

      pending_mem_addr = strtol(command+1, NULL, 16);
      pending_mem_size = strtol(argp, NULL, 16);

      printf("Set M command\n");
      pending_command[0] = 'm';
      while (pending_command[0] != 0) {
        // Stall until we have memory data from other thread
        usleep(100000000); // Quick sleep
      }

      printf("Finished with M command\n");

      if (pending_mem_buf == NULL) {
        // Error - even after waiting for command, buffer is null
        sprintf(response, "E01");
      }else {
        // Success
        printf("Finished waiting for m command, now have buffer with %s", pending_mem_buf);
        sprintf(response, "%s", pending_mem_buf);
        printf("Pending_mem_buf: %s\n", pending_mem_buf);
        free(pending_mem_buf);
      }
      break;
    }

    case 'g': {
      // Read registers. This is the first thing that will require sync communication
      assert(pending_command[0] == 0);
      pending_command[0] = 'g';

      while (pending_command[0] != 0) {
        // Stall until we have register data from other thread
        usleep(100000000);
      }
      printf("Finished with g command\n");

      // We have data in our user_regs_struct gregs but now
      // we need to populate a regs_struct regs with that data
      regs_struct regs = {
        .rax = gregs.rax,
        .rbx = gregs.rbx,
        .rcx = gregs.rcx,
        .rdx = gregs.rdx,
        .rsi = gregs.rsi,
        .rdi = gregs.rdi,
        .rbp = gregs.rbp,
        .rsp = gregs.rsp,
        .r8 = gregs.r8,
        .r9 = gregs.r9,
        .r10 = gregs.r10,
        .r11 = gregs.r11,
        .r12 = gregs.r12,
        .r13 = gregs.r13,
        .r14 = gregs.r14,
        .r15 = gregs.r15,
        .rip = gregs.rip,
        .eflags = static_cast<uint32_t>(gregs.eflags),
      };

      // TODO that should all be big endian, I think?

      // Ascii representation of regs
      char* responsep = response;
      for (int i=0; i<sizeof(regs_struct); i++) {
        sprintf(responsep, "%02x", ((uint8_t*)&regs)[i]);
        responsep += 2;
      } 
      break;
    } // End of g case


  #if 0
    case 'P': {
      // Write a register
      int reg = strtol(&command[1], NULL, 16);
      printf("Writing register %d\n", reg);
      break;
    }
    case 'c':
      // Continue
      printf("Continue\n");
      break;
    case 's':
      // Step
      printf("Step %d\n", strtol(argp, NULL, 16));
      break;
    case 'M':
      // Write memory
      printf("Write memory %d\n", strtol(argp, NULL, 16));
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
#endif
    default:
      printf("Unsupported command: %s\n", command);
  }

  //printf("Responding with %zd bytes: %s\n", strlen(response), response);

  char* scratch = strdup(response);
  int rv= generate_response(scratch, response);
  free(scratch);
  return rv;
}

void handle_connections(int sockfd) {
  while (alive) {
    // Accept actual connection from the client
    int newsockfd = accept(sockfd, (struct sockaddr *) NULL, NULL);
    if (newsockfd < 0) {
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

      // We got a message, it's in buffer. our response might be as big as an ascii
      // buffer or all registers, but no bigger(?)
      char response[sizeof(regs_struct)*2] = {0};
      int response_size = handle_message(buffer, n, (char*)response);

      printf("Sending %d byte response %s\n", response_size, response); 

      // Write a response to the client
      //printf("Sending %d byte response: %s\n", response_size, response);
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
    int port = 1234;
    if (getenv("HP_PORT") != NULL && atoi(getenv("HP_PORT")) != 0) {
      port = atoi(getenv("HP_PORT"));
    } else {
      printf("WARN: environ var HP_PORT not set using default %d\n", port);
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