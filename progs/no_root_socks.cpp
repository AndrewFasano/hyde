#include <sys/socket.h> // for socket, listen, getsockname, getsockopt
#include <netinet/in.h> // for sockaddr_in
#include <arpa/inet.h> // for inet_ntoa
#include <iostream> // for cerr

#include "hyde.h"

SyscallCoroutine block_sock(syscall_context* details) {
  int sockfd = get_arg(details, RegIndex::ARG0);
  int euid = yield_syscall(details, geteuid);

  if (euid == 0) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    // get the local address associated with the socket
    if (yield_syscall(details, getsockname, sockfd, (struct sockaddr*)&addr, &len) < 0) {
      std::cerr << "Error: getsockname failed" << std::endl;
      co_yield *(details->orig_syscall);
      co_return ExitStatus::SINGLE_FAILURE;
    }

    // check if the local address is a loopback address
    if (addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
      std::cerr << "Error: Remote listening socket detected at " << inet_ntoa(addr.sin_addr) << std::endl;
      set_retval(details, -EADDRINUSE);
      co_return ExitStatus::SUCCESS;
    }
  }

  co_yield *(details->orig_syscall);
  co_return ExitStatus::SUCCESS;
}

create_coopt_t* should_coopt(void* cpu, long unsigned int callno, long unsigned int pc, unsigned int asid) {
  if (callno == SYS_listen)
    return &block_sock;
  return NULL;
}
