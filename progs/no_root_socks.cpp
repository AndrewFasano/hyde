#include <sys/socket.h> // for socket, listen, getsockname, getsockopt
#include <netinet/in.h> // for sockaddr_in
#include <arpa/inet.h> // for inet_ntoa
#include <iostream> // for cerr
#include "hyde_sdk.h"

SyscallCoroutine block_sock(SyscallCtx* ctx) {
  int sockfd = ctx->get_arg(0);
  int euid = yield_syscall(ctx, geteuid);

  if (euid == 0) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    // get the local address associated with the socket
    if (yield_syscall(ctx, getsockname, sockfd, (struct sockaddr*)&addr, &len) < 0) {
      std::cerr << "Error: getsockname failed" << std::endl;
      co_yield *(ctx->get_orig_syscall());
      co_return ExitStatus::SINGLE_FAILURE;
    }

    // check if the local address is a loopback address
    if (addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
      std::cerr << "Error: Remote listening socket detected at " << inet_ntoa(addr.sin_addr) << std::endl;
      ctx->set_nop(-EADDRINUSE); // Instead of running syscall we'll just return this
    }
  }

  co_yield *(ctx->get_orig_syscall());
  co_return ExitStatus::SUCCESS;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[SYS_listen] = block_sock;
  return true;
}