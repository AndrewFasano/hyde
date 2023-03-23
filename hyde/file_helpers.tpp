#include "hyde.h"
#include "file_helpers.h"
// .tpp file to keep implementation out of header,
// but to indicate that this is a template file, built as
// part of the programs that include it - see https://stackoverflow.com/a/495056.

template <std::size_t N, std::size_t M>
SyscCoroHelper read_symlink(asid_details* details, char(&inbuf)[N], char (&outbuf)[M]) {
  int rv = 0;
  int readlink_rv;

  // Use readlink to read symlink path - we can output as much as M bytes into outbuf
  readlink_rv = yield_syscall(details, readlink, inbuf, outbuf, M);
  co_return readlink_rv;
}

template <std::size_t N>
SyscCoroHelper fd_to_filename(asid_details* details, int fd, char (&outbuf)[N]) {

  char fd_path[128]; // FD can't be that big
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

  co_return yield_from(read_symlink, details, fd_path, outbuf);
}