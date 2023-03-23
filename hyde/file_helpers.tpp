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

template <std::size_t N>
SyscCoroHelper read_file(asid_details* details, const char (&fname)[N], std::string *outbuf) {
    outbuf->erase();

    int fd = yield_syscall(details, open, fname, O_RDONLY, 0);
    if (fd < 0) {
      co_return fd;
    }

    int total_bytes_read = 0;
    char buffer[1024];
    int bytes_read;
    do {
        bytes_read = yield_syscall(details, read, fd, &buffer, sizeof(buffer));
        total_bytes_read += bytes_read;
        outbuf->append(buffer, bytes_read); // Is this okay with a read of 0 bytes?jI
    } while (bytes_read > 0);
    co_return total_bytes_read;
}

template <std::size_t N>
SyscCoroHelper fd_to_contents(asid_details* details, int fd, std::string &outbuf) {

  char fd_path[128]; // FD can't be that big
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
  char filename[256];

  int symlink_rv = yield_from(read_symlink, details, fd_path, filename);
  if (symlink_rv < 0)
    co_return symlink_rv;

  co_return yield_from(read_file, details, filename, outbuf);
}