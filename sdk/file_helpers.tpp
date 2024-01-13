#ifndef FILE_HELPERS_TPP_IMPL
#define FILE_HELPERS_TPP_IMPL

#include "file_helpers.h"
// .tpp file to keep implementation out of header,
// but to indicate that this is a template file, built as
// part of the programs that include it - see https://stackoverflow.com/a/495056.

template <std::size_t N, std::size_t M>
SyscCoroHelper read_symlink(SyscallCtx* details, char(&inbuf)[N], char (&outbuf)[M]) {
  int rv = 0;
  int readlink_rv;

  // Use readlink to read symlink path - we can output as much as M bytes into outbuf
  readlink_rv = yield_syscall(details, readlink, inbuf, outbuf, M);
  if (readlink_rv >= 0 && readlink_rv < M) outbuf[readlink_rv] = 0;
  co_return readlink_rv;
}

template <std::size_t N>
SyscCoroHelper fd_to_filename(SyscallCtx* details, int fd, char (&outbuf)[N]) {

  char fd_path[128]; // FD can't be that big
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

  co_return yield_from(read_symlink, details, fd_path, outbuf);
}

template <std::size_t N>
SyscCoroHelper read_file(SyscallCtx* details, const char (&fname)[N], std::string *outbuf) {
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
        if (bytes_read <= 0) break;
        total_bytes_read += bytes_read;
        outbuf->append(std::string(buffer, bytes_read)); // Is this okay with a read of 0 bytes?
    } while (bytes_read > 0);
    co_return total_bytes_read;
}

SyscCoroHelper fd_to_pos(SyscallCtx* details, int fd, ssize_t &pos) {
  char fd_path[128]; // FD can't be that big
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fdinfo/%d", fd);

  // Make a string as our outbuf arg
  std::string outbuf;
  int read_rv = yield_from(read_file, details, fd_path, &outbuf);

  if (read_rv < 0) {
    co_return read_rv;
  }

  // Now read the buffer. It should start with pos: <pos>. We want to extract pos.
  std::istringstream iss(outbuf);
  std::string line;
  // Loop through lines looking for pos
  while (std::getline(iss, line)) {
    if (line.find("pos:") == 0) {
      // Found pos line
      std::istringstream pos_iss(line);
      std::string pos_str;
      pos_iss >> pos_str >> pos;
      co_return 0;
    }
  }

  co_return -1;
}


template <std::size_t N>
SyscCoroHelper fd_to_contents(SyscallCtx* details, int fd, std::string &outbuf) {

  char fd_path[128]; // FD can't be that big
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
  char filename[256];

  int symlink_rv = yield_from(read_symlink, details, fd_path, filename);
  if (symlink_rv < 0)
    co_return symlink_rv;

  co_return yield_from(read_file, details, filename, outbuf);
}
#endif