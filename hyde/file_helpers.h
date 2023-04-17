#ifndef FILE_HELPERS_H
#define FILE_HELPERS_H
// for O_RDONLY
#include <fcntl.h>

#include "hyde.h"
#define PATH_LENGTH 256


template <std::size_t N>
SyscCoroHelper fd_to_filename(syscall_context* details, int fd, char (&outbuf)[N]);

template <std::size_t N, std::size_t M>
SyscCoroHelper read_symlink(syscall_context* details, char(&inbuf)[N], char (&outbuf)[M]);

template <std::size_t N>
SyscCoroHelper read_file(syscall_context* details, char (&fname)[N], std::string &outbuf);

// Now include the implementation - note .tpp file, see description in that file.
#include "file_helpers.tpp"
#endif