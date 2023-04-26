#include <sys/stat.h> // for open flags
#include <fcntl.h>
#include <vector>
#include <iostream>
#include "hyde_sdk.h"

static std::mutex running_in_root_proc;

SyscCoroHelper my_read_file(SyscallCtx *ctx, char* out_data, char* pathname, int out_size) {
    char local_pathname[128];
    if (strlen(pathname) > sizeof(local_pathname)) {
        printf("[PS] Error: pathname too long\n");
        co_return -1;
    }
    char *start = out_data;
    memset(out_data, 'A', out_size);

    // Open file
    memcpy(local_pathname, pathname, sizeof(local_pathname));
    int fd = yield_syscall(ctx, open, local_pathname, O_RDONLY, 0);

    if (fd < 0) {
        printf("[PS] Error: could not open %s\n", pathname);
        snprintf(out_data, out_size, "[open error]");
        out_data[0] = 0;
        co_return fd;
    }

    char host_buf[1024];
    int read_rv;
    int bytes_read = 0;
    do {
        // Read up to min(sizeof(host_buf), out_size) into host buf
        // Then copy that data into out_data, decrementing out_size

        read_rv = yield_syscall(ctx, read, fd, host_buf, std::min(sizeof(host_buf), (size_t)out_size));
        if (read_rv < 0) break;

        memcpy(out_data, host_buf, read_rv);
        out_data += read_rv;
        out_size -= read_rv;

        bytes_read += read_rv;

        if (out_size <= 0) {
            break;
        }
    } while (read_rv > 0);

    yield_syscall(ctx, close, fd);
    if (read_rv < 0) {
        printf("Error reading: %d\n", read_rv);
        co_return read_rv; // linux errno
    }
    start[bytes_read] = 0; // Ensure null term
    co_return bytes_read;
}

SyscallCoroutine read_in_root(SyscallCtx *ctx) {
    if (yield_syscall(ctx, geteuid)) {
        // Non-root
        co_yield *(ctx->get_orig_syscall());
        co_return ExitStatus::SUCCESS; // Not an error

    } else if (!running_in_root_proc.try_lock()) {
        // Lock unavailable, bail on this coopter
        // Note we don't want to wait since that would block a guest proc
        co_yield *(ctx->get_orig_syscall());
        co_return ExitStatus::SUCCESS; // Not an error
    }

    char out[2048];
    int bytes_read = yield_from(my_read_file, ctx, out, "/etc/passwd", sizeof(out));

    std::cerr << "Read " << bytes_read << " bytes from /etc/passwd" << std::endl;
    std::cerr << "Contents: " << std::endl;
    std::cerr << out << std::endl;

    ctx->get_orig_syscall()->pprint();
    co_yield *(ctx->get_orig_syscall());
    printf("Original syscall returned %ld\n", ctx->get_result());
    co_return ExitStatus::FINISHED;
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[-1] = read_in_root;
  return true;
}