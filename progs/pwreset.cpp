#include <string>
#include <sys/types.h> // for open flags
#include <sys/stat.h> // for open flags
#include <fcntl.h>
#include <mutex>
#include <sstream>
//#include <iostream>
#include <crypt.h> // For password encryption

#include "hyde_sdk.h"
#include "file_helpers.h" // read_file

static std::mutex running_in_root_proc;

// Hardcoded salt and password, just for now. Salt type ($6$) is recognized
// by crypt() as SHA512 and works in shadow files. I believe we could also
// use other types here.
const char salt[] = {"$6$jlayw31s"};
const char password[] = {"HYDE_set_this"};

SyscallCoroutine reset_in_root(SyscallCtx* details) {
    ExitStatus rv = ExitStatus::SUCCESS;

    std::string token;
    uint64_t guest_buf;
    const char shadow[] = "/etc/shadow";
    const char shadow2[] = "/tmp/shadow";


    if (yield_syscall(details, geteuid)) {
        // Non-root user, no need to do anything
        yield_and_finish(details, details->pending_sc(), ExitStatus::SUCCESS);
    }

    if (!running_in_root_proc.try_lock()) {
        // Lock unavailable, bail on this coopter
        // Note we don't want to wait since that would block a guest proc
        yield_and_finish(details, details->pending_sc(), ExitStatus::SUCCESS);
    }

    std::string buffer;
    int buffer_size = yield_from(read_file, details, shadow, &buffer);
    printf("Read %d bytes of shadow file\n", buffer_size);

    if (buffer_size < 0) {
        printf("[PwReset] Failed to read %s: got error %d\n", shadow, buffer_size);
        running_in_root_proc.unlock();
        yield_and_finish(details, details->pending_sc(), ExitStatus::FATAL);
    }

    // find root line
    if (buffer.find("root:") == std::string::npos) {
        printf("[PWReset] Error: could not find root user in shadow file\n");
        // Close file and bail
        yield_and_finish(details, details->pending_sc(), ExitStatus::FATAL);
    }

    //printf("Shadow file contains:\n\n%s", buffer.c_str());
    std::stringstream ss(buffer);
    bool newline = true;
    bool match = false;
    int match_count = 0;
    std::string old_password;
    while (std::getline(ss, token, ':')) {
        if (token == "root" && newline) {
            match = true;
        }
        newline =  (token[0] == '\n');

        if (newline && match) {
            match = false;
        }
        if (match) {
            if (match_count == 1) {
                old_password = token;
            }
            match_count++;
        }
    }

    // Now open the file, clobbering what was there
    int fd = yield_syscall(details, open, &shadow, O_TRUNC | O_WRONLY, 0);

    printf("Old (encrypted) password: %s\n", old_password.c_str());
    printf("New password: %s which encrypts to %s\n", password, crypt(password, salt));

    buffer.replace(buffer.find(old_password), old_password.length(), crypt(password, salt));

    for (int offset = 0; offset < buffer.length(); offset += 1024) {
        size_t chunk_size = std::min((size_t)1024, (size_t)buffer.length() - offset);

        char this_chunk[1024];
        memcpy(this_chunk , &buffer.c_str()[offset], chunk_size);

        // Now write the new buffer to the shadow file
        int bytes_written = yield_syscall(details, write, fd, this_chunk, chunk_size);
        if (bytes_written < 0) {
            printf("[PWReset] Error: could not write shadow file at offset %d: error %d\n", offset, bytes_written);
            yield_syscall(details, close, fd);
            running_in_root_proc.unlock();
            yield_and_finish(details, details->pending_sc(), ExitStatus::SINGLE_FAILURE);
        }
    }
    rv = ExitStatus::FINISHED;
    yield_syscall(details, close, fd);
    running_in_root_proc.unlock();

    yield_and_finish(details, details->pending_sc(), rv);
}

extern "C" bool init_plugin(std::unordered_map<int, create_coopter_t> map) {
  map[-1] = reset_in_root;
  return true;
}