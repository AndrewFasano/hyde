#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <sys/types.h> // for open flags
#include <sys/stat.h> // for open flags
#include <fcntl.h>
#include <vector>
#include <mutex>
#include <sstream>
#include <iostream>
#include <crypt.h> // For password encryption
#include "hyde.h"

static bool done = false;
static std::mutex running_in_root_proc;

// Hardcoded salt and password, just for now. Salt type ($6$) is recognized
// by crypt() as SHA512 and works in shadow files. I believe we could also
// use other types here.
const char salt[] = {"$6$jlayw31s"};
const char password[] = {"HYDE_set_this"};

SyscCoro start_coopter(asid_details* details) {
    int rv = 0;
    int fd;

    //printf("%s\n", crypt(password, salt));

    std::string buffer;
    std::string token;
    ga* guest_buf;
    char shadow[] = "/etc/shadow";
    char shadow2[] = "/tmp/shadow";
    char *new_host_buf;
    struct stat statbuf;

    if (done) co_return 0;

    if (yield_syscall(details, __NR_geteuid)) {
        rv = -1;
        goto out;
    }

    if (!running_in_root_proc.try_lock()) {
        // Lock unavailable, bail on this coopter
        // Note we don't want to wait since that would block a guest proc
        rv = -1;
        goto out;
    }
    // Now running with the lock
    if (done) {
        co_return 0;
    }

    // Allocate guest memory for reading/writing shadow file
    guest_buf = (ga*)yield_syscall(details, __NR_mmap,
        /*addr=*/0, /*size=*/1024, /*prot=*/PROT_READ | PROT_WRITE,
        /*flags=*/MAP_ANONYMOUS | MAP_SHARED, /*fd=*/-1, /*offset=*/0);

    if (yield_from(ga_memwrite, details, guest_buf, shadow, sizeof(shadow)) == -1) {
        printf("[PWReset] Error: could not to copy file name into to guest memory\n");
        goto cleanup_buf;
    }

    fd = yield_syscall(details, __NR_open, guest_buf, O_RDONLY, 0);
    if (fd == -1) {
        printf("[PWReset] Error: could not open shadow file\n");
        rv = -1;
        goto cleanup_buf;
    }

    // Get file permissions from FD. Normal is rw-r----- so we shouldn't need to change
    yield_syscall(details, __NR_fstat, fd, guest_buf);

    if (yield_from(ga_memcpy, details, &statbuf, guest_buf, sizeof(struct stat)) == -1) {
            printf("[PWReset] Error: could not read statbuf\n");
            rv = -1;
            goto cleanup_buf;
    }

    // root:root is root:$1$CrzjG7wM$1Wqb9ABOWNOa2nuaXFT740:18239:0:99999:7:::
    // find root line

    buffer.reserve(1024);
    while (true) {
        int bytes_read = yield_syscall(details, __NR_read, fd, guest_buf, 1024);
        if (bytes_read == -1) {
            printf("[PWReset] Error: could not read shadow file\n");
            rv = -1;
            goto close_fd;
        }
        if (bytes_read == 0) break; 

        char *host_buf;
        if (yield_from(ga_map, details, guest_buf, (void**)&host_buf, 1024) == -1) {
            printf("[PWReset] Error mapping allocated guest buffer from gva %lx\n", (uint64_t)guest_buf );
            goto close_fd;
        }

        buffer.append(host_buf, bytes_read);
    }

    if (buffer.find("root:") == std::string::npos) {
        printf("[PWReset] Error: could not find root user in shadow file\n");
        done=true; // Failure, but we're done, no point in trying again
        rv = -1;
        goto close_fd;
    }


    { // Don't want to deal with no new variables between gotos
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

        // Just reopen the FD instead of seeking.
        yield_syscall(details, __NR_close, fd);

        // Make sure it's writable by owner (assuming that's us, as root)
        if (!(statbuf.st_mode & S_IWUSR)) {
            // Let's make it writable!
            printf("[PwReset] File was unwritable, changing...\n");

            // write shadow, then chmod(shadow, writable)
            if (yield_from(ga_memwrite, details, guest_buf, shadow, sizeof(shadow)) == -1) {
                printf("[PWReset] Error: could not to copy file name into to guest memory v2\n");
                rv = -1;
                goto cleanup_buf;
            }
            if (yield_syscall(details, __NR_chmod, guest_buf, (statbuf.st_mode | S_IWUSR)) == -1) {
                printf("[PWReset] Error: could not chmod shadow file to become writable\n");
                rv = -1;
                goto cleanup_buf;
            }
        }


        // fd = open(shadow, O_WRONLY)
        if (yield_from(ga_memwrite, details, guest_buf, shadow, sizeof(shadow)) == -1) {
            printf("[PWReset] Error: could not to copy file name into to guest memory\n");
            goto cleanup_buf;
        }
        fd = yield_syscall(details, __NR_open, guest_buf, O_TRUNC | O_WRONLY, 0);

        //printf("Old (encrypted) password: %s\n", old_password.c_str());
        //printf("New password: %s which encrypts to %s\n", password, crypt(password, salt));

        buffer.replace(buffer.find(old_password), old_password.length(), crypt(password, salt));
        new_host_buf = strdup(buffer.c_str());

        //printf("Writing new shadow file (%lu bytes) in FD %d\n\n%s\n", buffer.length(), fd, new_host_buf);

        for (int offset = 0; offset < buffer.length(); offset += 1024) {
            size_t chunk_size = std::min((size_t)1024, (size_t)buffer.length() - offset);

            //printf("Writing from %d to +%lu\n", offset, chunk_size);
            if (yield_from(ga_memwrite, details, guest_buf, &new_host_buf[offset], chunk_size) == -1) {
                printf("[PWReset] Error: could not to copy new buffer at +[%d] into guest memory\n", offset);
                rv = -1;
                goto cleanup_new_buf;
            }

            // Now write the new buffer to the shadow file
            int bytes_written = yield_syscall(details, __NR_write, fd, guest_buf, chunk_size);
            if (bytes_written == -1) {
                printf("[PWReset] Error: could not write shadow file at offset %d\n", offset);
                rv = -1;
                goto cleanup_new_buf;
            }
            //printf("\tWrote %d bytes\n", bytes_written);
        }
    }
    done=true;

cleanup_new_buf:
    free(new_host_buf);

    // Always chmod back to old permissions, even if we didn't chmod, writing may have changed
    if (yield_from(ga_memwrite, details, guest_buf, shadow, sizeof(shadow)) == -1) {
        printf("[PWReset] Error: could not to copy file name into to guest memory v2\n");
        rv = -1;
        goto cleanup_buf;
    }
    if (yield_syscall(details, __NR_chmod, guest_buf, statbuf.st_mode) == -1) {
        printf("[PWReset] Error (unrecoverable) could not chmod shadow file to original value\n");
        rv = -1;
    }

close_fd:
    yield_syscall(details, __NR_close, fd);

cleanup_buf:
    yield_syscall(details, __NR_munmap, guest_buf, 1024);
    running_in_root_proc.unlock();

out:
    co_yield *(details->orig_syscall); // noreturn
    co_return rv;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
    if (!done)
        return &start_coopter;
  return NULL;
}