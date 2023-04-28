#include <string.h>
#include "hyde_sdk.h"

NoStackExn::NoStackExn() {}

#define PAGE_SIZE 1024 // Setting for alignment of guest pages to host pages

/* Internal funciton to synchronize guest->host or host-> guest memory. Supports strcpy-style early stop at null pointer
 * when going guest->host
*/

SyscCoroHelper _memsync_pages(SyscallCtx* r, void* host_buf, uint64_t gva, size_t size, bool copy_to_host, bool end_at_null) {
  assert(size != 0);
  uint64_t hva = 0;
  uint64_t remaining_size = size;
  uint8_t* host_buf_ptr = (uint8_t*)host_buf;

  if (!copy_to_host) {
    // We're about to write size bytes to gva - before doing this we need to ensure that GVA isn't aliased to a commonly
    // used GPA. To ensure this is the case, we inject a sycall so the guest populates the buffer with some random junk
    // to dealias it. The 0 flag means "unblocking random" so it shouldn't be too terribly slow
    yield_syscall_raw(r, getrandom, gva, size, 0);
  }

  while (remaining_size > 0) {
    int ntries=0;
    while (r->translate_gva(gva, &hva) == false && ntries++ <= 5) {
      if (ntries == 5) {
        printf("FATAL: _memsync_pages failed to translate gva %lx\n", gva);
        co_return -1;
      }
      yield_syscall_raw(r, access, (uint64_t)gva, 0);
    }

    // Calculate how much data to copy in this iteration max of one page
    uint64_t page_end_gva = (gva | (PAGE_SIZE - 1)) + 1;
    uint64_t this_size = std::min(remaining_size, page_end_gva - gva);

    if (copy_to_host) {
      memcpy(host_buf_ptr, (void*)hva, this_size);
    } else {
      memcpy((void*)hva, host_buf_ptr, this_size);
    }
    // check if host_buf_ptr contians a null byte in the first this_size characters
    if (end_at_null && std::memchr(host_buf_ptr, '\0', this_size) != nullptr) {
        co_return (size - remaining_size) + strlen((char*)host_buf_ptr); // Prior chunks + len of this chunk
    }

    // Update the pointers and remaining size for the next iteration
    remaining_size -= this_size;
    gva += this_size;
    host_buf_ptr += this_size;
  }

  co_return size;
}


// Both directions should expose an API with (dest, source, size). Also support string copy with early stop at null byte
// mem/str  + write/put or read/cpy

// Write into guest memory
SyscCoroHelper ga_memwrite(SyscallCtx* r, uint64_t gva, void* in, size_t size) {
    co_return yield_from(_memsync_pages, r, in, gva, size, false, false);
}
// Read out of guest memory
SyscCoroHelper ga_memread(SyscallCtx* r, void* out, uint64_t gva, size_t size) {
    co_return yield_from(_memsync_pages, r, out, gva, size, true, false);
}

// Read string out of guest
SyscCoroHelper ga_strncpy(SyscallCtx* r, void* out, uint64_t gva, size_t size) {
    int rv = yield_from(_memsync_pages, r, out, gva, size, true, true);

    if (rv >= 0) {
      // Null terminate the string we read out
      if (rv < size) {
        ((char*)out)[rv] = '\0';
      } else {
        ((char*)out)[size-1] = '\0';
      }
    }
    co_return rv;
}

// Write null-terminated string into guest
SyscCoroHelper ga_strnput(SyscallCtx* r, uint64_t gva, void* in, size_t size) {
    co_return yield_from(_memsync_pages, r, in, gva, size, false, true);
}


// Aliases
SyscCoroHelper ga_memput(SyscallCtx* r, uint64_t gva, void* in, size_t size) {
    co_return yield_from(ga_memwrite, r, gva, in, size);
}
SyscCoroHelper ga_memcpy(SyscallCtx* r, void* out, uint64_t gva, size_t size) {
    co_return yield_from(ga_memread, r, out, gva, size);
}
SyscCoroHelper ga_strnread(SyscallCtx* r, void* out, uint64_t gva, size_t size) {
    co_return yield_from(ga_strncpy, r, out, gva, size);
}
SyscCoroHelper ga_strnwrite(SyscallCtx* r, uint64_t gva, void* in, size_t size) {
    co_return yield_from(ga_strnput, r, gva, in, size);
}

SyscCoroHelper handle_stack_alloc(SyscallCtx *details, size_t total_size) {
  /* If we already have a stack that we'll fit into return it. Otherwise
  deallocate the existing one if necessary and allocate a new one of sufficient size */

  if (details->stack_ != 0 && details->stack_size_ <= total_size) [[likely]] {
    co_return 0;
  }

  if (details->stack_ != 0) {
    // Existing stack is too small, free it first
    uint64_t old_stack = details->stack_;
    size_t old_size = details->stack_size_;

    details->stack_ = 0;
    details->stack_size_ = 0;

    co_yield unchecked_build_syscall<SYS_munmap>(::munmap, old_stack, old_size);
  }

  if (details->stack_ == 0) {
    // We need to allocate a new stack
    co_yield unchecked_build_syscall<SYS_mmap>(::mmap, 0, 0, total_size, \
                                                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t guest_stack = details->get_result(); /* Is this assert good enough error checking? */
    if (((int64_t)guest_stack < 0 && (int64_t)guest_stack > -500)) [[unlikely]] {
      throw NoStackExn();
      co_return -1;
    }

    // XXX: Be sure to always de-alias stack
    co_yield unchecked_build_syscall<SYS_getrandom>(::getrandom, 0, guest_stack, total_size, 0);
    details->stack_ = guest_stack;
  }
  co_return 0;
}