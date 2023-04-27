#include "hyde_sdk.h"

#define PAGE_SIZE 1024 // Setting for alignment of guest pages to host pages

// Implementations of the various ga_ coroutines
/*
 * Copy size bytes from a guest virtual address into a host buffer.
 */
SyscCoroHelper _memsync_page(SyscallCtx* r, void* host_buf, uint64_t gva, size_t size, bool copy_to_host) {
  // We wish to read size bytes from the guest virtual address space
  assert(size != 0);
  uint64_t hva = 0;

  if (!r->translate_gva(gva, &hva)) {
      yield_syscall_raw(r, access, (uint64_t)gva, 0);
      if (!r->translate_gva(gva, &hva)) {
        yield_syscall_raw(r, access, (uint64_t)gva, 0); // Try again
        if (!r->translate_gva(gva, &hva)) {
          co_return -1; // Failure, even after two retries?
        }
      }
  }

  // Sanity check - just for debugging, can we also translate the last byte?
  uint64_t expected_hva_end = hva + size;
  uint64_t hva_end;
  uint64_t gva_end = gva + size;
  if (!r->translate_gva(gva_end, &hva_end)) {
    printf("FATAL couldn't translate last byte of page: %lx->%lx but %lx->???\n", gva_end, hva_end, gva_end);
    co_return -1;
  }
  if (hva_end != expected_hva_end) {
    printf("FATAL: Translated gva %lx -> %lx but %lx translates to %lx NOT %lx\n", gva, hva, gva_end, hva_end, expected_hva_end);
    co_return -1;
  }

  if (copy_to_host) {
    memcpy((uint64_t*)host_buf, (void*)hva, size);
  } else {
    memcpy((void*)hva, (uint64_t*)host_buf, size);
  }
  co_return 0;
}

// Write size bytes of host_buf into guest at gva
SyscCoroHelper ga_memwrite_one(SyscallCtx* r, void* host_buf, uint64_t gva, size_t size) {
  co_return yield_from(_memsync_page, r, host_buf, gva, size, false);
}

// Write size bytes from guest at gva into host_buf
SyscCoroHelper ga_memread_one(SyscallCtx* r, void* host_buf, uint64_t gva, size_t size) {
  co_return yield_from(_memsync_page, r, host_buf, gva, size, true);
}

/*
 * Copy size bytes from a guest virtual address into a host buffer, re-issue
 * translation requests as necessary, guaranteed to work so long as address through
 * address + size are mappable
 */
SyscCoroHelper ga_memcpy(SyscallCtx* r, void* out, uint64_t gva_base, size_t size) {
  uint64_t gva_end = (uint64_t)((uint64_t)gva_base + size);
  uint64_t gva_start_page = (uint64_t)gva_base  & ~(PAGE_SIZE - 1);
  uint64_t first_page_size = std::min(gva_base - gva_start_page, (uint64_t)size);

  // If first page isn't aligned, copy it and set us up to be aligned for subsequent pages
  if (first_page_size != 0) {
    if (yield_from(ga_memread_one, r, out, gva_base, first_page_size) == -1) {
      printf("First page read fails\n");
      co_return -1;
    }

    gva_base += first_page_size;
    out = (void*)((uint8_t*)out + first_page_size);
  }


  while ((uint64_t)gva_base < (uint64_t)gva_end) {
    uint64_t this_sz = std::min((uint64_t)PAGE_SIZE, (uint64_t)gva_end - (uint64_t)gva_base);
    if (yield_from(ga_memread_one, r, out, gva_base, this_sz) == -1) {
      printf("Subsequent page read fails\n");
      co_return -1;
    }
    gva_base += this_sz;
    out = (void*)((uint8_t*)out + this_sz);
  }
  co_return 0;
}

/* Write one page to guest virtual memory */
SyscCoroHelper ga_memwrite_one(SyscallCtx* r, uint64_t gva, void* in, size_t size) {
  assert(size != 0);

  if (size == 0) {
    printf("FATAL memcpy size 0\n");
    co_return -1;
  }

  uint64_t hva = 0;
  if (!r->translate_gva(gva, &hva)) {
      yield_syscall_raw(r, access, (uint64_t)gva, 0);
      if (!r->translate_gva(gva, &hva)) {
        yield_syscall_raw(r, access, (uint64_t)gva, 0); // Try again
        if (!r->translate_gva(gva, &hva)) {
          co_return -1; // Failure, even after two retries?
        }
      }
  }

  // Sanity check - just for debugging, can we also translate the last byte?
  uint64_t expected_hva_end = hva + size;
  uint64_t hva_end;
  uint64_t gva_end = gva + size;
  if (!r->translate_gva(gva_end, &hva_end)) {
    printf("FATAL couldn't translate last byte of page: %lx->%lx but %lx->???\n", gva_end, hva_end, gva_end);
    co_return -1;
  }
  if (hva_end != expected_hva_end) {
    printf("FATAL: Translated gva %lx -> %lx but %lx translates to %lx NOT %lx\n", gva, hva, gva_end, hva_end, expected_hva_end);
    co_return -1;
  }

  memcpy((void*)hva, in, size);
  co_return 0;
}

/* Given a host buffer, write it to a guest virtual address. The opposite
 * of ga_memcpy */
SyscCoroHelper ga_memwrite(SyscallCtx* r, uint64_t gva_base, void* in, size_t size) {
  uint64_t gva_end = (uint64_t)((uint64_t)gva_base + size);
  uint64_t gva_start_page = (uint64_t)gva_base  & ~(PAGE_SIZE - 1);
  uint64_t first_page_size = std::min(gva_base - gva_start_page, (uint64_t)size);

  // If first page isn't aligned, copy it and set us up to be aligned for subsequent pages
  if (first_page_size != 0) {
    if (yield_from(ga_memwrite_one, r, gva_base, in, first_page_size) == -1) {
      printf("First page read fails\n");
      co_return -1;
    }

    gva_base += first_page_size;
    in = (void*)((uint8_t*)in + first_page_size);
  }


  while ((uint64_t)gva_base < (uint64_t)gva_end) {
    uint64_t this_sz = std::min((uint64_t)PAGE_SIZE, (uint64_t)gva_end - (uint64_t)gva_base);
    if (yield_from(ga_memwrite_one, r, gva_base, in, this_sz) == -1) {
      printf("Subsequent page read fails\n");
      co_return -1;
    }
    gva_base += this_sz;
    in = (void*)((uint8_t*)in + this_sz);
  }
  co_return 0;
}


// OLD CODE that we might still use somewhere:

SyscCoroHelper ga_map(SyscallCtx* r,  uint64_t gva, void** host, size_t min_size) {
  // Set host to a host virtual address that maps to the guest virtual address gva

  // TODO: Assert that gva+0 and gva+min_size can both be reached
  //at host[0], and host[min_size] after mapping. If not, fail?
  // TODO how to handle failures here?

  uint64_t gpa;

  if (!r->translate_gva(gva, &gpa)) {
    // Translation failed on base address - not in our TLB, maybe paged out
    // Inject access syscall, forcing guest kernel to page it in with no other side effects
    yield_syscall_raw(r, access, gva, 0);
    // Now retry
    if (!r->translate_gva(gva, &gpa)) {
      printf("ga_map double fails for %lx\n", gva);
      co_return -1; // Failure!
    }
  }

  // Translation has succeeded, we have the guest physical address
  // Now translate that to the host virtual address
  uint64_t hva;
  assert(r->gpa_to_hva(gpa, &hva));
  (*host) = (void*)hva;
  co_return 0;
}

// Alias for ga_memcpy
SyscCoroHelper ga_memread(SyscallCtx* r, void* out, uint64_t gva_base, size_t size) {
  co_return yield_from(ga_memcpy, r, out, gva_base, size);
}

