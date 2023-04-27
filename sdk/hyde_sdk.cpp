#include "hyde_sdk.h"

#define PAGE_SIZE 1024 // Setting for alignment of guest pages to host pages

// Implementations of the various ga_ coroutines
/* 
  Internal helper to syncronize a single page of guest->host or host->guest memory
*/
SyscCoroHelper _memsync_page(SyscallCtx* r, void* host_buf, uint64_t gva, size_t size, bool copy_to_host) {
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
SyscCoroHelper ga_memwrite_one(SyscallCtx* r, uint64_t gva, void* host_buf, size_t size) {
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
  uint64_t hva;

  int i = 0;
  while (r->translate_gva(gva, &hva) == false && i++ <= 10) {
    if (i == 10) {
      printf("Translation failed 10 times, aborting\n");
      co_return -1;
    }
    yield_syscall_raw(r, access, gva, 0);
  }

  uint64_t hva_end;
  if (!r->translate_gva(gva + min_size, &hva_end)) {
    printf("Translation failed for end of range\n");
    co_return -1;
  }

  if (hva_end - hva != min_size) {
    printf("Range is not contigious\n");
    co_return -1;
  }

  // Translation succeeded - we should now have HVA
  (*host) = (void*)hva;
  co_return 0;
}

// Alias for ga_memcpy
SyscCoroHelper ga_memread(SyscallCtx* r, void* out, uint64_t gva_base, size_t size) {
  co_return yield_from(ga_memcpy, r, out, gva_base, size);
}

