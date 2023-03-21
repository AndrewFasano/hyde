// Non-KVM code to use with HyDE programs

#include "hyde.h"

#define PAGE_SIZE 1024 // Setting for alignment of guest pages to host pages

// Implementations of the various ga_ coroutines
/*
 * Copy size bytes from a guest virtual address into a host buffer.
 */
SyscCoro ga_memcpy_one(asid_details* r, void* out, uint64_t gva, size_t size) {
  // We wish to read size bytes from the guest virtual address space
  // and store them in the buffer pointed to by out. If out is NULL,
  // we allocate it

  uint64_t hva = 0;

  if (!translate_gva(r, gva, &hva)) {
      yield_syscall_raw(r, access, (uint64_t)gva, 0);
      if (!translate_gva(r, gva, &hva)) {
        yield_syscall_raw(r, access, (uint64_t)gva, 0); // Try again
        if (!translate_gva(r, gva, &hva)) {
          co_return -1; // Failure, even after two retries?
        }
      }
  }

  //printf("Writing %lu bytes of data to %lx - %lx\n",  size, (uint64_t)out, (uint64_t)out + size);
  memcpy((uint64_t*)out, (void*)hva, size);
  co_return 0;
}


/* Memread will copy guest data to a host buffer, paging in memory as needed.
 * It's an alias for ga_memcpy but that might go away later in favor of this name.
 */
SyscCoro ga_memread(asid_details* r, void* out, uint64_t gva_base, size_t size) {
  co_return yield_from(ga_memcpy, r, out, gva_base, size);
}

/*
 * Copy size bytes from a guest virtual address into a host buffer, re-issue
 * translation requests as necessary, guaranteed to work so long as address through
 * address + size are mappable
 */
SyscCoro ga_memcpy(asid_details* r, void* out, uint64_t gva_base, size_t size) {

  uint64_t gva_end = (uint64_t)((uint64_t)gva_base + size);
  uint64_t gva_start_page = (uint64_t)gva_base  & ~(PAGE_SIZE - 1);
  //uint64_t gva_end_page = (uint64_t)gva_end  & ~(PAGE_SIZE - 1);
  uint64_t first_page_size = std::min((uint64_t)gva_base - gva_start_page, (uint64_t)size);

  // Copy first page up to alignment (or maybe even end!)
  //printf("Read up to %lu bytes into hva %lx from gva %lx\n", first_page_size, (uint64_t)out, (uint64_t)gva_base);
  if (yield_from(ga_memcpy_one, r, out, gva_base, first_page_size) == -1) {
    printf("First page read fails\n");
    co_return -1;
  }

  gva_base += first_page_size;
  out = (void*)((uint64_t)out + first_page_size);

  while ((uint64_t)gva_base < (uint64_t)gva_end) {
    uint64_t this_sz = std::min((uint64_t)PAGE_SIZE, (uint64_t)gva_end - (uint64_t)gva_base);
    if (yield_from(ga_memcpy_one, r, out, gva_base, this_sz) == -1) {
      printf("Subsequent page read fails\n");
      co_return -1;
    }
    gva_base += this_sz;
    out = (void*)((uint64_t)out + this_sz);
  }
  co_return 0;

  #if 0
  // Let's read from address to next page, then read pages? This is still a bit of a lazy implementation,
  // really we should be like binary searching


  // Given address X that lies somewhere between two pages, and say we want the subsequent page:
  // | page1 start     X      | page2 start     | page 3 start

  // First we calculate page1 start, translate it, calculate the offset of X into page one
  // and copy the number of bytes from X to the end of page 1 into the buffer

  #define PAGE_SIZE 0x1000uL
  uint64_t start_offset = (uint64_t)gva_base & (PAGE_SIZE-1);
  uint64_t first_page = (uint64_t)((uint64_t)gva_base & ~(PAGE_SIZE-1));

  if (first_page != gva_base) {
    // Original address wasn't page aligned
    uint64_t hva;
    if (!translate_gva(r, first_page, &hva)) {
        yield_syscall(r, __NR_access, (__u64)first_page, 0);
        if (!translate_gva(r, gva_base, &hva)) {
          co_return -1; // Failure, even after retry
        }
    }
    // Sanity check, should be able to translate requested address now that we have the page?
    assert(can_translate_gva(r->cpu, gva_base));

    //printf("\tga_memcpy: first copy. guest first page %lx maps to host %lx, reading from host at %lx\n", (uint64_t)first_page, hva, hva + start_offset);
    memcpy((uint64_t*)out, (void*)(hva + start_offset), std::min((ulong)size, (ulong)(PAGE_SIZE - start_offset)));
  }

  // Now copy page-aligned memory, one page at a time
  for (uint64_t page = gva_base + start_offset; page < gva_base + size; page += PAGE_SIZE) {
    ulong remsize  = std::min((ulong)PAGE_SIZE, (ulong)((gva_base + size) - page));

    printf("\tga_memcpy: subsequent page = %p, size=%lu\n", page, remsize);
    uint64_t hva;
    if (!translate_gva(r, page, &hva)) {
        yield_syscall(r, __NR_access, (__u64)page, 0);
        if (!translate_gva(r, gva_base, &hva)) {
          co_return -1; // Failure, even after retry
        }
    }

    printf("\tga_memcpy: subsequent copy of %lu bytes from %lx to %lx\n", remsize, hva, (uint64_t)out+(page-gva_base));
    memcpy((uint64_t*)out+(page-gva_base), (void*)hva, remsize);
  }

  co_return 0;
  #endif
}

/* Given a host buffer, write it to a guest virtual address. The opposite
 * of ga_memcpy */
SyscCoro ga_memwrite(asid_details* r, uint64_t gva, void* in, size_t size) {
  // TODO: re-issue translation requests as necessary
  uint64_t hva;
  assert(size != 0);

  if (!translate_gva(r, gva, &hva)) {
      //yield_syscall(r, __NR_access, (__u64)gva, 0);
      yield_syscall_raw(r, access, (uint64_t)gva, 0); // XXX: don't auto-map arguments! And don't typecheck!
      if (!translate_gva(r, gva, &hva)) {
        co_return -1; // Failure, even after retry
      }
  }

  //printf("Copying %lu bytes of %s to GVA %lx\n", size, (char*)in, (uint64_t)gva);
  memcpy((uint64_t*)hva, in, size);
  co_return 0;
}

SyscCoro ga_map(asid_details* r,  uint64_t gva, void** host, size_t min_size) {
  // Set host to a host virtual address that maps to the guest virtual address gva

  // TODO: Assert that gva+0 and gva+min_size can both be reached
  //at host[0], and host[min_size] after mapping. If not, fail?
  // TODO how to handle failures here?
  __u64 _gva = (uint64_t)gva & (uint64_t)-1;

  struct kvm_translation trans = { .linear_address = _gva };
  assert(kvm_vcpu_ioctl_ext(r->cpu, KVM_TRANSLATE, &trans) == 0);

  // Translation failed on base address - not in our TLB, maybe paged out
  if (trans.physical_address == (unsigned long)-1) {
      yield_syscall_raw(r, access, _gva, 0);

      // Now retry. if we fail again, bail
      //printf("Retrying to read %llx\n", trans.linear_address);
      assert(kvm_vcpu_ioctl_ext(r->cpu, KVM_TRANSLATE, &trans) == 0);
      //printf("\t result: %llx\n", trans.physical_address);
      if (trans.physical_address == (unsigned long)-1) {
        printf("Oh no we double fail mapping %llx\n", _gva);
        co_return -1; // Failure!
      }
  }

  // Translation has succeeded, we have the guest physical address
  // Now translate that to the host virtual address
  uint64_t hva;
  assert(kvm_host_addr_from_physical_memory_ext(trans.physical_address, &hva) == 1);
  (*host) = (void*)hva;

  co_return 0;
}
