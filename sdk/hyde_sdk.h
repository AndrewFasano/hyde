#ifndef HYDEEXT_H
#define HYDEEXT_H

// Some extras in here
#include <sys/syscall.h>
#include <sys/types.h>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <type_traits>
#include <unistd.h>
#include <linux/kvm.h>
#include <cassert>
#include <tuple>
#include <utility>
#include <coroutine>
#include <sys/random.h>
#include <exception>

#include "hyde_common.h"
#include "static_args.h" // For accumulate_stack_sizes template class magic


/* There are a couple of syscalls where namespace conflicts make things
 * less clean than normal for users of yield_syscall:
 * stat, times, gettimeofday, settimeofday.
 *  For these, we define simple wrappers with a
 * trailing _ to distinguish them.
 */

#include <sys/stat.h> // include stat function declaration
#include <sys/time.h> // gettimeofday
#include <sys/times.h> // times
#define SYS_stat_ SYS_stat
#define SYS_times_ SYS_times
#define SYS_gettimeofday_ SYS_gettimeofday
inline int stat_(const char *path, struct stat *buf) {
        return ::stat(path, buf);
}

inline clock_t times_(struct tms *buf) {
        return ::times(buf);
}

inline int gettimeofday_(struct timeval *tv, struct timezone *tz) {
    return ::gettimeofday(tv, tz);
}

/* Exception raised during a coroutine when we can't allocate guest memroy
 * to use for our stack-based arguments */
class NoStackExn : public std::exception {
public:
    NoStackExn();
    virtual const char* what() const noexcept override { return "Unable to alloate stack in guest"; }
};

/* Yield_from runs a HydeCoro<hsyscall, uint>, yielding the syscalls it yields, then finally returns a value that's co_returned from there */
#define yield_from(f, ...) \
  ({ \
    auto h = f(__VA_ARGS__).h_; \
    auto &promise = h.promise(); \
    int rv = 0; \
    if (h.done()) { \
      /* Edge case: no co_yields in target. Get final \
      result without running the subsequent loop */ \
      rv = promise.retval; \
    } \
    while (!h.done()) { \
        co_yield promise.value_; \
        h(); /* Advance the other coroutine  */ \
        rv = promise.retval; \
    } \
    h.destroy(); \
    rv; \
  })

// Coroutine helpers - HyDE programs can yield_from these and the helpers can inject more syscalls if they'd like
// {mem,str} + {cpy,read} or {put,write}
SyscCoroHelper ga_memcpy(SyscallCtx* r, void* out, uint64_t gva, size_t size);
SyscCoroHelper ga_memread(SyscallCtx* r, void* out, uint64_t gva, size_t size);
SyscCoroHelper ga_memput(SyscallCtx* r, uint64_t gva, void* in, size_t size);
SyscCoroHelper ga_memwrite(SyscallCtx* r, uint64_t gva, void* in, size_t size);
SyscCoroHelper ga_strncpy(SyscallCtx* r, void* out, uint64_t gva, size_t size);
SyscCoroHelper ga_strnread(SyscallCtx* r, void* out, uint64_t gva, size_t size);
SyscCoroHelper ga_strnput(SyscallCtx* r, uint64_t gva, void* in, size_t size);
SyscCoroHelper ga_strnwrite(SyscallCtx* r, uint64_t gva, void* in, size_t size);

template <long SyscallNumber, typename Function, typename... Args>
hsyscall unchecked_build_syscall(Function syscall_func, uint64_t guest_stack, Args... args) {
    //printf("Inject syscall %ld with %ld args\n", SyscallNumber, sizeof...(Args));
    // Now generate an hsyscall object with the syscall number, arguments, and number of args
    hsyscall s(SyscallNumber);

    // Populate s->args with each of the elements in args and set s->nargs to the number of arguments.
    s.nargs = 0;
    auto set_args = [&s](auto &&arg) {
      assert(s.nargs < sizeof(s.args) / sizeof(s.args[0])); // Make sure we don't go OOB (is this off by 1?)
      s.args[s.nargs++].value = (uint64_t)arg;
    };
    (set_args(args), ...);
    //s.dump();
    return s;
}

/* Given a system call number, a function pointer to the system call, and a list of arguments, allocate, initialize
 * and return na hsyscall object
 */
template <long SyscallNumber, typename Function, typename... Args>
hsyscall build_syscall(Function syscall_func, uint64_t guest_stack, Args... args) {
    //using ReturnType = decltype(syscall_func(std::declval<Args>()...));
    using ExpectedArgsTuple = std::tuple<typename std::remove_reference<Args>::type...>;
    using ActualArgsTuple = std::tuple<typename std::remove_reference<decltype(std::declval<Args>())>::type...>;

    // Ensure that the specified arguments match the syscall signature
    // Note that every syscall for linux returns a long so we don't need to typecheck that
    static_assert(std::is_same_v<ExpectedArgsTuple, ActualArgsTuple>,
                  "Argument types do not match the syscall signature.");

    return unchecked_build_syscall<SyscallNumber>(syscall_func, guest_stack, args...);
}

void map_one_arg(int idx, hsyscall *pending, uint64_t *stack_addr, auto args) {
  // Calculate how argument idx should be mapped to the guest stack. Update pending->args[idx] and stack_addr
  uint64_t this_size = (uint64_t)std::get<1>(args);
  if (this_size) {
    uint64_t padded_size = this_size + (32 - (this_size % 32)); // 32-bit aligned
    pending->args[idx].is_ptr = true;
    pending->args[idx].guest_ptr = *stack_addr;
    pending->args[idx].size = this_size;
    pending->args[idx].copy_out = std::get<2>(args) ? false : true; // If it's a const, we don't copy out, otherwise we do
    //printf("Allocation for arg %d: stack (GVA) %lx, size %u\n", idx, pending->args[idx].guest_ptr, pending->args[idx].size);
    *stack_addr += padded_size; // Shift stack address
  }
}

template <typename... Args>
SyscCoroHelper map_args_to_guest_stack(SyscallCtx* details, uint64_t stack_addr, hsyscall *pending, std::tuple<Args...> tuple) {
  // Given a tuple of arguments with types and sizes, map those arguments, with concrete
  // pointer values stored in pending->args to the guest stack

  // Our fold expression can't be a coroutine, but we're a coroutine. In the map_one_arg function
  // that we call on each element, we'll identify host->guest mappings we need to do and update pending->args
  pending->nargs = 0;
  std::apply(
    [pending, &stack_addr](auto... args) {
      // Size is args.second? If size isn't 0, we should map. If size is 0 we can skip?
      (..., (map_one_arg(pending->nargs++, pending, &stack_addr, args)));
    },
  tuple);

  // Now look through pending->args and actually do the memory mappings
  for (int i = 0; i < pending->nargs; i++) {
    if (pending->args[i].is_ptr) {
      //printf("Map arg %d: host %lx guest %lx\n", i, pending->args[i].value, pending->args[i].guest_ptr);
      if (yield_from(ga_memwrite, details, pending->args[i].guest_ptr, (void*)pending->args[i].value, pending->args[i].size) < 0) {
        printf("FATAL: failed to memwrite argument %d into guest stack\n", i);
        co_return -1;
      }

      // If we want to debug, can't use yield_syscall macro - need to do something like:
      //co_yield unchecked_build_syscall<SYS_write>(write, 0, 1, pending->args[i].guest_ptr, pending->args[i].size);
    }
  }
  co_return 0;
}

template <typename... Args>
SyscCoroHelper map_args_from_guest_stack(SyscallCtx* details, uint64_t stack_addr, hsyscall *sc, Args&&... args) {
  // We just ran syscall sc, iterate through it's arguments, identifying poitners and yield syscalls to map them back

  for (int i = 0; i < sc->nargs; i++) {
    if (sc->args[i].is_ptr && sc->args[i].copy_out) {
      //printf("map guest %lx to host %lx, size %d\n", sc->args[i].guest_ptr, sc->args[i].value, sc->args[i].size);
      if (yield_from(ga_memread, details, (void*)sc->args[i].value, sc->args[i].guest_ptr, sc->args[i].size) < 0) {
        printf("FATAL: failed to memread argument %d from guest stack\n", i);
        co_return -1;
      }
    }
  }
  co_return 0;
}

SyscCoroHelper handle_stack_alloc(SyscallCtx *details, size_t total_size);

/* Helper macro to be used by SyscCoro coroutines. Build an hsyscall using the given function name,
 * yield that hsyscall (which will cause the details object to update place a return in last_sc_ret),
 * free the heap-allocated hsyscall, and finally provide the caller with the result of the simulated
 * syscall which was set in details->last_sc_ret.
 */
#define yield_syscall(details, func, ...) ({                                                                  \
  auto arg_types_tup = deduce_types_and_sizes(__VA_ARGS__);                                                   \
  size_t total_size = accumulate_stack_sizes(arg_types_tup);                                                  \
  size_t padded_total_size = total_size + (1024 - (total_size % 1024));                                       \
  /*printf("Total stack size is %lu, padded to %lu\n", total_size, padded_total_size);*/                      \
  if (padded_total_size > 0) yield_from(handle_stack_alloc, details, padded_total_size);                      \
  hsyscall s = build_syscall<SYS_##func>(::func, details->stack_, ##__VA_ARGS__);                             \
  if (total_size > 0)                                                                                         \
  {                                                                                                           \
    /* Now, we've built the syscall and have the scratch stack. Do the mapping!*/                             \
    yield_from(map_args_to_guest_stack, details, details->stack_, &s, arg_types_tup);                         \
  }                                                                                                           \
  co_yield s;                                                                                                 \
  auto rv = details->get_result();                                                                            \
  rv;                                                                                                         \
  })

#define free_stack(details) ({                                                                          \
  if (details->stack_ != 0) {                                                                           \
    co_yield (unchecked_build_syscall<SYS_munmap>(::munmap, 0, details->stack_, details->stack_size_)); \
    details->stack_ = 0;                                                                                \
    details->stack_size_ = 0;                                                                           \
  }                                                                                                     \
})

#define finish(details, rv) ({ \
  free_stack(details);         \
  co_return rv;                \
});

#define yield_and_finish(details, syscall, retval)    \
  free_stack(details);                                \
  details->set_noreturn(retval);                      \
  co_yield syscall;                                   \
  co_return ExitStatus::FATAL; /* UNREACHABLE */      \

#define co_yield_noreturn(details, syscall, retval) co_ret_noreturn(details, syscall, retval)

/* Build and yield a syscall, return it's result. Do *not* auto allocate and map arguments. */
#define yield_syscall_raw(details, func, ...) ({                        \
  co_yield unchecked_build_syscall<SYS_##func>(::func, 0, __VA_ARGS__); \
  details->get_result();                                                \
})

#endif
