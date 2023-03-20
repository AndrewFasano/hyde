#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <iostream> // Just for cout
#include <string>
#include <sys/mman.h> // for mmap flags
#include <type_traits>
#include <unistd.h>
#include <vector>
#include <linux/kvm.h>
#include <cassert>
#include <tuple>
#include <utility>
#include <coroutine>

struct hsyscall_arg {
  uint64_t value; // host_pointer OR constant
  bool is_ptr; // if true, value is a host pointer
  uint64_t guest_ptr; // ignored if !is_ptr
  unsigned int size; // ignored if !is_ptr
};

// hsyscall is a struct that represents a system call that we will simulate execution of.
// Before the syscall is simulated, it should be populated with callno, nargs, and args.
// After the syscall is simulated, retval will store the return value and has_retval will be set to true.
typedef struct {
  uint64_t callno; // System call number
  unsigned int nargs; // Number of arguments
 hsyscall_arg args[6]; // Arguments for the syscall

  // After we simulate
  uint64_t retval; // Only used when co-opting
  bool has_retval;
} hsyscall;

// Coroutine that yield objects of type T and finally returns a uint64_t
template <typename T>
struct HydeCoro {
  struct promise_type {
    T value_;
    uint64_t retval;

    ~promise_type() {
      //printf("Coro destroyed\n");
    }

    HydeCoro<T> get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {}

    // Regular yield, returns an hsyscall value
    std::suspend_always yield_value(T value) {
      value_ = value;
      return {};
      //printf("Yielding a value\n");
    }

    //void return_value(T const& value) {
    void return_value(int value) {
      retval = value;
      value_ = {0};
      //printf("Returning a value: %ld\n", retval);
    };
  };

  std::coroutine_handle<promise_type> h_;
};

// The syscCoro type is a coroutine that yields hsyscall objects and returns a uint64_t
typedef HydeCoro<hsyscall> SyscCoro;
// coopter_t is a coroutine handle to SyscCoro coroutines
typedef std::coroutine_handle<HydeCoro<hsyscall>::promise_type> coopter_t;

/* This structure stores details about a given process that we are co-opting.
 * It contains a pointer to the coroutine that is simulating the process's execution.
 * It also contains a pointer to the original system call that the process was executing.
 * Finally, it contains a pointer to the original registers that the process was executing.
*/
typedef struct _asid_details {
  coopter_t coopter; // The coroutine that is simulating the process's execution
  struct kvm_regs orig_regs; // The original registers when we started simulating the guest process
  hsyscall *orig_syscall; // The original system call that was about to run in the target process
  void* cpu; // Opaque pointer we use internally
  long unsigned int last_sc_retval; // Return value to be set after simulating a system call

  uint64_t asid;

  uint64_t orig_rcx; // RCX and R11 values before the original requested system call
  uint64_t orig_r11;
  bool use_orig_regs; // If set, after coopter finishes we' restore RCX/R11 to their pre-syscall values

  unsigned long custom_return; // If set to a non-zero value, we will set the guest's program counter to this address after coopter finishes

  bool did_malloc;
  uint64_t guest_stack;
  uint64_t guest_stack_end;

  //std::function<void(_asid_details*, void*, unsigned long, unsigned long, unsigned long)> *on_ret; // Unused
} asid_details;


// create_coopt_t functions are called with a bunch of stuff and return a pointer to a function with type SyscCoro(asid_details*)
typedef SyscCoro(create_coopt_t)(asid_details*);
// create_coopt_t is function type that is given a few arguments and returns a function pointer function with type create_coopt_t(asid_details*)
typedef create_coopt_t*(coopter_f)(void*, long unsigned int, long unsigned int, unsigned int);

// Series of templates to deduce the size of a variadic list of arguments
// This is used so we can calculate the necessary stack size in guest
// memory that we will use for copying hsyscall arguments into the guest's memory

// Handle non-array, non-pointer types
template <typename T>
auto deduce_type_and_size_impl(T&& arg, std::false_type, std::false_type) {
    //return std::make_pair(&arg, sizeof(T));
    return std::make_pair(&arg, 0); // XXX: Do *not* count the size of these types
}

// Handle pointer types
template <typename T>
auto deduce_type_and_size_impl(T* arg, std::false_type, std::true_type) {
    return std::make_pair(arg, sizeof(std::remove_pointer_t<T>));
}

// Handle array types
template <typename T, size_t N>
auto deduce_type_and_size_impl(T (&arr)[N], std::true_type, std::false_type) {
    return std::make_pair(arr, sizeof(T) * N);
}

template <typename T>
auto deduce_type_and_size(T&& arg) {
    return deduce_type_and_size_impl(std::forward<T>(arg), 
                                     std::is_array<std::remove_reference_t<T>>{}, 
                                     std::is_pointer<std::remove_reference_t<T>>{});
}

template <typename... Args>
auto deduce_types_and_sizes(Args&&... args) {
    return std::tuple_cat(std::make_tuple(deduce_type_and_size(std::forward<Args>(args)))...);
}


template <typename... Args>
constexpr size_t accumulate_stack_sizes(std::tuple<Args...> tuple) {
    size_t sum = 0;
    std::apply([&sum](auto... args) { (..., (sum += args.second)); }, tuple); // TODO include rounding up for alignment in here like we do later (32-bit?)
    return sum;
}

template <long SyscallNumber, typename Function, typename... Args>
hsyscall unchecked_build_syscall(Function syscall_func, uint64_t guest_stack, Args... args) {
    //printf("Inject syscall %ld with %ld args, total size %ld\n", SyscallNumber, sizeof...(Args), TotalSize);
    // Now generate an hsyscall object with the syscall number, arguments, and number of args
    hsyscall s {
      .callno = SyscallNumber
    };
 
    // Populate s->args with each of the elements in args and set s->nargs to the number of arguments.
    // Also populate s->arg_sizes with the size of each argument 
    // XXX: this setup is later clobbered by map_args_to_guest_stack
    s.nargs = 0;
    auto set_args = [&s](auto &&arg) {
      assert(s.nargs < sizeof(s.args) / sizeof(s.args[0])); // Make sure we don't go OOB
      s.args[s.nargs++].value = (uint64_t)arg;
    };
    (set_args(args), ...);
    return s;
}

/* Given a system call number, a function pointer to the system call, and a list of arguments, allocate, initialize
 * and return na hsyscall object
 */
template <long SyscallNumber, typename Function, typename... Args>
hsyscall build_syscall(Function syscall_func, uint64_t guest_stack, Args... args) {
    using ReturnType = decltype(syscall_func(std::declval<Args>()...));
    using ExpectedArgsTuple = std::tuple<typename std::remove_reference<Args>::type...>;
    using ActualArgsTuple = std::tuple<typename std::remove_reference<decltype(std::declval<Args>())>::type...>;

    // Ensure that the specified arguments match the syscall signature
    // Note that every syscall for linux returns a long so we don't need to typecheck that
    static_assert(std::is_same_v<ExpectedArgsTuple, ActualArgsTuple>,
                  "Argument types do not match the syscall signature.");

    return unchecked_build_syscall<SyscallNumber>(syscall_func, guest_stack, args...);
}

/* Yield_from runs a coroutine, yielding the syscalls it yields, then finally returns a value that's co_returned from there */
#define yield_from(f, ...) \
  ({ \
    auto h = f(__VA_ARGS__).h_; \
    auto &promise = h.promise(); \
    uint64_t rv = 0; \
    while (!h.done()) { \
        co_yield promise.value_; \
        h(); /* Advance the other coroutine  */ \
        rv = promise.retval; \
    } \
    h.destroy(); \
    rv; \
  })

void map_one_arg(int idx, hsyscall *pending, uint64_t *stack_addr, auto args) {
  // Calculate how argument idx should be mapped to the guest stack. Update pending->args[idx] and stack_addr
  uint64_t this_size = (uint64_t)args.second;
  if (this_size) {
    // 32-bit alignment?
    uint64_t padded_size = this_size + (32 - (this_size % 32));
    pending->args[idx].is_ptr = true;
    pending->args[idx].guest_ptr = *stack_addr;
    pending->args[idx].size = this_size;
    //auto rv = std::make_pair(*stack_addr, this_size);
    *stack_addr += padded_size; // Shift stack address
  }
} 

template <typename... Args>
SyscCoro map_args_to_guest_stack(uint64_t stack_addr, hsyscall *pending, std::tuple<Args...> tuple) {
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
      printf("TODO map host %lx to guest %lx, size %d\n", pending->args[i].value, pending->args[i].guest_ptr, pending->args[i].size);
      //yield_from(ga_memwrite, pending->args[i].guest_ptr, pending->args[i].value, pending->args[i].size); // XXX we want this, just need kvm
    }
  }
  co_return 0;
}

template <typename... Args>
SyscCoro map_args_from_guest_stack(uint64_t stack_addr, Args&&... args) {
  printf("Mapping args FROM guest stack TODO - NYI\n");
  co_return 0;
}

/* Pair of macros to 1) get a mapping of {type, arg size} and 2) sum up the arg size values returned by the first */
#define get_arg_types_sizes(...) deduce_types_and_sizes(__VA_ARGS__);
#define calculate_size(_argTuple) accumulate_stack_sizes(_argTuple);

/* Helper macro to be used by SyscCoro coroutines. Build an hsyscall using the given function name,
 * yield that hsyscall (which will cause the details object to update place a return in last_sc_ret),
 * free the heap-allocated hsyscall, and finally provide the caller with the result of the simulated
 * syscall which was set in details->last_sc_ret.
 */
#define yield_syscall(details, func, ...) ({                                                                  \
  auto arg_types_tup = get_arg_types_sizes(__VA_ARGS__);                                                      \
  size_t total_size = calculate_size(arg_types_tup);                                                          \
  size_t padded_total_size = total_size + (1024 - (total_size % 1024));                                       \
  printf("Total stack size is %lu, padded to %lu\n", total_size, padded_total_size);                          \
  uint64_t guest_stack = 0;                                                                                   \
  hsyscall s = build_syscall<SYS_##func>(::func, guest_stack, __VA_ARGS__);                                   \
  if (total_size > 0)                                                                                         \
  { /* We need some stack space for the arguments for this syscall. Allocate it! */                           \
    /*printf("AUTO-ALLOCATE %d bytes (rounded up from %d)\n", padded_total_size, total_size);*/               \
    co_yield unchecked_build_syscall<SYS_mmap>(::mmap, 0, 0, padded_total_size,                               \
                                                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);  \
    guest_stack = details->last_sc_retval; /* TODO: error checking?*/                                         \
    /* Now, for each argument, map it!*/                                                                      \
    yield_from(map_args_to_guest_stack, guest_stack, &s, arg_types_tup);                                      \
  }                                                                                                           \
  co_yield s;                                                                                                 \
  int rv = details->last_sc_retval;                                                                           \
  if (total_size > 0)                                                                                         \
  { /* We previously allocated some stack space for this syscall, sync it back, then free it */               \
    yield_from(map_args_from_guest_stack, guest_stack, arg_types_tup);                                        \
    co_yield (unchecked_build_syscall<SYS_munmap>(::munmap, 0, padded_total_size));                           \
  }                                                                                                           \
  rv;                                                                                                         \
})

SyscCoro start_coopter(asid_details* details)
{
    struct sysinfo info;
    details->did_malloc = false;

    // Every call to yield_syscall will automatically map, use, then unmap memory as necessary for its arguments

    // Simulate running the sysinfo system call and get the result.
    printf("\nRun sysinfo syscall with %lu byte argument\n", sizeof(info));
    int rv = yield_syscall(details, sysinfo, &info);

    char msg[] = {"Hello from the coopter!\n"};
    printf("\n\nRun write syscall with %lu byte argument\n", sizeof(msg));
    printf("CALLER: msg is at %p, has size %lu\n", msg, sizeof(msg));
    int rv2 = yield_syscall(details, write, 1, msg, strlen(msg));

    // Finally, yield the original system call (which triggers it's execution in the guest)
    co_yield *(details->orig_syscall);

    co_return 0;
}

extern "C" create_coopt_t* should_coopt(void *cpu, long unsigned int callno, long unsigned int pc, unsigned int asid);

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

  if (callno == __NR_getuid || callno == __NR_geteuid)
    return &start_coopter;

  return NULL;
}

SyscCoro test(asid_details* details) {
  int fd = 1;
  char out_path[128];
  char in_path[128];

  snprintf(in_path, sizeof(in_path), "/proc/self/fd/%d", fd);
  int readlink_rv = yield_syscall(details, readlink, in_path, out_path, sizeof(out_path));

  printf("Readlink of %s returns %d with out_path=%s\n", in_path, readlink_rv, out_path);

  co_yield (*details->orig_syscall);

  co_return 0;
}

int main(int argc, char **argv) {

  // Start executing the start_coopter coroutine. Say we were co-opting the getuid syscall.
  asid_details *details = new asid_details({
    .orig_syscall = new hsyscall({
      .callno = __NR_getuid,
      .nargs = 0
    })
  });

  auto h = test(details).h_;
  auto &promise = h.promise();
  while(!h.done()) {
    auto sc = promise.value_;
    if (sc.callno == SYS_mmap) {
      details->last_sc_retval = 0x100000;
    }else {
      details->last_sc_retval = 0; // Lie?
    }
    h();
  }
  h.destroy();
  return 0;
}