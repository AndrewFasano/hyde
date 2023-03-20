#include "sys/socket.h"
#include "sys/syscall.h"
#include <sys/sysinfo.h>
#include "sys/types.h"
#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <iostream> // Just for cout
#include <stdio.h>
#include <string>
#include <sys/mman.h> // for mmap flags
#include <type_traits>
#include <unistd.h>
#include <vector>
#include <linux/kvm.h>
#include <assert.h>

#include <type_traits>
#include <tuple>
#include <utility>


#include <coroutine>
#include <functional>
//#include "hyde_common.h"

struct hsyscall_arg {
  union {
    uint64_t host_pointer;
    uint64_t constant;
  } value;
  bool is_ptr; // tagged union

  uint64_t guest_ptr; // 0 if non-pointer
  unsigned int size;
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
template <typename T>
auto deduce_type_and_size_impl(T* arg, std::false_type) {
    return std::make_pair(arg, sizeof(std::remove_pointer_t<T>));
}
template <typename T, size_t N>
auto deduce_type_and_size_impl(T (&arr)[N], std::true_type) {
    return std::make_pair(arr, sizeof(T) * N);
}
template <typename T>
auto deduce_type_and_size(T&& arg) {
    return deduce_type_and_size_impl(std::forward<T>(arg), std::is_array<std::remove_reference_t<T>>{});
}
template <typename... Args>
auto deduce_types_and_sizes(Args&&... args) {
    return std::tuple_cat(std::make_tuple(deduce_type_and_size(std::forward<Args>(args)))...);
}

template <typename... Args>
constexpr size_t accumulate_stack_sizes(std::tuple<Args...> tuple) {
    size_t sum = 0;
    std::apply([&sum](auto... args) { (..., (sum += args.second)); }, tuple);
    return sum;
}

/* Calculate the total size of the arguments that can't be stored in registers */
#define get_arg_size(...) ({                                                                     \
  auto _argTuple = deduce_types_and_sizes(__VA_ARGS__); \
  size_t total_size = accumulate_stack_sizes(_argTuple); \
  total_size; \
})


template <long SyscallNumber, typename Function, typename... Args>
hsyscall* unchecked_build_syscall(Function syscall_func, uint64_t guest_stack, Args... args) {
    //printf("Inject syscall %ld with %ld args, total size %ld\n", SyscallNumber, sizeof...(Args), TotalSize);
    // Now generate an hsyscall object with the syscall number, arguments, and number of args
    hsyscall *s = new hsyscall;
    s->callno = SyscallNumber;
 
    // Populate s->args with each of the elements in args and set s->nargs to the number of arguments.
    // Also populate s->arg_sizes with the size of each argument 
    int i = 0;
    auto set_args = [&s, &i](auto &&arg) {
      assert(i < sizeof(s->args) / sizeof(s->args[0])); // Make sure we don't go OOB
      s->args[i++].value.constant = arg;
    };
    (set_args(args), ...);

    s->nargs = i;
    return s;
}

/* Given a system call number, a function pointer to the system call, and a list of arguments, allocate, initialize
 * and return na hsyscall object
 */
template <long SyscallNumber, typename Function, typename... Args>
hsyscall* build_syscall(Function syscall_func, uint64_t guest_stack, Args... args) {
    using ReturnType = decltype(syscall_func(std::declval<Args>()...));
    using ExpectedArgsTuple = std::tuple<typename std::remove_reference<Args>::type...>;
    using ActualArgsTuple = std::tuple<typename std::remove_reference<decltype(std::declval<Args>())>::type...>;

    // Ensure that the specified arguments match the syscall signature
    // Note that every syscall for linux returns a long so we don't need to typecheck that
    static_assert(std::is_same_v<ExpectedArgsTuple, ActualArgsTuple>,
                  "Argument types do not match the syscall signature.");

    return unchecked_build_syscall<SyscallNumber>(syscall_func, guest_stack, args...);
}

/* Helper macro to be used by SyscCoro coroutines. Build an hsyscall using the given function name,
 * yield that hsyscall (which will cause the details object to update place a return in last_sc_ret),
 * free the heap-allocated hsyscall, and finally provide the caller with the result of the simulated
 * syscall which was set in details->last_sc_ret.
 */
#define yield_syscall(details, func, ...) ({                                                                     \
  constexpr size_t total_size = get_arg_size<decltype(__VA_ARGS__)>();                                 \
  constexpr size_t padded_total_size = total_size + (1024 - (total_size % 1024));                                \
  uint64_t guest_stack = 0;                                                                                           \
  if (total_size > 0)                                                                                            \
  { /* We need some stack space for the arguments for this syscall. Allocate it! */                              \
    hsyscall *h = unchecked_build_syscall<SYS_mmap>(::mmap, 0, 0, padded_total_size,                                \
                                                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); \
    (co_yield *h);                                                                                               \
    free(h);                                                                                                     \
    guest_stack = details->last_sc_retval;                                                                       \
  }                                                                                                              \
  hsyscall *h = build_syscall<SYS_##func>(::func, guest_stack, __VA_ARGS__);                                                \
  (co_yield *h);                                                                                                 \
  free(h);                                                                                                       \
  int rv = details->last_sc_retval;                                                                              \
  if (total_size > 0)                                                                                            \
  { /* We previously allocated some stack space for this syscall, free it */                                     \
    hsyscall *h = unchecked_build_syscall<SYS_munmap>(::munmap, 0, padded_total_size);        \
    (co_yield *h);                                                                                               \
    free(h);                                                                                                     \
  }                                                                                                              \
  rv;                                                                                                            \
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