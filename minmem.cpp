#include "sys/socket.h"
#include "sys/syscall.h"
#include "sys/sysinfo.h"
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
#include <coroutine>

#include <coroutine>
#include <functional>
//#include "hyde_common.h"

// hsyscall is a struct that represents a system call that we will simulate execution of.
// Before the syscall is simulated, it should be populated with callno, nargs, and args.
// After the syscall is simulated, retval will store the return value and has_retval will be set to true.
typedef struct {
  uint64_t callno; // System call number
  unsigned int nargs; // Number of arguments
  uint64_t args[6]; // Arguments for the syscall

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

// Calculate the size of all arguments in a variadic template

template<typename T>
constexpr size_t stack_size() {
    if constexpr (std::is_array_v<T>) {
      // Array - calculate size
      return sizeof(typename std::remove_extent<T>::type) * std::extent_v<T>;
    } else if constexpr (std::is_pointer_v<T>) {
      // Pointer - calculate size of pointed object
      return sizeof(typename std::remove_pointer<T>::type);
    } else {
      // Non-pointer type, doesn't count
      return 0;
    }
}

// Given a list of types, calculate the total size of all non-int arguments
template <typename... Args>
constexpr size_t accumulate_stack_sizes() {
  // For each in Args, call stack_size and add the result to the sum
  return (stack_size<Args>() + ...);
}

/* TODO: replace print_pointer_info. Instead of printing the argument, we should store it in the args field of the hsyscall struct
 * that we've been given in the out pointer.
*/
template <typename T>
void _set_arg(uint64_t *out, uint64_t *cumulative_size, const T& arg, std::integral_constant<bool, true>) {
  // This argument is a pointer type, so we update cumulative size
    std::cout << "Argument at " << out << ": Pointer: " << &arg << ", size of pointed object: " << sizeof(typename std::remove_pointer<T>::type) << std::endl;
    out = 0;
    *cumulative_size += sizeof(typename std::remove_pointer<T>::type);
}
template <typename T>
void _set_arg(uint64_t* out, uint64_t *cumulative_size, const T& arg, std::integral_constant<bool, false>) {
  *out = (uint64_t)arg;
  // We don't update cumulative_size here here because this argument isn't a pointer
}
template <typename T>
void set_arg(uint64_t* out, const T& arg) {
    uint64_t arg_pointer_size = 0;
    _set_arg(out, &arg_pointer_size, arg, std::is_pointer<T>{});
}

template <long SyscallNumber, typename Function, typename... Args>
hsyscall* unchecked_build_syscall(Function syscall_func, Args... args) {
    //printf("Inject syscall %ld with %ld args, total size %ld\n", SyscallNumber, sizeof...(Args), TotalSize);
    // Now generate an hsyscall object with the syscall number, arguments, and number of args
    hsyscall *s = new hsyscall;
    s->callno = SyscallNumber;
 
    // After validating that the types match, we store the arguments internally as uint64_t's, since those are what
    // we actually store in guest registers.
    // TODO: is there any hope of handling char*s and structs with a scratch buffer automatically?

    // Populate s->args with each of the elements in args and set s->nargs to the number of arguments
    int i = 0;
    (..., set_arg(&s->args[i++], args));
    s->nargs = i;

    return s;
}

/* Given a system call number, a function pointer to the system call, and a list of arguments, allocate, initialize
 * and return na hsyscall object
 */
template <long SyscallNumber, typename Function, typename... Args>
hsyscall* build_syscall(Function syscall_func, Args... args) {
    using ReturnType = decltype(syscall_func(std::declval<Args>()...));
    using ExpectedArgsTuple = std::tuple<typename std::remove_reference<Args>::type...>;
    using ActualArgsTuple = std::tuple<typename std::remove_reference<decltype(std::declval<Args>())>::type...>;

    // Ensure that the specified arguments match the syscall signature
    // Note that every syscall for linux returns a long so we don't need to typecheck that
    static_assert(std::is_same_v<ExpectedArgsTuple, ActualArgsTuple>,
                  "Argument types do not match the syscall signature.");

    return unchecked_build_syscall<SyscallNumber>(syscall_func, args...);
}

/* Helper macro to be used by SyscCoro coroutines. Build an hsyscall using the given function name,
 * yield that hsyscall (which will cause the details object to update place a return in last_sc_ret),
 * free the heap-allocated hsyscall, and finally provide the caller with the result of the simulated
 * syscall which was set in details->last_sc_ret.
 */
#define yield_syscall(details, func, ...) ({                                                                                    \
  constexpr size_t total_size = accumulate_stack_sizes<decltype(__VA_ARGS__)>();                                                \
  constexpr size_t padded_total_size = total_size + (1024 - (total_size % 1024));                                               \
  if (total_size > 0)                                                                                                           \
  { /* We need some stack space for the arguments for this syscall. Allocate it! */                                             \
    hsyscall *h = unchecked_build_syscall<SYS_mmap>(::mmap, 0, padded_total_size ,                                              \
               PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);                                                     \
    (co_yield *h);                                                                                                              \
    free(h);                                                                                                                    \
    details->guest_stack = details->last_sc_retval;                                                                             \
  }                                                                                                                             \
  hsyscall *h = build_syscall<SYS_##func>(::func, ##__VA_ARGS__);                                                               \
  (co_yield *h);                                                                                                                \
  free(h);                                                                                                                      \
  int rv = details->last_sc_retval;                                                                                             \
  if (total_size > 0)                                                                                                           \
  { /* We previously allocated some stack space for this syscall, free it */                                                    \
    hsyscall *h = unchecked_build_syscall<SYS_munmap>(::munmap, details->guest_stack, padded_total_size);                       \
    (co_yield *h); \
    free(h); \
  } \
  rv; \
})

SyscCoro start_coopter(asid_details* details)
{
    struct sysinfo info;
    details->did_malloc = false;

    // Every call to yield_syscall will automatically map, use, then unmap memory as necessary for its arguments

    // Simulate running the sysinfo system call and get the result.
    int rv = yield_syscall(details, sysinfo, &info);

    char msg[] = {"Hello from the coopter!\n"};
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