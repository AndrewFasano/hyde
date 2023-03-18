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

  //std::function<void(_asid_details*, void*, unsigned long, unsigned long, unsigned long)> *on_ret; // Unused
} asid_details;


// create_coopt_t functions are called with a bunch of stuff and return a pointer to a function with type SyscCoro(asid_details*)
typedef SyscCoro(create_coopt_t)(asid_details*);
// create_coopt_t is function type that is given a few arguments and returns a function pointer function with type create_coopt_t(asid_details*)
typedef create_coopt_t*(coopter_f)(void*, long unsigned int, long unsigned int, unsigned int);

/* TODO: replace print_pointer_info. Instead of printing the argument, we should store it in the args field of the hsyscall struct
 * that we've been given in the out pointer.
*/
template <typename T>
void print_pointer_info(uint64_t *out, const T& arg, std::integral_constant<bool, true>) {
    std::cout << "Argument at " << out << ": Pointer: " << &arg << ", size of pointed object: " << sizeof(typename std::remove_pointer<T>::type) << std::endl;
    out = 0;
}
template <typename T>
void print_pointer_info(uint64_t* out, const T& arg, std::integral_constant<bool, false>) {
  *out = (uint64_t)arg;
}
template <typename T>
void check_pointer(uint64_t* out, const T& arg) {
    print_pointer_info(out, arg, std::is_pointer<T>{});
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

    // Now generate an hsyscall object with the syscall number, arguments, and number of args
    hsyscall *s = new hsyscall;
    s->callno = SyscallNumber;
 
    // After validating that the types match, we store the arguments internally as uint64_t's, since those are what
    // we actually store in guest registers.
    // TODO: is there any hope of handling char*s and structs with a scratch buffer automatically?

    // Populate s->args with each of the elements in args and set s->nargs to the number of arguments
    int i = 0;
    (..., check_pointer(&s->args[i++], args));
    s->nargs = i;

    return s;
}

/* Helper macro to be used by SyscCoro coroutines. Build an hsyscall using the given function name,
 * yield that hsyscall (which will cause the details object to update place a return in last_sc_ret),
 * free the heap-allocated hsyscall, and finally provide the caller with the result of the simulated
 * syscall which was set in details->last_sc_ret.
 */
#define yield_syscall2(details, func, ...) ({                      \
  hsyscall *h = build_syscall<SYS_##func>(::func, ##__VA_ARGS__); \
  (co_yield *h);                                                   \
  free(h);                                                         \
  details->last_sc_retval;                                         \
})

SyscCoro start_coopter(asid_details* details) {
  printf("First get the PID\n");
  char foo[] = "/tmp/hyde_test";
  //int rv = yield_syscall2(details, socket, AF_UNIX, foo, 0);
  struct sysinfo info;

  int rv = yield_syscall2(details, sysinfo, &info);

  printf("PID is %d. Now allocate\n", rv);

  // Finally, we run the original syscall
  //details->orig_syscall->nargs = 0;
  co_yield *(details->orig_syscall); // noreturn

  co_return 0;
}

extern "C" create_coopt_t* should_coopt(void *cpu, long unsigned int callno, long unsigned int pc, unsigned int asid);

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {

  if (callno == __NR_getuid || callno == __NR_geteuid)
    return &start_coopter;

  return NULL;
}