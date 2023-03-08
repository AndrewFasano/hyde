#include <future>
#include <coroutine>
#include <assert.h>
#include <stdint.h>
#include <syscall.h>
#include <linux/kvm.h>

typedef struct {
  unsigned int callno;
  unsigned long args[6];
  unsigned int nargs;
  uint64_t retval; // Only used when co-opting
  bool has_retval;
} hsyscall;

// Co-routine classes based off https://www.scs.stanford.edu/~dm/blog/c++-coroutines.html
struct SyscCoroutine {
  struct promise_type {
    hsyscall value_;

    ~promise_type() { }

    SyscCoroutine get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {}

    // Regular yield, returns an hsyscall value
    std::suspend_always yield_value(hsyscall value) {
      value_ = value;
      return {};
    }

    void return_void() {}

  };

  std::coroutine_handle<promise_type> h_;
};

typedef std::coroutine_handle<SyscCoroutine::promise_type> coopter_t;
#define on_ret_t void(_asid_details*, void*, unsigned long, unsigned long, unsigned long)

typedef struct _asid_details {
  coopter_t coopter;
  struct kvm_regs orig_regs;
  hsyscall *orig_syscall;
  void* cpu;
  long unsigned int retval;
#ifdef DEBUG
  unsigned int injected_callno; // Debug only
#endif
  unsigned int asid;
  unsigned long int orig_rcx;
  unsigned long int orig_r11;
  bool use_orig_regs; // If set, after sysret we'll restore RCX/R11 to their pre-syscall values
  unsigned long custom_return;
  bool modify_original_args;
  std::function<void(struct kvm_regs*)> *modify_on_ret;

  std::function<on_ret_t> *on_ret;
  hsyscall scratch;
} asid_details;

typedef SyscCoroutine(create_coopt_t)(asid_details*);
typedef create_coopt_t*(coopter_f)(void*, long unsigned int, long unsigned int, unsigned int);

static void _build_syscall(hsyscall* s, unsigned int callno, int nargs,
    int unsigned long arg0, int unsigned long arg1, int unsigned long arg2,
    int unsigned long arg3, int unsigned long arg4, int unsigned long arg5) {
  s->callno = callno;
  s->nargs = nargs;
  if (nargs > 0) s->args[0] = arg0;
  if (nargs > 1) s->args[1] = arg1;
  if (nargs > 2) s->args[2] = arg2;
  if (nargs > 3) s->args[3] = arg3;
  if (nargs > 4) s->args[4] = arg4;
  if (nargs > 5) s->args[5] = arg5;
}

void build_syscall(hsyscall*, unsigned int callno);
void build_syscall(hsyscall* s, unsigned int callno) {
  _build_syscall(s, callno, 0, /*args:*/0, 0, 0, 0, 0, 0);
}

#define yield_syscall(r, ...) (build_syscall(&r->scratch, __VA_ARGS__), (co_yield r->scratch), r->retval)

SyscCoroutine my_coopter(asid_details* a) {
    printf("Yield syscall\n");
    int rv = yield_syscall(a, __NR_getpid);
    printf("Syscall 1 gets return %d\n", rv);

    printf("Yield another syscall\n");
    int rv2 = yield_syscall(a, __NR_getpid);
    printf("Syscall 2 gets return %d\n", rv2);

    printf("End of co-opter fn\n");
    co_return;
}

create_coopt_t* should_coopt(void *cpu, long unsigned int callno,
                             long unsigned int pc, unsigned int asid) {
  // We inject syscalls starting at every execve
  if (callno == __NR_execve)
    return &my_coopter;
  return NULL;
}


int main() {
  asid_details *a;
    create_coopt_t *f = should_coopt(NULL, __NR_execve, 0, 0);
    assert (f != NULL);

    a = new asid_details;
    printf("A scratch is at %p\n", &a->scratch);

    // XXX this *RUNS* the coopter to the first yielded SC
    a->coopter = (*f)(a).h_;

    while (true) {
        auto &promise = a->coopter.promise();
        if (a->coopter.done()) {
            printf("Coopter is done\n");
            break;
        }
        hsyscall sysc = promise.value_;
        int retval = rand() % 100;
        printf("Yielded syscall %d pretend running it returns %d\n", sysc.callno, retval);
        a->retval = retval;

        a->coopter();
    }

    delete a;
    return 0;
}
