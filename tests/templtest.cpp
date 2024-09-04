#include <cstdio>
#include <cassert>
#include <sys/sysinfo.h>
#include <cstdint>
#include "static_args.h" // For deduce_types_and_sizes + accumulate_stack_sizes template class magic

// Series of templates to deduce the size of a variadic list of arguments
// This is used by yield_syscall so we can calculate the necessary stack size in guest
// memory that we will use for copying hsyscall arguments into the guest's memory

#define print_sizes(...) ({                                                       \
    auto _argTuple = deduce_types_and_sizes(__VA_ARGS__);                         \
    size_t total_size = accumulate_stack_sizes(_argTuple);                        \
    printf("Total stack size of arguments is %lu\n", total_size);                 \
    printf("First arg const is %d\n", (bool)std::get<2>(std::get<0>(_argTuple))); \
    total_size;                                                                   \
})

#define padsizeof(x) \
    (sizeof(x) + (sizeof(x) % 32 == 0 ? 0 : 32 - sizeof(x) % 32))

int main() {
  char msg[] = {"Hello world!\n"};
  struct sysinfo info;
  const char cmsg[] = {"Const hello world!\n"};

  uint64_t foo = 0xdeadbeef;
  assert(0 == print_sizes(foo));
  assert(padsizeof(msg) == print_sizes(msg));
  assert(padsizeof(info) == print_sizes(&info));
  assert(padsizeof(info) + padsizeof(msg) == print_sizes(&info, msg));
  assert(padsizeof(info) + padsizeof(msg) == print_sizes(msg, &info));
  assert(padsizeof(cmsg) == print_sizes(cmsg));

  return 0;
}
