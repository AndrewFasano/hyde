#include <iostream>
#include <type_traits>
#include <tuple>
#include <utility>
#include <sys/sysinfo.h>

template <typename T>
size_t stack_size2() {
    if constexpr (std::is_array_v<T>) {
        return sizeof(T);
    } else if constexpr (std::is_pointer_v<T>) {
        return sizeof(typename std::remove_pointer<T>::type);
    } else {
        return 0;
    }
}

template <typename... Args>
size_t accumulate_stack_sizes2(std::tuple<Args...> tuple) {
    size_t sum = 0;
    std::apply([&sum](auto... args) { (..., (sum += args.second)); }, tuple);
    return sum;
}

template <typename T>
std::pair<T, size_t> deduce_type_and_size(T&& arg) {
    return {arg, sizeof(typename std::remove_pointer<T>::type)};
}

template <typename T, size_t N>
std::pair<T*, size_t> deduce_type_and_size(T (&arr)[N]) {
    return {arr, sizeof(T) * N};
}

#define print_sizes(...) ({                                                                     \
  auto _argTuple = std::make_tuple(deduce_type_and_size(__VA_ARGS__)); \
  size_t total_size = accumulate_stack_sizes2(_argTuple); \
  printf("Total stack size of arguments is %lu\n", total_size);                                 \
  total_size; \
});

int main() {
  char msg[] = {"Hello world!\n"};
  struct sysinfo info;

  printf("Msg size is %lu\n", sizeof(msg));
  print_sizes(msg);

  printf("info size is %lu\n", sizeof(info));
  print_sizes(&info);

  //printf("Both together have size %lu\n", sizeof(msg) + sizeof(info));
  //print_sizes(msg, &info);
  //print_sizes(&info, msg);

  return 0;
}
