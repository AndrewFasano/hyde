#include <iostream>
#include <type_traits>
#include <tuple>
#include <utility>
#include <assert.h>
#include <sys/sysinfo.h>

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
constexpr size_t accumulate_stack_sizes2(std::tuple<Args...> tuple) {
    size_t sum = 0;
    std::apply([&sum](auto... args) { (..., (sum += args.second)); }, tuple);
    return sum;
}

#define print_sizes(...) ({                                                                     \
  auto _argTuple = deduce_types_and_sizes(__VA_ARGS__); \
  size_t total_size = accumulate_stack_sizes2(_argTuple); \
  printf("Total stack size of arguments is %lu\n", total_size);                                 \
  total_size; \
})

int main() {
  char msg[] = {"Hello world!\n"};
  struct sysinfo info;

  printf("Msg size is %lu\n", sizeof(msg));
  assert(sizeof(msg) == print_sizes(msg));
  assert(sizeof(info) == print_sizes(&info));
  assert(sizeof(info) + sizeof(msg) == print_sizes(&info, msg));
  assert(sizeof(info) + sizeof(msg) == print_sizes(msg, &info));

  return 0;
}
