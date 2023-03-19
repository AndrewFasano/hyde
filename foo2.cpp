#include <iostream>
#include <type_traits>
#include <tuple>
#include <utility>
#include <sys/sysinfo.h>

// Calculate the total size of all non-integer arguments 
template <typename... Args>
size_t accumulate_stack_sizes2(std::tuple<Args...> tuple) {
    size_t sum = 0;
    std::apply([&sum](auto... args) { (..., (sum += args.second)); }, tuple);
    return sum;
}

// The deduce_type_and_size function is used to deduce the type and size of
// non-integer arguments. It is used to generate a tuple of type and size pairs.

// When T is not an array, we need to compute its size, if we can
// TODO: this is incorrect, we hit the else branch when calling print_sizes(&info)
// and fail to calculate the size of the struct. We should be able to deduce the
// size at compile time!
template <typename T>
auto deduce_type_and_size(T&& arg) {
    if constexpr (std::is_array_v<std::remove_reference_t<T>>) {
        return std::make_pair(arg, sizeof(std::remove_reference_t<T>));
    } else if constexpr (std::is_pointer_v<std::remove_reference_t<T>>) {
        return std::make_pair(arg, sizeof(typename std::remove_pointer<std::remove_reference_t<T>>::type));
    } else {
        return std::make_pair(arg, sizeof(std::remove_reference_t<T>));
    }
}


// When T is an array, we compute it's size. This is correct
template <typename T, size_t N>
std::pair<T*, size_t> deduce_type_and_size(T (&arr)[N]) {
    return {arr, sizeof(T) * N};
}

// Helper function to generate a tuple of type and size pairs
template <typename... Args>
auto deduce_types_and_sizes(Args&&... args) {
    return std::tuple_cat(std::make_tuple(deduce_type_and_size(args))...);
}

#define print_sizes(...) ({                                                                     \
  auto _argTuple = deduce_types_and_sizes(__VA_ARGS__); \
  size_t total_size = accumulate_stack_sizes2(_argTuple); \
  printf("Total stack size of arguments is %lu\n", total_size);                                 \
  total_size; \
});

int main() {
  char msg[] = {"Hello world!\n"};
  struct sysinfo info;

  printf("Msg size is %lu\n", sizeof(msg));
  print_sizes(msg);

  puts("");

  printf("info size is %lu\n", sizeof(info));
  print_sizes(&info); // TODO: this output is incorrect, it prints a size of 8

  printf("Both together have size %lu\n", sizeof(msg) + sizeof(info));
  print_sizes(msg, &info);
  print_sizes(&info, msg);

  return 0;
}
