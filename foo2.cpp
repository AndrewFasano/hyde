#include <iostream>
#include <type_traits>
#include <tuple>
#include <utility>
#include <assert.h>
#include <sys/sysinfo.h>

/* The deduce_type_and_size function is used to deduce the type of arguments and,
* for arguments that cannot be directly placed into registers, their size.
* In particular, we calculate the size of pointed-to structs and arrays.
* We do this through two specializations - one for arrays, and one for everything else.
* In the everything-else case, we check if it's a pointer and calculate the size of
* the pointed-to type if it is. otherwise we report a size of 0.
*/


/* When T is a pointer, we need to calculated the size of the pointed-to type
 * Note this is *NOT* recrusive - if a pointed-to type contains additional pointers
 * we won't calculate the sizes of what they point to
 */
template <typename T>
auto deduce_type_and_size(T&& arg) {
     if constexpr (std::is_pointer_v<std::remove_reference_t<T>>) {
        // If T is a pointer, calculate the size of the pointed-to type
        return std::make_pair(arg, sizeof(typename std::remove_pointer<std::remove_reference_t<T>>::type));
    } else {
        /* Otherwise T isn't a pointer, and it can't be an array if we're here.
         * So we just return a size of 0. If we wanted the size of the type, we could
         * have used sizeof(std::remove_reference_t<T>)
         */
        return std::make_pair(arg, 0); // When T is not an
    }
}

// TODO: are there any cases this will fail to handle? Can we detect those and
// raise compile-time errors?

// When T is an array, we compute it's size
template <typename T, size_t N>
std::pair<T*, size_t> deduce_type_and_size(T (&arr)[N]) {
    return {arr, sizeof(T) * N};
}

// Helper function to generate a tuple of type and size pairs
template <typename... Args>
auto deduce_types_and_sizes(Args&&... args) {
    return std::tuple_cat(std::make_tuple(deduce_type_and_size(args))...);
}

// Given a tuple of (type, size) pairs, accumulate the sizes
template <typename... Args>
size_t accumulate_stack_sizes2(std::tuple<Args...> tuple) {
    size_t sum = 0;
    std::apply([&sum](auto... args) { (..., (sum += args.second)); }, tuple);
    return sum;
}


/* Calculate the total size of arguments that can't fit into registers,
* as previously described. Print this information and return it.
*/
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
  // Tests
  assert(sizeof(msg) == print_sizes(msg));
  assert(sizeof(info) == print_sizes(&info));
  assert(sizeof(info) + sizeof(msg) == print_sizes(&info, msg));
  assert(sizeof(info) + sizeof(msg) == print_sizes(msg, &info));

  return 0;
}
