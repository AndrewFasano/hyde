// Series of templates to deduce the size of a variadic list of arguments
// This is used by yield_syscall so we can calculate the necessary stack size in guest
// memory that we will use for copying hsyscall arguments into the guest's memory
#include <type_traits>
#include <tuple>
#include <utility>

// Handle non-array, non-pointer types
template <typename T>
auto deduce_type_and_size_impl(T&& arg, std::false_type, std::false_type) {
    //return std::make_pair(&arg, sizeof(T));
    return std::tuple(&arg, 0, false); // XXX: Do *not* count the size of these types
}

// Handle pointer types
template <typename T>
auto deduce_type_and_size_impl(T* arg, std::false_type, std::true_type) {
    return std::tuple(arg, sizeof(std::remove_pointer_t<T>), std::is_const_v<std::remove_pointer_t<T>>);
}

// Handle array types
template <typename T, size_t N>
auto deduce_type_and_size_impl(T (&arr)[N], std::true_type, std::false_type) {
    return std::tuple(arr, sizeof(std::remove_extent_t<T>) * N, std::is_const_v<std::remove_extent_t<T>>);
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
    // If the size is nonzeo count it and pad it to 32-bits to match how we do actual allocations
    std::apply([&sum](auto... args) { (..., (sum += std::get<1>(args) ? (std::get<1>(args) + (32 - (std::get<1>(args) % 32))): 0 ) ); }, tuple);
    return sum;
}