#include <type_traits>
#include <tuple>
#include <utility>

template <typename T>
auto deduce_type_and_size_impl(T&& arg, std::false_type, std::false_type);

// Handle pointer types
template <typename T>
auto deduce_type_and_size_impl(T* arg, std::false_type, std::true_type);

// Handle array types
template <typename T, size_t N>
auto deduce_type_and_size_impl(T (&arr)[N], std::true_type, std::false_type);

template <typename T>
auto deduce_type_and_size(T&& arg);

template <typename... Args>
auto deduce_types_and_sizes(Args&&... args);


template <typename... Args>
constexpr size_t accumulate_stack_sizes(std::tuple<Args...> tuple);

// Note we include the tpp here - it's a template file so we need it to be a header, not a built object
// but it's nice to keep the implementation seperate from the interface that we've defined above
#include "static_args.tpp"