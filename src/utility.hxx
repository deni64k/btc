#pragma once

#include <type_traits>

#include <boost/preprocessor.hpp>

#if defined(__GNUC__)
# define PP_FUNCTION __PRETTY_FUNCTION__
#elif defined(_MSC_VER)
# define PP_FUNCTION __FUNCSIG__
#else
# define PP_FUNCTION __func__
#endif

#define PP_QUOTE(x)     #x
#define PP_STRINGIZE(x) PP_QUOTE(x)
#define PP_WHERE        __FILE__ ":" PP_STRINGIZE(__LINE__)

#if defined(__GNUC__) && __GNUC__ < 9
namespace std {

template <typename T>
using remove_cvref = remove_cv<typename remove_reference<T>::type>;

template <typename T>
using remove_cvref_t = typename remove_cvref<T>::type;

}
#endif

template <typename T>
concept
#if defined(_GNUC)
bool
#endif
Iterable = requires(T&& o) {
  begin(std::forward<T>(o));
  end(std::forward<T>(o));
};

std::uint64_t gen_nonce() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<std::uint64_t> dis(0, UINT64_MAX);

  return dis(gen);
}

template <typename ...Ts> std::tuple<Ts&...> make_tuple_refs(Ts&... ts) {
  return {ts...};
}
template <typename ...Ts> std::tuple<Ts const&...> make_tuple_crefs(Ts const&... ts) {
  return {ts...};
}
