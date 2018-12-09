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

namespace std {

template <typename T>
using remove_cvref = remove_cv<typename remove_reference<T>::type>;

template <typename T>
using remove_cvref_t = typename remove_cvref<T>::type;

}

template <typename T>
concept bool Iterable = requires(T&& o) {
  begin(std::forward<T>(o));
  end(std::forward<T>(o));
};
