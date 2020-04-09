#pragma once

#include "utility.hxx"

#define SERDES_TUPLE(...)                       \
  auto tuple() {                                \
    return make_tuple_refs(__VA_ARGS__);        \
  }
#define SERDES_CTUPLE(...)                      \
  auto tuple() const {                          \
    return make_tuple_crefs(__VA_ARGS__);       \
  }
#define SERDES_NAMES(M_list)                                    \
  static char const** names() {                                 \
    static char const* xs[] = {BOOST_PP_LIST_ENUM(M_list)};     \
    return xs;                                                  \
  }
#define SERDES_NAMES_OP(M_r, M_data, M_elem) BOOST_PP_STRINGIZE(M_elem)

#define SERDES(...)                                                     \
  SERDES_TUPLE(__VA_ARGS__)                                             \
  SERDES_CTUPLE(__VA_ARGS__)                                            \
  SERDES_NAMES(                                                         \
      BOOST_PP_LIST_TRANSFORM(                                          \
          SERDES_NAMES_OP, @,                                           \
          BOOST_PP_VARIADIC_TO_LIST(__VA_ARGS__)))                      \

template <typename T>
concept
#if defined(_GNUC)
bool
#endif
SerDes = requires(T&& o) {
  o.names();
  o.tuple();
};
