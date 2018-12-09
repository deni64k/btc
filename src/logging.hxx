#pragma once

#include <fstream>
#include <iomanip>
#include <iostream>
#include <cstdint>

#include "utility.hxx"

namespace btc {

namespace streams {

extern std::ofstream Null;
}

}

namespace logging {
namespace details {

struct log_record {
  constexpr log_record(std::ostream& os): os_(os) {}
  ~log_record() { os_ << '\n'; }

  inline constexpr std::ostream& stream() const { return os_; }

 private:
  std::ostream& os_;
};

}

enum: std::uint_fast8_t {
  LEVEL_PANIC   = 0,
  LEVEL_ERROR   = 1,
  LEVEL_WARNING = 2,
  LEVEL_INFO    = 3,
  LEVEL_DEBUG   = 4,
  LEVEL_TRACE   = 5
};

}

constexpr auto enabled_log_level = logging::LEVEL_DEBUG;
auto& enabled_log_stream = std::cerr;

#define PANIC()                                                         \
  if (logging::LEVEL_PANIC <= enabled_log_level)                        \
    logging::details::log_record(enabled_log_stream).stream()           \
        << "PANIC: " << PP_WHERE << " `" << PP_FUNCTION << "': "

#define ERROR()                                                 \
  if (logging::LEVEL_ERROR <= enabled_log_level)                \
    logging::details::log_record(enabled_log_stream).stream()   \
        << "ERROR: "

#define WARN()                                                  \
  if (logging::LEVEL_WARNING <= enabled_log_level)              \
    logging::details::log_record(enabled_log_stream).stream()   \
        << "WARN : "

#define INFO()                                                  \
  if (logging::LEVEL_INFO <= enabled_log_level)                 \
    logging::details::log_record(enabled_log_stream).stream()   \
        << "INFO : "

#define DEBUG()                                                         \
  if (logging::LEVEL_DEBUG <= enabled_log_level)                        \
    logging::details::log_record(enabled_log_stream).stream()           \
        << "DEBUG: " << PP_WHERE << " `" << PP_FUNCTION << "': "

#define TRACE()                                                         \
  if (logging::LEVEL_TRACE <= enabled_log_level)                        \
    logging::details::log_record(enabled_log_stream).stream()           \
        << "TRACE: " << PP_WHERE << " `" << PP_FUNCTION << "': "
