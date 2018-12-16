#pragma once

#include <array>
#include <cstdlib>

#include "serdes.hxx"

using hash_t   = std::array<std::uint8_t, 32>;
using hash32_t = std::array<std::uint32_t, 8>;
using hash64_t = std::array<std::uint64_t, 4>;

using addr_t = std::array<std::uint8_t, 16>;

struct var_int {
  std::uint64_t num;
  operator std::uint64_t () const { return num; }
};

struct be_uint16_t {
  std::uint16_t num;
  operator std::uint16_t () const { return num; }
};

using var_str = std::string;

struct hash_t_key {
  std::size_t operator () (hash_t const& h) const noexcept {
    using sv_t = std::basic_string_view<char>;
    return std::hash<sv_t>{}(sv_t{reinterpret_cast<char const*>(h.data()), h.size()});
  }
};

struct net_addr {
  // The Time (version >= 31402). Not present in version message.
  std::uint32_t time;
  // Same service(s) listed in version
  std::uint64_t services;
  // IPv6 address. Network byte order.
  // (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
  addr_t addr;
  // Port number, network byte order
  be_uint16_t port;

  SERDES(time, services, addr, port)
};

struct net_addr_version {
  // Same service(s) listed in version
  std::uint64_t services;
  // IPv6 address. Network byte order.
  // (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
  addr_t addr;
  // Port number, network byte order
  be_uint16_t port;

  SERDES(services, addr, port)
};

namespace {

std::string addr_to_s(addr_t addr) {
  bool is_ipv6 = false;
  for (int i = 0; i < 10; ++i) {
    if (addr[i]) {
      is_ipv6 = true;
      break;
    }
  }
  if (!is_ipv6 && addr[10] != 0xff && addr[11] != 0xff)
    is_ipv6 = true;

  char buf[128];
  if (is_ipv6) {
    std::snprintf(buf, sizeof(buf), "%4hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx",
                  std::uint16_t{addr[0]}  << 8 | addr[1],  std::uint16_t{addr[2]}  << 8 | addr[3],
                  std::uint16_t{addr[4]}  << 8 | addr[5],  std::uint16_t{addr[6]}  << 8 | addr[7],
                  std::uint16_t{addr[8]}  << 8 | addr[9],  std::uint16_t{addr[10]} << 8 | addr[11],
                  std::uint16_t{addr[12]} << 8 | addr[13], std::uint16_t{addr[14]} << 8 | addr[15]);
  } else {
    std::snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                  int{addr[12]}, int{addr[13]}, int{addr[14]}, int{addr[15]});
  }
  return {buf};
}

std::string prettify_hash(std::string hash) {
  for (unsigned i = hash.size() - 8; i > 0; i -= 8) {
    hash.insert(i - 1, 1, '\'');
  }
  return std::move(hash);
}

std::string to_string(hash_t const& hash) {
  char buf[65] = {'\0'};
  for (std::size_t i = 0, j = 0; i < hash.size(); ++i, j += 2) {
    unsigned char b = hash[hash.size() - i - 1];
    std::snprintf(buf + j, sizeof(buf) - j, "%02hhx", b);
  }
  return {buf};
}

inline std::string to_string(hash32_t const& hash) {
  char buf[65] = {'\0'};
  for (std::size_t i = 0, j = 0; i < hash.size(); ++i, j += 8) {
    std::uint32_t b = hash[hash.size() - i - 1];
    std::snprintf(buf + j, sizeof(buf) - j, "%08x", b);
  }
  return {buf};
}

inline std::string to_string(hash64_t const& hash) {
  char buf[65] = {'\0'};
  for (std::size_t i = 0, j = 0; i < hash.size(); ++i, j += 16) {
    std::uint64_t b = hash[hash.size() - i - 1];
    std::snprintf(buf + j, sizeof(buf) - j, "%016llx", b);
  }
  return {buf};
}

inline std::string target_to_s(std::uint32_t bits) {
  std::string buf = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  unsigned int val = bits & 0x00ffffffU;
  int exp = (bits >> 24) - 3;
  int off = buf.size() - exp*2 - 6;
  std::snprintf(buf.data() + off, 7, "%06x", val);
  for (int i = 0; i < off; ++i) {
    buf[i] = '0';
  }
  for (unsigned i = off+6; i < buf.size(); ++i) {
    buf[i] = 'f';
  }
  return std::move(buf);
}

inline hash_t to_hash(hash32_t const& hash) {
  hash_t result_hash;
  for (unsigned i = 0, j = 0; i < hash.size(); ++i) {
    result_hash[j++] = (hash[i] >> (sizeof(std::uint32_t) - 4)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint32_t) - 3)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint32_t) - 2)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint32_t) - 1)*8) & 0xff;
  }
  return std::move(result_hash);
}

inline hash_t to_hash(hash64_t const& hash) {
  hash_t result_hash;
  for (unsigned i = 0, j = 0; i < hash.size(); ++i) {
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 8)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 7)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 6)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 5)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 4)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 3)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 2)*8) & 0xff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 1)*8) & 0xff;
  }
  return std::move(result_hash);
}

inline hash32_t to_hash32(hash64_t const& hash) {
  hash32_t result_hash;
  for (unsigned i = 0, j = 0; i < hash.size(); ++i) {
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 8)*8) & 0xffffffff;
    result_hash[j++] = (hash[i] >> (sizeof(std::uint64_t) - 4)*8) & 0xffffffff;
  }
  return std::move(result_hash);
}

inline hash64_t vectorize_hash(hash_t const& hash) {
  std::array<std::uint64_t, 4> vec = {0, 0, 0, 0};
  for (unsigned i = 0; i < vec.size(); ++i) {
    for (int j = i*8, k = 64-8; k >= 0; ++j, k -= 8) {
      unsigned char b = hash[hash.size() - j - 1];
      vec[i] |= std::uint64_t{b} << k;
    }
  }
  return std::move(vec);
}

inline hash64_t target_to_hash64(std::uint32_t bits) {
  auto target = target_to_s(bits);
  INFO() << "target_to_hash64: target: " << target;
  hash64_t vec;
  std::sscanf(target.c_str(), "%016llx%016llx%016llx%016llx",
              &vec[0], &vec[1], &vec[2], &vec[3]);
  for (auto& x : vec)
    x = (std::uint64_t(ntohl(x & 0xffffffff)) << 32) | ntohl(x >> 32);
  return std::move(vec);
}

inline hash32_t target_to_hash32(std::uint32_t bits) {
  auto target = target_to_s(bits);
  // INFO() << "target_to_hash32: target: " << target;
  hash32_t vec;
  std::sscanf(target.c_str(), "%08x%08x%08x%08x%08x%08x%08x%08x",
              &vec[7], &vec[6], &vec[5], &vec[4],
              &vec[3], &vec[2], &vec[1], &vec[0]);
  for (auto& x : vec)
    x = ntohl(x);
  return std::move(vec);
}

int compare_hashes(hash32_t const& lhs, hash32_t const& rhs) {
  for (int i = lhs.size() - 1; i >= 0; --i) {
    if (lhs[i] < rhs[i])
      return -1;
    else if (lhs[i] > rhs[i])
      return 1;
  }
  return 0;
}

}
