// cxx = g++-8
// cxxflags = -std=c++2a -fconcepts -Wall -Werror -pedantic

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "picosha2.h"

#if 0
#define TRACE \
  std::cerr << __PRETTY_FUNCTION__ << ':' << __LINE__ << std::endl;
#else
#define TRACE
#endif

static_assert(__cpp_concepts >= 201500, "Compile with -fconcepts");
static_assert(__cplusplus >= 201500, "C++17 at least required");

namespace std {
template <typename T>
using remove_cvref_t = remove_cv_t<remove_reference_t<T>>;
}

using namespace std;

std::uint64_t gen_nonce() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<std::uint64_t> dis(0, UINT64_MAX);

  return dis(gen);
}

struct var_int {
  std::uint64_t num;
  operator std::uint64_t () const { return num; }
};

struct be_uint16_t {
  std::uint16_t num;
  operator std::uint16_t () const { return num; }
};

using hash_t = std::array<std::uint8_t, 32>;
using addr_t = std::array<std::uint8_t, 16>;

struct var_str {};

template <typename ...Ts> std::tuple<Ts&...> make_tuple_refs(Ts&... ts) {
  return {ts...};
}
template <typename ...Ts> std::tuple<Ts const&...> make_tuple_crefs(Ts const&... ts) {
  return {ts...};
}

struct header {
  enum: std::uint32_t {
    NETWORK_MAIN = 0xD9B4BEF9
  };

  // Magic value indicating message origin network, and used to seek to next message when stream state is unknown
  std::uint32_t magic;
  // ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
  std::array<char, 12> command;
  // Length of payload in number of bytes
  std::uint32_t length;
  // First 4 bytes of sha256(sha256(payload))
  std::array<std::uint8_t, 4> checksum;

  auto tuple() {
    return make_tuple_refs(magic, command, length, checksum);
  }
  auto tuple() const {
    return make_tuple_crefs(magic, command, length, checksum);
  }
  static char const** names() {
    static char const* xs[] = {"magic", "command", "length", "checksum"};
    return xs;
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

  auto tuple() {
    return make_tuple_refs(time, services, addr, port);
  }
  auto tuple() const {
    return make_tuple_crefs(time, services, addr, port);
  }
  static char const** names() {
    static char const* xs[] = {"time", "services", "addr", "port"};
    return xs;
  }
};

struct net_addr_version {
  // Same service(s) listed in version
  std::uint64_t services;
  // IPv6 address. Network byte order.
  // (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
  addr_t addr;
  // Port number, network byte order
  be_uint16_t port;

  auto tuple() {
    return make_tuple_refs(services, addr, port);
  }
  auto tuple() const {
    return make_tuple_crefs(services, addr, port);
  }
  static char const** names() {
    static char const* xs[] = {"services", "addr", "port"};
    return xs;
  }
};

namespace proto {
enum {
  VERSION = 70015
};

struct version {
  enum: std::uint64_t {
    NODE_NETWORK = 1,
    NODE_GETUTXO = 2,
    NODE_BLOOM = 4,
    NODE_WITNESS = 8,
    NODE_NETWORK_LIMITED = 1024
  };

  // Identifies protocol version being used by the node
  std::int32_t version;
  // Bitfield of features to be enabled for this connection
  std::uint64_t services;
  // Standard UNIX timestamp in seconds
  std::int64_t timestamp;
  // The network address of the node receiving this message
  net_addr_version addr_recv;
  // The network address of the node emitting this message
  net_addr_version addr_from;
  // Node random nonce, randomly generated every time a version packet is sent.
  // This nonce is used to detect connections to self.
  std::uint64_t nonce;
  // User Agent (0x00 if string is 0 bytes long)
  //var_str user_agent;
  std::string user_agent;
  // The last block received by the emitting node
  std::int32_t start_height;
  // Whether the remote peer should announce relayed transactions or not, see BIP 0037
  std::uint8_t relay;

  auto tuple() {
    return make_tuple_refs(version, services, timestamp, addr_recv, addr_from, nonce,
                           user_agent, start_height, relay);
  }
  auto tuple() const {
    return make_tuple_crefs(version, services, timestamp, addr_recv, addr_from, nonce,
                            user_agent, start_height, relay);
  }
  static char const** names() {
    static char const* xs[] = {"version", "services", "timestamp", "addr_recv", "addr_from", "nonce",
                               "user_agent", "start_height", "relay"};
    return xs;
  }
};

struct addr {
  std::vector<net_addr> addrs;

  auto tuple() {
    return make_tuple_refs(addrs);
  }
  auto tuple() const {
    return make_tuple_crefs(addrs);
  }
  static char const** names() {
    static char const* xs[] = {"addrs"};
    return xs;
  }
};

struct block_headers {
  std::uint32_t version;
  std::array<std::uint8_t, 32> prev_block;
  std::array<std::uint8_t, 32> merkle_root;
  std::uint32_t timestamp;
  std::uint32_t bits;
  std::uint32_t nonce;
  var_int       txn_count;

  auto tuple() {
    return make_tuple_refs(version, prev_block, merkle_root, timestamp, bits, nonce, txn_count);
  }
  auto tuple() const {
    return make_tuple_crefs(version, prev_block, merkle_root, timestamp, bits, nonce, txn_count);
  }
  static char const** names() {
    static char const* xs[] = {"version", "prev_block", "merkle_root", "timestamp", "bits", "nonce", "txn_count"};
    return xs;
  }
};

struct headers {
  std::vector<block_headers> headers;

  auto tuple() {
    return make_tuple_refs(headers);
  }
  auto tuple() const {
    return make_tuple_crefs(headers);
  }
  static char const** names() {
    static char const* xs[] = {"headers"};
    return xs;
  }
};

struct inv_vect {
  enum: std::uint32_t {
    // Any data of with this number may be ignored
    ERROR = 0,
    // Hash is related to a transaction
    MSG_TX = 1,
    // Hash is related to a data block
    MSG_BLOCK = 2,
    // Hash of a block header; identical to MSG_BLOCK. Only to be used in getdata message.
    // Indicates the reply should be a merkleblock message rather than a block message;
    // this only works if a bloom filter has been set.
    MSG_FILTERED_BLOCK = 3,
    // Hash of a block header; identical to MSG_BLOCK. Only to be used in getdata message.
    // Indicates the reply should be a cmpctblock message. See BIP 152 for more info.
    MSG_CMPCT_BLOCK = 4
  };
  
  std::uint32_t type;
  std::array<std::uint8_t, 32> hash;

  auto tuple() {
    return make_tuple_refs(type, hash);
  }
  auto tuple() const {
    return make_tuple_crefs(type, hash);
  }
  static char const** names() {
    static char const* xs[] = {"type", "hash"};
    return xs;
  }
};

struct inv {
  std::vector<inv_vect> inventory;

  auto tuple() {
    return make_tuple_refs(inventory);
  }
  auto tuple() const {
    return make_tuple_crefs(inventory);
  }
  static char const** names() {
    static char const* xs[] = {"inventory"};
    return xs;
  }
};

struct getdata {
  std::vector<inv_vect> inventory;

  auto tuple() {
    return make_tuple_refs(inventory);
  }
  auto tuple() const {
    return make_tuple_crefs(inventory);
  }
  static char const** names() {
    static char const* xs[] = {"inventory"};
    return xs;
  }
};

struct notfound {
  std::vector<inv_vect> inventory;

  auto tuple() {
    return make_tuple_refs(inventory);
  }
  auto tuple() const {
    return make_tuple_crefs(inventory);
  }
  static char const** names() {
    static char const* xs[] = {"inventory"};
    return xs;
  }
};

struct getblocks {
  std::uint32_t version;
  std::vector<hash_t> block_locator_hashes;
  hash_t hash_stop;

  auto tuple() {
    return make_tuple_refs(version, block_locator_hashes, hash_stop);
  }
  auto tuple() const {
    return make_tuple_crefs(version, block_locator_hashes, hash_stop);
  }
  static char const** names() {
    static char const* xs[] = {"version", "block_locator_hashes", "hash_stop"};
    return xs;
  }
};

struct getheaders {
  std::uint32_t version;
  std::vector<hash_t> block_locator_hashes;
  hash_t hash_stop;

  auto tuple() {
    return make_tuple_refs(version, block_locator_hashes, hash_stop);
  }
  auto tuple() const {
    return make_tuple_crefs(version, block_locator_hashes, hash_stop);
  }
  static char const** names() {
    static char const* xs[] = {"version", "block_locator_hashes", "hash_stop"};
    return xs;
  }
};

struct sendcmpct {
  std::array<char, 9> pld;

  auto tuple() {
    return make_tuple_refs(pld);
  }
  auto tuple() const {
    return make_tuple_crefs(pld);
  }
  static char const** names() {
    static char const* xs[] = {"pld"};
    return xs;
  }
};

struct ping {
  std::uint64_t nonce;

  auto tuple() {
    return make_tuple_refs(nonce);
  }
  auto tuple() const {
    return make_tuple_crefs(nonce);
  }
  static char const** names() {
    static char const* xs[] = {"nonce"};
    return xs;
  }
};

struct pong {
  std::uint64_t nonce;

  auto tuple() {
    return make_tuple_refs(nonce);
  }
  auto tuple() const {
    return make_tuple_crefs(nonce);
  }
  static char const** names() {
    static char const* xs[] = {"nonce"};
    return xs;
  }
};
}

template <std::size_t N>
std::ostream& operator << (std::ostream& os, std::array<char, N> const& o) {
  auto fn = [&o, &os]<std::size_t ...Is>(std::index_sequence<Is...>) {
    os << "{ ";
    ((os << std::get<Is>(o) << ' '), ...);
    os << '}';
  };
  fn(std::make_index_sequence<N>{});
  return os;
}

template <std::size_t N>
std::ostream& operator << (std::ostream& os, std::array<std::uint8_t, N> const& o) {
  auto fn = [&o, &os]<std::size_t ...Is>(std::index_sequence<Is...>) {
    os << "{ ";
    ((os << std::setw(2) << std::setfill('0') << int{std::get<Is>(o)} << ' '), ...);
    os << '}';
  };
  os << std::hex;
  fn(std::make_index_sequence<N>{});
  os << std::resetiosflags(std::ios_base::basefield);
  return os;
}

template <typename T>
std::ostream& operator << (std::ostream& os, std::vector<T> const& o) {
  os << "{\n";
  for (auto &&x : o) {
    os << "\t" << x << "\n";
  }
  os << "}\n";
  return os;
}

template <typename T>
concept bool Serializable = requires(T&& o) {
  o.names();
  o.tuple();
};

template <Serializable T>
std::ostream& operator << (std::ostream& os, T const& cmd) {
  auto fn = [&cmd, &os]<std::size_t ...Is>(std::index_sequence<Is...>) {
    ((os << T::names()[Is] << ": " << std::get<Is>(cmd.tuple()) << '\n'), ...);
  };
  fn(std::make_index_sequence<std::tuple_size_v<decltype(cmd.tuple())>>{});
  return os;
}

template <typename base_ops, typename T>
struct io_ops {
  static void read(base_ops& io, T& o) {
    using o_type = std::remove_cvref_t<T>;
    io.read_impl(reinterpret_cast<char *>(&o), sizeof(o_type));
  }
  static void write(base_ops& io, T const& o) {
    using o_type = std::remove_cvref_t<T>;
    io.write_impl(reinterpret_cast<char const*>(&o), sizeof(o_type));
  }
};

template <typename base_ops, typename T, std::size_t N>
struct io_ops<base_ops, std::array<T, N>> {
  static void read(base_ops& io, std::array<T, N>& o) {
    io.read_impl(reinterpret_cast<char *>(&o.front()), sizeof(T) * N);
  }
  static void write(base_ops& io, std::array<T, N> const& o) {
    io.write_impl(reinterpret_cast<char const*>(&o.front()), sizeof(T) * N);
  }
};

template <typename base_ops>
struct io_ops<base_ops, be_uint16_t> {
  static void read(base_ops& io, be_uint16_t& o) {
    io.read_impl((char*)&o.num, sizeof(o.num));
    o.num = ntohs(o.num);
  }

  static void write(base_ops& io, be_uint16_t const o) {
    std::uint16_t num = htons(o.num);
    io.write_impl((char*)&num, sizeof(num));
  }
};

template <typename base_ops>
struct io_ops<base_ops, var_int> {
  static void read(base_ops& io, var_int& o) {
    std::uint8_t prefix;
    io.read_impl((char*)&prefix, 1);
    if (prefix < 0xfd) {
      o.num = prefix;
    } else if (prefix == 0xfd) {
      std::uint16_t num;
      io.read_impl((char*)&num, sizeof(num));
      o.num = num;
    } else if (prefix == 0xfe) {
      std::uint32_t num;
      io.read_impl((char*)&num, sizeof(num));
      o.num = num;
    } else if (prefix == 0xff) {
      std::uint64_t num;
      io.read_impl((char*)&num, sizeof(num));
      o.num = num;
    } else {
      throw std::runtime_error("unknown prefix in var_int");
    }
  }

  static void write(base_ops& io, var_int const o) {
    if (o.num < 0xfd) {
      std::uint8_t num = o.num;
      io.write_impl((char const*)&num, sizeof(num));
    } else if (o.num <= 0xffff) {
      std::uint8_t prefix = 0xfd;
      std::uint16_t num = o.num;
      io.write_impl((char const*)&prefix, sizeof(prefix));
      io.write_impl((char const*)&num, sizeof(num));
    } else if (o.num <= 0xffffffff) {
      std::uint8_t prefix = 0xfe;
      std::uint32_t num = o.num;
      io.write_impl((char const*)&prefix, sizeof(prefix));
      io.write_impl((char const*)&num, sizeof(num));
    } else {
      std::uint8_t prefix = 0xff;
      std::uint64_t num = o.num;
      io.write_impl((char const*)&prefix, sizeof(prefix));
      io.write_impl((char const*)&num, sizeof(num));
    }
  }
};

template <typename base_ops>
struct io_ops<base_ops, std::string> {
  static void read(base_ops& io, std::string& o) {
    var_int len;
    io_ops<base_ops, var_int>::read(io, len);
    o.resize(len.num);
    if (o.empty())
      return;

    io.read_impl(reinterpret_cast<char*>(&o.front()), len.num);
  }

  static void write(base_ops& io, std::string const& o) {
    io_ops<base_ops, var_int>::write(io, var_int{o.size()});
    if (o.empty())
      return;
    
    io.write_impl(reinterpret_cast<char const*>(&o.front()), o.size());
  }
};

template <typename base_ops, typename T>
struct io_ops<base_ops, std::vector<T>> {
  static void read(base_ops& io, std::vector<T>& o) {
    var_int len;
    io_ops<base_ops, var_int>::read(io, len);
    o.resize(len.num);
    if (o.empty())
      return;

    for (auto& e : o) {
      io_ops<base_ops, T>::read(io, e);
    }
  }

  static void write(base_ops& io, std::vector<T> const& o) {
    io_ops<base_ops, var_int>::write(io, var_int{o.size()});
    if (o.empty())
      return;
    
    for (auto const& e : o) {
      io_ops<base_ops, T>::write(io, e);
    }
  }
};

template <typename base_ops, Serializable T>
struct io_ops<base_ops, T> {
  template <std::size_t ...Is>
  static void read_details(base_ops& io, T& o, std::index_sequence<Is...>) {
    auto tupl = o.tuple();
    ((io.template read<std::remove_cvref_t<decltype(std::get<Is>(tupl))>>(
        std::get<Is>(tupl))), ...);
  }
  static void read(base_ops& io, T& o) {
    read_details(io, o, std::make_index_sequence<std::tuple_size_v<decltype(o.tuple())>>{});
  }

  template <std::size_t ...Is>
  static void write_details(base_ops& io, T const& o, std::index_sequence<Is...>) {
    auto tupl = o.tuple();
    ((io.template write<std::remove_cvref_t<decltype(std::get<Is>(tupl))>>(
        std::get<Is>(tupl))), ...);
  }
  static void write(base_ops& io, T const& o) {
    write_details(io, o, std::make_index_sequence<std::tuple_size_v<decltype(o.tuple())>>{});
  }
};

struct socket_ops {
  socket_ops(int sock): sock_{sock} {}

  template <typename T> void read(T& o) {
    TRACE;
    io_ops<socket_ops, T>::read(*this, o);
  }
  template <typename T> void write(T const& o) {
    TRACE;
    io_ops<socket_ops, T>::write(*this, o);
  }

  void read_impl(char* p, std::size_t s) {
    while (s > 0) {
      int rv = ::read(sock_, p, s);
      if (rv <= 0)
        throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)));
      s -= rv;
      p += rv;
    }
  }
  void write_impl(char const* p, std::size_t s) {
    while (s > 0) {
      int rv = ::write(sock_, p, s);
      if (rv <= 0)
        throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)));
      s -= rv;
      p += rv;
    }
  }

 private:
  int sock_;
};

struct ostream_ops {
  ostream_ops(std::ostream &os): os_{os} {}

  template <typename T> void write(T const& o) {
    TRACE;
    io_ops<ostream_ops, T>::write(*this, o);
  }

  void write_impl(char const* p, std::size_t s) {
    os_.write(p, s);
  }

 private:
  std::ostream &os_;
};

template <Serializable T>
void from_socket(int sock, T& payload) {
  socket_ops ops(sock);
  ops.read(payload);
}

template <Serializable T>
void to_socket(int sock, T const& payload) {
  socket_ops ops(sock);
  ops.write(payload);
}

template <Serializable T>
void to_stream(std::ostream &os, T const& payload) {
  ostream_ops ops(os);
  ops.write(payload);
}

template <typename Payload>
std::array<unsigned char, 4> compute_crc(Payload&& payload) {
  std::stringstream ss;
  to_stream(ss, payload);
  std::string payload_raw = ss.str();
  
  std::vector<unsigned char> crc(picosha2::k_digest_size);
  std::vector<unsigned char> hash(picosha2::k_digest_size);
  picosha2::hash256(payload_raw.begin(), payload_raw.end(), hash.begin(), hash.end());
  picosha2::hash256(hash.begin(), hash.end(), crc.begin(), crc.end());

  return {crc[0], crc[1], crc[2], crc[3]};
}

template <typename... Payloads>
hash_t compute_hash(Payloads&&... payloads) {
  std::stringstream ss;
  ostream_ops ops(ss);
  (ops.write(std::forward<Payloads>(payloads)), ...);
  // (to_stream(ss, std::forward<Payloads>(payloads)), ...);
  std::string payload_raw = ss.str();
  
  hash_t crc;
  std::vector<unsigned char> hash(picosha2::k_digest_size);
  picosha2::hash256(payload_raw.begin(), payload_raw.end(), hash.begin(), hash.end());
  picosha2::hash256(hash.begin(), hash.end(), crc.begin(), crc.end());

  return std::move(crc);
}

header make_header(char const command[]) {
  header hdr{
    header::NETWORK_MAIN,
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    0,
    {0x5d, 0xf6, 0xe0, 0xe2}
  };

  std::strncpy(hdr.command.data(), command, hdr.command.size());

  return hdr;
}

template <typename Payload>
header make_header(char const command[], Payload&& payload) {
  std::stringstream ss;
  to_stream(ss, payload);
  std::string payload_raw = ss.str();
  
  std::vector<unsigned char> crc(picosha2::k_digest_size);
  std::vector<unsigned char> hash(picosha2::k_digest_size);
  picosha2::hash256(payload_raw.begin(), payload_raw.end(), hash.begin(), hash.end());
  picosha2::hash256(hash.begin(), hash.end(), crc.begin(), crc.end());

  header hdr{
    header::NETWORK_MAIN,
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    static_cast<uint32_t>(payload_raw.size()),
    {crc[0], crc[1], crc[2], crc[3]}
  };

  std::strncpy(hdr.command.data(), command, hdr.command.size());

  return hdr;
}

addr_t make_addr6(char const* addr) {
  std::array<std::uint16_t, 8> addr_words;
  std::sscanf(addr, "%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx",
              &addr_words[0], &addr_words[1], &addr_words[2], &addr_words[3],
              &addr_words[4], &addr_words[5], &addr_words[6], &addr_words[7]);

  addr_t addr_bytes;
  for (int i = 0, j = 0; i < 8; ++i, j += 2) {
    addr_bytes[j]   = addr_words[i] >> 8;
    addr_bytes[j+1] = addr_words[i];
  }
  return std::move(addr_bytes);
}
addr_t make_addr4(char const* addr) {
  std::array<std::uint8_t, 8> octs;
  std::sscanf(addr, "%hhu.%hhu.%hhu.%hhu",
              &octs[0], &octs[1], &octs[2], &octs[3]);

  return {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
          octs[0], octs[1], octs[2], octs[3]};
}

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

std::string hash_to_s(hash_t const& hash) {
  char buf[128] = {'\0'};
  for (std::size_t i = 0; i < hash.size(); ++i) {
    unsigned char b = hash[hash.size() - i - 1];
    std::snprintf(buf + i*2, sizeof(buf) - i*2, "%02hhx", b);
  }
  return {buf};
}

std::string target_to_s(std::uint32_t bits) {
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

// From libbitcoin which is under AGPL
std::vector<std::size_t> block_locator_indexes(std::size_t top_height) {
  std::vector<std::size_t> indexes;

  // Modify the step in the iteration.
  std::int64_t step = 1;

  // Start at the top of the chain and work backwards.
  for (auto index = (std::int64_t)top_height; index > 0; index -= step)
  {
    // Push top 10 indexes first, then back off exponentially.
    if (indexes.size() >= 10)
      step *= 2;

    indexes.push_back((std::size_t)index);
  }

  //  Push the genesis block index.
  indexes.push_back(0);
  return indexes;
}

int conn(char const* addr) {
  int sock_fd = -1;
  int ret;
  sock_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (sock_fd == -1) {
    perror("socket()");
    throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)));
  }
  struct sockaddr_in6 server_addr;
  bzero((char*)&server_addr, sizeof(server_addr));
  server_addr.sin6_family = AF_INET6;
  inet_pton(AF_INET6, addr, &server_addr.sin6_addr);
  server_addr.sin6_port = htons(8333);
  ret = connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (ret == -1) {
    close(sock_fd);
    perror("connect()");
    throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)));
  }
  return sock_fd;
}

struct DB {
  struct block_headers_page_t {
    std::uint32_t version = 0;
    std::uint32_t last_height = 0;
    std::uint32_t sz_block_hdr = sizeof(proto::block_headers);
  };

  DB(char const* path) {
    fd_ = ::open(path, O_CREAT | O_SYNC | O_RDWR, 0644);
    lseek(fd_, 0, SEEK_SET);
    read(fd_, (char*)&block_headers_page, sizeof(block_headers_page));

    std::cerr << "block_headers_page.version="
              << block_headers_page.version << std::endl;
    std::cerr << "block_headers_page.last_height="
              << block_headers_page.last_height << std::endl;
    std::cerr << "block_headers_page.sz_block_hdr="
              << block_headers_page.sz_block_hdr << std::endl;
  }
  ~DB() {
    sync();
    ::close(fd_);
  }

  void save_block(std::size_t height, proto::block_headers const& payload) {
    lseek(fd_, sizeof(block_headers_page) + block_headers_page.sz_block_hdr * height, SEEK_SET);
    to_socket(fd_, payload);

    if (height > block_headers_page.last_height) {
      block_headers_page.last_height = height;
    }
    sync();
  }

  void load_block(std::size_t height, proto::block_headers& payload) {
    lseek(fd_, sizeof(block_headers_page) + block_headers_page.sz_block_hdr * height, SEEK_SET);
    from_socket(fd_, payload);

    if (height > block_headers_page.last_height) {
      block_headers_page.last_height = height;
    }
    sync();
  }

  std::size_t last_height() {
    return block_headers_page.last_height;
  }

  void sync() {
    lseek(fd_, 0, SEEK_SET);
    write(fd_, (char const*)&block_headers_page, sizeof(block_headers_page));
    fsync(fd_);
  }

 private:
  int fd_;
  block_headers_page_t block_headers_page;
};

void run(char const* addr_to) {
  DB db("block_headers.db");

  int sock_fd = conn(addr_to);
  auto addr_from = make_addr6("2a02:8084:2161:c800:ccc6:b381:5797:eb");
  // auto addr_from = make_addr4("37.228.246.55");

  {
    proto::version payload = {
      proto::VERSION,
      proto::version::NODE_NETWORK,
      std::time(nullptr),
      {
        proto::version::NODE_NETWORK,
        make_addr6(addr_to),
        8333
      },
      {
        proto::version::NODE_NETWORK,
        addr_from,
        8333
      },
      gen_nonce(),
      "/Satoshi:0.16.3/",
      0,
      0
    };
    header hdr = make_header("version", payload);
    std::cout << " ==> version\n";

    to_socket(sock_fd, hdr);
    to_socket(sock_fd, payload);
  }

  std::deque<proto::block_headers> blocks = {};
  std::deque<hash_t> block_hashes = {};

  for (;;) {
    header hdr;
    from_socket(sock_fd, hdr);
    std::cout << "<==  " << hdr.command.data() << "\n";
    std::cout << hdr << endl;

    if (::strncmp(&hdr.command.front(), "version", hdr.command.size()) == 0) {
      proto::version payload;
      from_socket(sock_fd, payload);

      hdr = make_header("verack");
      std::cout << " ==> verack\n";
      to_socket(sock_fd, hdr);

      hdr = make_header("getaddr");
      std::cout << " ==> getaddr\n";
      to_socket(sock_fd, hdr);

      {
        proto::getheaders payload = {
          proto::VERSION, {hash_t{}}, {}
        };
        hdr = make_header("getheaders", payload);
        std::cout << " ==> getheaders\n";
        std::cout << hdr << payload << std::endl;
        to_socket(sock_fd, hdr);
        to_socket(sock_fd, payload);
      }
    } else if (::strncmp(&hdr.command.front(), "headers", hdr.command.size()) == 0) {
      proto::headers payload;
      std::cout << "<==  headers" << std::endl;
      from_socket(sock_fd, payload);

      if (!payload.headers.empty()) {
        auto &&e = payload.headers.back();
        std::cout << "\tBlocks (" << payload.headers.size() << ", " << block_hashes.size() << " downloaded):\n";
        std::cout << "\t\t"
                  << e.version << ' '
                  << hash_to_s(e.prev_block) << ' '
                  << hash_to_s(e.merkle_root) << ' '
                  << e.timestamp << ' '
                  << std::hex << e.bits << std::dec << ' '
                  << e.nonce << ' '
                  << e.txn_count << ' '
                  << '\n';
        std::cout << "\t\t"
                  << target_to_s(e.bits)
                  << '\n';
        std::cout << "\t\t"
                  << hash_to_s(compute_hash(e.version, e.prev_block, e.merkle_root, e.timestamp, e.bits, e.nonce))
                  << '\n';
        std::cout << std::flush;
      }

      for (auto &&e : payload.headers) {
        db.save_block(block_hashes.size(), e);
        block_hashes.push_back(
            compute_hash(e.version, e.prev_block, e.merkle_root, e.timestamp, e.bits, e.nonce));
        //blocks.push_back(std::move(e));
      }

      if (!payload.headers.empty()) {
        auto indexes = block_locator_indexes(block_hashes.size());
        std::vector<hash_t> hashes;
        for (auto i : indexes) {
          auto &h = block_hashes[i];
          hashes.push_back(h);
        }
        proto::getheaders payload = {
          proto::VERSION, hashes, {}
        };
        hdr = make_header("getheaders", payload);
        std::cout << " ==> getheaders\n";
        // std::cout << hdr << payload << std::endl;
        to_socket(sock_fd, hdr);
        to_socket(sock_fd, payload);
      } else {
        db.sync();
      }
    } else if (::strncmp(&hdr.command.front(), "sendheaders", hdr.command.size()) == 0) {
      proto::headers payload;
      std::cout << "<==  sendheaders\n";
      std::cout << " ==> headers\n";
      std::cout << payload << endl;
      to_socket(sock_fd, make_header("headers", payload));
      to_socket(sock_fd, payload);
    } else if (::strncmp(&hdr.command.front(), "sendcmpct", hdr.command.size()) == 0) {
      proto::sendcmpct payload;
      from_socket(sock_fd, payload);
      std::cout << "<==  sendcmpct\n";
      std::cout << payload << endl;
    } else if (::strncmp(&hdr.command.front(), "ping", hdr.command.size()) == 0) {
      proto::ping ping;
      std::cout << "<==  ping\n";
      from_socket(sock_fd, ping);
      proto::pong pong{ping.nonce};
      std::cout << " ==> pong\n";
      to_socket(sock_fd, make_header("pong", pong));
      to_socket(sock_fd, pong);
    } else if (::strncmp(&hdr.command.front(), "addr", hdr.command.size()) == 0) {
      proto::addr payload;
      std::cout << "<==  addr" << std::endl;
      from_socket(sock_fd, payload);
      std::cout << "\tPeers (" << payload.addrs.size() << "):\n";
      for (auto &&e : payload.addrs) {
        std::cout << "\t\t" << addr_to_s(e.addr) << ':' << e.port << '\n';
      }
      std::cout << std::flush;
    } else {
      char buf[128];
      std::size_t len = hdr.length;
      while (len > 0) {
        std::size_t to_read = std::min(sizeof(buf), len);
        int rv = read(sock_fd, buf, to_read);
        if (rv <= 0)
          throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)));
        len -= to_read;
      }
    }

    // from_socket(sock_fd, hdr);
    // std::cout << "<==  Read a header\n";
    // std::cout << hdr << endl;

    // break;
  }

  close(sock_fd);
}

int main(int argc, char* argv[]) {
  try {
    run(argv[1]);
  } catch (std::system_error const& err) {
    std::cerr << "Error occurred (" << err.code() << "): " << err.what() << std::endl;
    return -1;
  }

  return 0;
}
