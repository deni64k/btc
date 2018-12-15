// cxx = g++-8
// cppflags = -I/usr/local/include
// cxxflags = -std=c++2a -O2 -march=native -fconcepts -Wall -Werror -pedantic

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <condition_variable>
#include <deque>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <queue>
#include <random>
#include <set>
#include <sstream>
#include <system_error>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <boost/preprocessor.hpp>
#include <openssl/sha.h>
#include <picosha2/picosha2.h>

#include "common/logging.hxx"
#include "common/types.hxx"
#include "hasher.hxx"
#include "opencl.hxx"
#include "proto/script.hxx"
#include "serdes.hxx"
#include "utility.hxx"

static_assert(__cpp_concepts >= 201500, "Compile with -fconcepts");
static_assert(__cplusplus >= 201500, "C++17 at least required");

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

using var_str = std::string;

struct hash_t_key {
  std::size_t operator () (hash_t const& h) const noexcept {
    using sv_t = std::basic_string_view<char>;
    return std::hash<sv_t>{}(sv_t{reinterpret_cast<char const*>(h.data()), h.size()});
  }
};

template <typename... Payloads> hash_t compute_hash(Payloads&&... payloads);

template <typename ...Ts> std::tuple<Ts&...> make_tuple_refs(Ts&... ts) {
  return {ts...};
}
template <typename ...Ts> std::tuple<Ts const&...> make_tuple_crefs(Ts const&... ts) {
  return {ts...};
}

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

namespace proto {
enum {
  VERSION = 70015
};

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

  SERDES(magic, command, length, checksum)
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
  std::uint32_t version;
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
  var_str user_agent;
  // The last block received by the emitting node
  std::uint32_t start_height;
  // Whether the remote peer should announce relayed transactions or not, see BIP 0037
  std::uint8_t relay;

  SERDES(version, services, timestamp, addr_recv, addr_from, nonce,
         user_agent, start_height, relay)
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
  hash_t prev_block;
  hash_t merkle_root;
  std::uint32_t timestamp;
  std::uint32_t bits;
  std::uint32_t nonce;
  var_int       txn_count;

  SERDES(version, prev_block, merkle_root, timestamp, bits, nonce, txn_count)

  auto hash() const {
    return compute_hash(version, prev_block, merkle_root, timestamp, bits, nonce);
  }
};

struct headers {
  std::vector<block_headers> headers;

  SERDES(headers)
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
  hash_t hash;

  SERDES(type, hash)
};

struct inv {
  std::vector<inv_vect> inventory;

  SERDES(inventory)
};

struct getdata {
  std::vector<inv_vect> inventory;

  SERDES(inventory)
};

struct notfound {
  std::vector<inv_vect> inventory;

  SERDES(inventory)
};

struct getblocks {
  std::uint32_t version;
  std::vector<hash_t> block_locator_hashes;
  hash_t hash_stop;

  SERDES(version, block_locator_hashes, hash_stop)
};

struct getheaders {
  std::uint32_t version;
  std::vector<hash_t> block_locator_hashes;
  hash_t hash_stop;

  SERDES(version, block_locator_hashes, hash_stop)
};

struct sendcmpct {
  std::uint8_t cmpct_enabled;
  std::uint64_t version;

  SERDES(cmpct_enabled, version)
};

struct ping {
  std::uint64_t nonce;

  SERDES(nonce)
};

struct pong {
  std::uint64_t nonce;

  SERDES(nonce)
};

struct outpoint {
  hash_t hash;
  std::uint32_t index;

  SERDES(hash, index)
};

struct tx_in {
  outpoint previous_output;
  std::vector<unsigned char> signature_script;
  std::uint32_t sequence;

  SERDES(previous_output, signature_script, sequence)
};

struct tx_out {
  std::uint64_t value;
  std::vector<unsigned char> pk_script;

  SERDES(value, pk_script)
};

struct tx_witness {
  std::vector<unsigned char> data;

  SERDES(data)
};

struct tx {
  // Transaction data format version (note, this is signed)
  std::int32_t version;
  // If present, always 0001, and indicates the presence of witness data
  // std::array<std::uint8_t, 2> flag;
  // A list of 1 or more transaction inputs or sources for coins
  std::vector<tx_in> txs_in;
  // A list of 1 or more transaction outputs or destinations for coins
  std::vector<tx_out> txs_out;
  // A list of witnesses, one for each input; omitted if flag is omitted above
  std::vector<tx_witness> tx_witnesses;
  // The block number or timestamp at which this transaction is unlocked
  // =  0          Not locked
  // <  500000000  Block number at which this transaction is unlocked
  // >= 500000000  UNIX timestamp at which this transaction is unlocked
  // If all TxIn inputs have final (0xffffffff) sequence numbers then lock_time is
  // irrelevant. Otherwise, the transaction may not be added to a block until after
  // lock_time (see NLockTime).
  std::uint32_t lock_time;

  SERDES(version, txs_in, txs_out, tx_witnesses, lock_time)

  auto total_value() const {
    std::uint64_t value = 0;
    for (auto&& tx : txs_out)
      value += tx.value;
    return value;
  }
};

struct feefilter {
  // The value represents a minimal fee and is expressed in satoshis per 1000 bytes.
  std::uint64_t feerate;

  SERDES(feerate)
};

struct block {
  std::int32_t version;
  hash_t prev_block;
  hash_t merkle_root;
  std::uint32_t timestamp;
  std::uint32_t bits;
  std::uint32_t nonce;
  std::vector<tx> txs;

  SERDES(version, prev_block, merkle_root, timestamp, bits, nonce, txs)
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
  auto ff = os.flags();
  auto fill = os.fill();

  auto fn = [&o, &os]<std::size_t ...Is>(std::index_sequence<Is...>) {
    os << "{ ";
    ((os << std::setw(2) << std::setfill('0') << int{std::get<Is>(o)} << ' '), ...);
    os << '}';
  };
  os << std::hex;
  fn(std::make_index_sequence<N>{});
  os << std::dec;

  os.flags(ff);
  os.fill(fill);
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

template <SerDes T>
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
struct io_ops<base_ops, var_str> {
  static void read(base_ops& io, var_str& o) {
    var_int len;
    io_ops<base_ops, var_int>::read(io, len);
    o.resize(len.num);
    if (o.empty())
      return;

    io.read_impl(reinterpret_cast<char*>(&o.front()), len.num);
  }

  static void write(base_ops& io, var_str const& o) {
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

template <typename base_ops>
struct io_ops<base_ops, proto::tx> {
  static void read(base_ops& io, proto::tx& o) {
    io_ops<base_ops, decltype(o.version)>::read(io, o.version);
    bool has_witnesses = false;
    var_int len;
    io_ops<base_ops, decltype(len)>::read(io, len);
    if (len.num == 0) {
      has_witnesses = true;
      char c;
      io_ops<base_ops, decltype(c)>::read(io, c);
      io_ops<base_ops, decltype(len)>::read(io, len);
    }
    for (unsigned i = 0; i < len.num; ++i) {
      proto::tx_in tx;
      io_ops<base_ops, decltype(tx)>::read(io, tx);
      o.txs_in.push_back(std::move(tx));
    }
    io_ops<base_ops, decltype(o.txs_out)>::read(io, o.txs_out);
    if (has_witnesses) {
      io_ops<base_ops, decltype(o.tx_witnesses)>::read(io, o.tx_witnesses);
    }
    io_ops<base_ops, decltype(o.lock_time)>::read(io, o.lock_time);
  }

  static void write(base_ops& io, proto::tx const& o) {
    bool has_witnesses = !o.tx_witnesses.empty();
    io_ops<base_ops, decltype(o.version)>::write(io, o.version);
    if (has_witnesses) {
      std::array<char, 2> flag = {0, 1};
      io_ops<base_ops, decltype(flag)>::write(io, flag);
    }
    io_ops<base_ops, decltype(o.txs_in)>::write(io, o.txs_in);
    io_ops<base_ops, decltype(o.txs_out)>::write(io, o.txs_out);
    if (has_witnesses)
      io_ops<base_ops, decltype(o.tx_witnesses)>::write(io, o.tx_witnesses);
    io_ops<base_ops, decltype(o.lock_time)>::write(io, o.lock_time);
  }
};

template <typename base_ops, SerDes T>
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
    TRACE();
    io_ops<socket_ops, T>::read(*this, o);
  }
  template <typename T> void write(T const& o) {
    TRACE();
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
    TRACE();
    io_ops<ostream_ops, T>::write(*this, o);
  }

  void write_impl(char const* p, std::size_t s) {
    os_.write(p, s);
  }

 private:
  std::ostream &os_;
};

template <SerDes T>
void from_socket(int sock, T& payload) {
  socket_ops ops(sock);
  ops.read(payload);
}

template <SerDes T>
void to_socket(int sock, T const& payload) {
  socket_ops ops(sock);
  ops.write(payload);
}

template <SerDes T>
void to_stream(std::ostream& os, T const& payload) {
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
  std::string payload_raw = ss.str();
  
  hash_t crc;
  hash_t hash;
  picosha2::hash256(payload_raw.begin(), payload_raw.end(), hash.begin(), hash.end());
  picosha2::hash256(hash.begin(), hash.end(), crc.begin(), crc.end());

  return std::move(crc);
}

hash_t merkle_tree(std::vector<hash_t> hashes) {
  if (hashes.size() > 1 && hashes.size() % 2) {
    hashes.push_back(hashes.back());
  }
  std::vector<hash_t> hashes_prev = hashes;

  while (hashes_prev.size() > 1) {
    hashes.resize(hashes.size() / 2);

    for (unsigned i = 0, j = 0; i < hashes.size(); i += 1, j += 2) {
      hashes[i] = compute_hash(hashes_prev[j], hashes_prev[j+1]);
    }
    if (hashes.size() == 1)
      break;

    if (hashes.size() % 2) {
      hashes.push_back(hashes.back());
    }
    hashes_prev = hashes;
  }

  return std::move(hashes[0]);
}

hash_t merkle_tree(std::vector<proto::tx> const& txs) {
  std::vector<hash_t> hashes;
  hashes.reserve((txs.size() + 1) ^ 1);
  for (auto&& tx : txs) {
    hashes.push_back(compute_hash(tx));
  }
  return merkle_tree(std::move(hashes));
}

proto::header make_header(char const command[]) {
  proto::header hdr{
    proto::header::NETWORK_MAIN,
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    0,
    {0x5d, 0xf6, 0xe0, 0xe2}
  };

  std::strncpy(hdr.command.data(), command, hdr.command.size());

  return hdr;
}

template <typename Payload>
proto::header make_header(char const command[], Payload&& payload) {
  std::stringstream ss;
  to_stream(ss, payload);
  std::string payload_raw = ss.str();
  
  std::vector<unsigned char> crc(picosha2::k_digest_size);
  std::vector<unsigned char> hash(picosha2::k_digest_size);
  picosha2::hash256(payload_raw.begin(), payload_raw.end(), hash.begin(), hash.end());
  picosha2::hash256(hash.begin(), hash.end(), crc.begin(), crc.end());

  proto::header hdr{
    proto::header::NETWORK_MAIN,
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

// From libbitcoin which is under AGPL
std::vector<std::size_t> block_locator_indexes(std::size_t top_height) {
  std::vector<std::size_t> indexes;

  // Modify the step in the iteration.
  std::uint64_t step = 1;

  // Start at the top of the chain and work backwards.
  for (auto index = std::uint64_t{top_height}; index > 0;)
  {
    // Push top 10 indexes first, then back off exponentially.
    if (indexes.size() >= 10)
      step *= 2;

    indexes.push_back(std::size_t{index});

    if (index <= step)
      break;
    index -= step;
  }

  //  Push the genesis block index.
  // indexes.push_back(0);
  return indexes;
}

static std::unique_ptr<opencl::context> g_ctx;

struct db_t {
  struct block_headers_page_t {
    std::uint32_t version = 0;
    std::uint32_t last_height = 0;
    std::uint32_t sz_block_hdr = sizeof(proto::block_headers);
  };

  db_t(char const* path) {
    fd_ = ::open(path, O_CREAT | O_SYNC | O_RDWR, 0644);
    lseek(fd_, 0, SEEK_SET);
    read(fd_, (char*)&block_headers_page, sizeof(block_headers_page));

    INFO() << "block_headers_page.version="
           << block_headers_page.version;
    INFO() << "block_headers_page.last_height="
           << block_headers_page.last_height;
    INFO() << "block_headers_page.sz_block_hdr="
           << block_headers_page.sz_block_hdr;
  }
  ~db_t() {
    sync();
    ::close(fd_);
  }

  void save_block(std::uint32_t height, proto::block_headers const& payload) {
    lseek(fd_, sizeof(block_headers_page) + block_headers_page.sz_block_hdr * height, SEEK_SET);
    to_socket(fd_, payload);

    if (height > block_headers_page.last_height) {
      block_headers_page.last_height = height;
    }
    sync();
  }

  void load_block(std::int32_t height, proto::block_headers& payload) {
    lseek(fd_, sizeof(block_headers_page) + block_headers_page.sz_block_hdr * height, SEEK_SET);
    from_socket(fd_, payload);
  }

  auto last_height() const {
    return block_headers_page.last_height;
  }
  void set_last_height(std::int32_t height) {
    block_headers_page.last_height = height;
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

std::uint8_t pk_script[] = {
  btc::proto::OP_DUP,
  btc::proto::OP_HASH160,
  // public key hash for 1GLcrrQt2XQniTzK65JYVVGQXNQ6JAMuQ8
  btc::proto::DATA_20,
  0xa8, 0x3f, 0xb9, 0x5b, 0x27, 0x02, 0x44, 0x20, 0xc6, 0x45,
  0x6c, 0x19, 0xa4, 0x97, 0x49, 0x52, 0xce, 0x09, 0x54, 0xd5,
  btc::proto::OP_EQUALVERIFY,
  btc::proto::OP_CHECKSIG
};

constexpr std::uint64_t reward(std::uint32_t const block_height) {
  constexpr std::uint64_t const initial_reward = 5000000000;
  std::uint64_t const era = block_height / 210000;
  return initial_reward >> era;
}

proto::tx reward_tx(std::uint64_t satoshis) {
  proto::tx_out tx_out = {
    satoshis, {pk_script, pk_script + sizeof(pk_script)}
  };
  proto::tx tx = {
    proto::VERSION,
    {},
    {tx_out},
    {},
    0
  };
  return tx;
}

struct miner_state {
  enum miner_command {
    RESTART,
    MEMPOOL_TX
  };
  std::condition_variable   queue_cond;
  std::mutex                queue_mtx;
  std::queue<miner_command> queue;

  std::vector<hash_t> mining_txs;

  void restart() {
  }

  template <Iterable T>
  void mempool_tx(T&& cont) {
    
  }
};

struct node_t {
  enum state_t {
    STATE_CHAIN_DOWNLOADING,
    STATE_CHAIN_DOWNLOADED,
    STATE_TX_REQUESTING,
    STATE_TX_RECEIVED,
    STATE_MEMPOOL_REQUESTING,
    STATE_MEMPOOL_TX_REQUESTING,
    STATE_MEMPOOL_FEE_REQUESTING,
    STATE_MINING,
    STATE_END
  };

  std::string addr;
  db_t&       db;
  int         sock_fd;
  state_t     state;

  std::uint64_t feerate;
  std::uint32_t current_version;
  std::uint32_t node_version;

  std::unordered_map<hash_t, proto::tx, hash_t_key> transactions;
  std::set<hash_t> mempool_transactions;
  std::set<hash_t> fee_transactions;

  node_t(std::string addr_, db_t& db_)
      : addr{std::move(addr_)}
      , db{db_}
      , sock_fd{0}
      , state{STATE_CHAIN_DOWNLOADING}
      , feerate{0}
      , current_version{proto::VERSION}
      , node_version{0}
  {
    // db.set_last_height(0);
    // db.set_last_height(500000);
    // db.set_last_height(std::max(0, db.last_height() - 10000));
    // db.sync();
  }

  ~node_t() {
    if (sock_fd)
      close(sock_fd);
  }

  static int conn(char const* addr) {
    int sock_fd = -1;
    int ret;
    sock_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1) {
      throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)),
                              "socket failed");
    }
    struct sockaddr_in6 server_addr;
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, addr, &server_addr.sin6_addr);
    server_addr.sin6_port = htons(8333);
    ret = connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret == -1) {
      close(sock_fd);
      throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)),
                              "connect failed");
    }
    return sock_fd;
  }

  void run() {
    sock_fd = conn(addr.c_str());
    auto addr_from = make_addr6("2a02:8084:2161:c800:ccc6:b381:5797:eb");
    // auto addr_from = make_addr4("37.228.246.55");

    {
      proto::version payload = {
        current_version,
        proto::version::NODE_NETWORK,
        std::time(nullptr),
        {
          proto::version::NODE_NETWORK,
          make_addr6(addr.c_str()),
          8333
        },
        {
          proto::version::NODE_NETWORK,
          addr_from,
          8333
        },
        gen_nonce(),
        "/Satoshi:0.16.3/",
        db.last_height(),
        0
      };
      proto::header hdr = make_header("version", payload);
      INFO() << " <== version";

      to_socket(sock_fd, hdr);
      to_socket(sock_fd, payload);
    }

    for (;;) {
      proto::header hdr;
      from_socket(sock_fd, hdr);
      // INFO() << addr << " ==>  " << hdr.command.data();
      // INFO() << hdr;

      if (::strncmp(&hdr.command.front(), "version", hdr.command.size()) == 0) {
        handle_version(hdr);
      } else if (::strncmp(&hdr.command.front(), "sendheaders", hdr.command.size()) == 0) {
        handle_sendheaders(hdr);
      } else if (::strncmp(&hdr.command.front(), "sendcmpct", hdr.command.size()) == 0) {
        handle_sendcmpct(hdr);
      } else if (::strncmp(&hdr.command.front(), "headers", hdr.command.size()) == 0) {
        handle_headers(hdr);
      } else if (::strncmp(&hdr.command.front(), "feefilter", hdr.command.size()) == 0) {
        handle_feefilter(hdr);
      } else if (::strncmp(&hdr.command.front(), "ping", hdr.command.size()) == 0) {
        handle_ping(hdr);
      } else if (::strncmp(&hdr.command.front(), "pong", hdr.command.size()) == 0) {
        handle_pong(hdr);
      } else if (::strncmp(&hdr.command.front(), "addr", hdr.command.size()) == 0) {
        handle_addr(hdr);
      } else if (::strncmp(&hdr.command.front(), "block", hdr.command.size()) == 0) {
        handle_block(hdr);
      } else if (::strncmp(&hdr.command.front(), "inv", hdr.command.size()) == 0) {
        handle_inv(hdr);
      } else if (::strncmp(&hdr.command.front(), "notfound", hdr.command.size()) == 0) {
        handle_notfound(hdr);
      } else if (::strncmp(&hdr.command.front(), "tx", hdr.command.size()) == 0) {
        handle_tx(hdr);
      } else {
        handle_unknown(hdr);
      }

      switch (state) {
      case STATE_TX_REQUESTING:
        // XXX: Non-mempool mining
        // to_socket(sock_fd, make_header("ping"));
        // to_socket(sock_fd, proto::ping{gen_nonce()});
        // state = STATE_MINING;
        // break;

        INFO() << " <== mempool";
        to_socket(sock_fd, make_header("mempool"));

        state = STATE_MEMPOOL_REQUESTING;
        break;

      case STATE_MEMPOOL_REQUESTING:
        break;

      case STATE_MEMPOOL_TX_REQUESTING:
        if (mempool_transactions.empty()) {
          proto::getdata getdata;
          for (auto&& [k, v] : transactions) {
            for (auto&& t : v.txs_in) {
              getdata.inventory.push_back(proto::inv_vect{proto::inv_vect::MSG_TX, t.previous_output.hash});
              fee_transactions.insert(t.previous_output.hash);
            }
          }
          INFO() << addr << " <== getdata (" << fee_transactions.size() << " fee txs)";
          to_socket(sock_fd, make_header("getdata", getdata));
          to_socket(sock_fd, getdata);

          state = STATE_MEMPOOL_FEE_REQUESTING;
        }
        break;

      case STATE_MEMPOOL_FEE_REQUESTING:
        if (fee_transactions.empty()) {
          state = STATE_MINING;
        }
        break;

      case STATE_MINING: {
        INFO() << " Let's mine having " << transactions.size() << " mempool transactions";

        std::vector<std::pair<hash_t, std::size_t>> mining_txs;
        for (auto&& [hash, tx] : transactions) {
          std::uint64_t prev_value = 0;
          bool incomplete = false;
          for (auto&& tx_in : tx.txs_in) {
            if (auto iter = transactions.find(tx_in.previous_output.hash);
                iter != transactions.end()) {
              prev_value += iter->second.txs_out.at(tx_in.previous_output.index).value;
            } else {
              incomplete = true;
              break;
            }
          }
          if (incomplete)
            continue;

          auto total_value = tx.total_value();
          auto fee = prev_value - total_value;
          // INFO() << "mempool tx " << to_string(hash)
          //        << "\thas fee " << prev_value << '-' << total_value << '=' << fee;
          mining_txs.emplace_back(hash, fee);
        }
        // std::sort(mining_txs.begin(), mining_txs.end(), [](auto const& lhs, auto const& rhs) {
        //   return lhs.second > rhs.second;
        // });
        std::uint64_t total_fee = std::accumulate(
            mining_txs.cbegin(), mining_txs.cend(), 0,
            [](auto state, auto const& x) {
              return state + x.second;
            });
        INFO() << "We go for fee of " << total_fee << " satoshis from " << mining_txs.size() << " txs";

        // auto const last_height = 4;
        auto const last_height = db.last_height();

        proto::block_headers last_block;
        db.load_block(last_height, last_block);

        state = STATE_END;
        auto target_hash = target_to_hash32(last_block.bits);
        auto mine = [last_height, last_block, mining_txs, total_fee, target_hash](
            sha256_program& hasher_prog,
            std::uint32_t const nonce_begin,
            std::uint32_t const nonce_end) mutable {
          static std::random_device rd;
          static std::mt19937 g(rd());

          // auto target_hash = target_to_hash64(last_block.bits);
          auto tx = reward_tx(reward(last_height) + total_fee);
          std::vector<hash_t> txs;
          txs.push_back(compute_hash(tx));
          std::transform(mining_txs.cbegin(), mining_txs.cend(), std::back_inserter(txs),
                         [](auto const &x) {
                           return x.first;
                         });
          std::shuffle(txs.begin(), txs.end(), g);
          auto merkle_root = merkle_tree(txs);

          proto::block_headers block = {
            proto::VERSION,
            last_block.hash(),
            merkle_root,
            static_cast<uint32_t>(::time(nullptr) + 600),
            last_block.bits,
            0
          };
          //
          // block.version = 1;
          // block.timestamp = 1231471428;
          // block.merkle_root = {
          //   0xe1, 0x1c, 0x48, 0xfe, 0xcd, 0xd9, 0xe7, 0x25, 0x10, 0xca, 0x84, 0xf0, 0x23, 0x37, 0x0c, 0x9a,
          //   0x38, 0xbf, 0x91, 0xac, 0x5c, 0xae, 0x88, 0x01, 0x9b, 0xee, 0x94, 0xd2, 0x45, 0x28, 0x52, 0x63};
          // Should give nonce=2011431709 0x77e4031d
          //
          std::ostringstream os;
          ostream_ops ops(os);
          ops.write(block.version);
          ops.write(block.prev_block);
          ops.write(block.merkle_root);
          ops.write(block.timestamp);
          ops.write(block.bits);
          ops.write(block.nonce);
          std::string buf_s = os.str();
          std::vector<std::uint8_t> buf = {buf_s.cbegin(), buf_s.cend()};

          using namespace std::chrono_literals;
          std::this_thread::sleep_for(1s);
          INFO() << "target: " << prettify_hash(target_to_s(block.bits));
          INFO() << "mining with block:\n" << block;

          // auto min_hash = hasher_prog(target_hash, buf, nonce_begin, nonce_end);
          auto [min_hash, min_nonce] = hasher_prog(target_hash, buf, nonce_begin, nonce_end);

          INFO() << "\tmin_hash: " << prettify_hash(to_string(min_hash));
          INFO() << "\tmin_nonce: " << min_nonce;

          if (to_string(min_hash) < target_to_s(block.bits)) {
            INFO() << "Found!";
            exit(0);
          }
          // std::uint32_t& nonce = *reinterpret_cast<std::uint32_t*>(&buf.back() + 1 - sizeof(std::uint32_t));
          // decltype(target) min_hash = {~0ull, ~0ull, ~0ull, ~0ull};
          // hash_t hash0, hash1;
          // SHA256_CTX hash0ctx, hash1ctx;
          // for (nonce = nonce_begin; ; ++nonce) {
          //   {
          //     SHA256_Init(&hash0ctx);
          //     SHA256_Update(&hash0ctx, buf.data(), buf.size());
          //     SHA256_Final(hash0.data(), &hash0ctx);

          //     SHA256_Init(&hash1ctx);
          //     SHA256_Update(&hash1ctx, hash0.data(), hash0.size());
          //     SHA256_Final(hash1.data(), &hash1ctx);

          //     // picosha2::hash256(buf.cbegin(), buf.cend(), hash0.begin(), hash0.end());
          //     // picosha2::hash256(hash0.cbegin(), hash0.cend(), hash1.begin(), hash1.end());
          //   }
            
          //   auto hash = vectorize_hash(hash1);
          //   if (hash < target) {
          //     INFO() << "Solved!\n"
          //            << "\thash: " << to_string(hash1) << ' '
          //            << " nonce=\t" << nonce
          //            << '\n' << block;
          //     exit(0);
          //     break;
          //   } else {
          //     min_hash = std::min(min_hash, hash);
          //     if (nonce % 50000000 == 0) {
          //       INFO() << "Not yet! min_hash: "
          //              << std::hex
          //              << std::setfill('0') << std::setw(16) << min_hash[0] << ' '
          //              << std::setfill('0') << std::setw(16) << min_hash[1] << ' '
          //              << std::setfill('0') << std::setw(16) << min_hash[2] << ' '
          //              << std::setfill('0') << std::setw(16) << min_hash[3] << ' '
          //              << std::dec
          //              << " nonce: " << std::setfill(' ') << std::setw(12) << std::right << nonce
          //              << ' ' << (double(nonce - nonce_begin) / double((nonce_end - nonce_begin) + 1));
          //     }
          //   }

          //   if (nonce == nonce_end)
          //     break;
          // }
          INFO() << "miner done";
        };

        std::thread miner_thr([mine]() mutable {
          sha256_program hasher_prog(*g_ctx);
          while (1) {
            mine(hasher_prog,
                 std::numeric_limits<std::uint32_t>::min(),
                 std::numeric_limits<std::uint32_t>::max());
          }
        });

        miner_thr.detach();
        
        break;
      }
      case STATE_CHAIN_DOWNLOADED:
        {
          auto last_height = db.last_height();
          proto::block_headers hdrs;
          db.load_block(last_height, hdrs);

          proto::getdata pld = {
            {{proto::inv_vect::MSG_BLOCK, hdrs.prev_block}}
          };
          INFO() << " <== getdata (" << to_string(hdrs.prev_block) << ')';
          to_socket(sock_fd, make_header("getdata", pld));
          to_socket(sock_fd, pld);

          state = STATE_TX_REQUESTING;

          break;
        }
      default:
        break;
      }
    }
  }

  void send_sendcmpct() {
    proto::sendcmpct payload{0, 1};
    INFO() << addr << " <== sendcmpct";
    to_socket(sock_fd, make_header("sendcmpct", payload));
    to_socket(sock_fd, payload);
  }

  void send_getaddr() {
    INFO() << addr << " <== getaddr";
    to_socket(sock_fd, make_header("getaddr"));
  }

  void send_block_headers(std::uint32_t last_height) {
    auto indexes = block_locator_indexes(last_height);
    std::vector<hash_t> hashes;
    proto::block_headers block_hdrs;
    for (auto i : indexes) {
      db.load_block(i, block_hdrs);
      auto const& e = block_hdrs;
      auto h = e.hash();
      hashes.push_back(h);
    }
    hashes.push_back(hash_t{});
    proto::getheaders payload = {
      current_version, hashes, {}
    };
    INFO() << addr << " <== getheaders";
    to_socket(sock_fd, make_header("getheaders", payload));
    to_socket(sock_fd, payload);
  };

  void handle_version(proto::header const&) {
    proto::version payload;
    from_socket(sock_fd, payload);
    node_version = payload.version;
    current_version = std::min(current_version, node_version);
    INFO() << addr << ": [version] node version=" << node_version;
    INFO() << addr << ": [version] current version=" << current_version;

    to_socket(sock_fd, make_header("verack"));

    send_sendcmpct();
    send_getaddr();
    send_block_headers(db.last_height());
  }

  void handle_sendcmpct(proto::header const&) {
    proto::sendcmpct payload;
    from_socket(sock_fd, payload);
    INFO() << addr << ": [sendcmpct] enabled=" << int{payload.cmpct_enabled};
    INFO() << addr << ": [sendcmpct] version=" << payload.version;
  }

  void handle_sendheaders(proto::header const&) {
    proto::headers payload;
    INFO() << addr << " <== headers";
    to_socket(sock_fd, make_header("headers", payload));
    to_socket(sock_fd, payload);
  }

  void handle_headers(proto::header const&) {
    proto::headers payload;
    from_socket(sock_fd, payload);

    if (!payload.headers.empty()) {
      auto&& e = payload.headers.back();
      INFO() << "\tBlocks (" << payload.headers.size() << "):";
      INFO() << "\t\t"
             << e.version << ' '
             << "prev=" << to_string(e.prev_block) << ' '
             << "root=" << to_string(e.merkle_root) << ' '
             << e.timestamp << ' '
             << std::hex << e.bits << std::dec << ' '
             << e.nonce << ' '
             << e.txn_count;
      INFO() << "\t\t"
             << prettify_hash(target_to_s(e.bits));
      INFO() << "\t\t"
             << "hash=" << prettify_hash(to_string(e.hash()));
    }

    auto height = db.last_height();
    for (auto&& e : payload.headers) {
      ++height;
      db.save_block(height, e);
    }

    INFO() << "\tLast height: " << db.last_height();

    if (!payload.headers.empty()) {
      send_block_headers(db.last_height());
    } else if (state == STATE_CHAIN_DOWNLOADING)
      state = STATE_CHAIN_DOWNLOADED;
  }
  
  void handle_feefilter(proto::header const&) {
    proto::feefilter payload;
    from_socket(sock_fd, payload);
    feerate = payload.feerate;
    INFO() << addr << ": [feefilter] feerate=" << feerate << " satoshis/KiB";
  }

  void handle_ping(proto::header const&) {
    proto::ping ping;
    from_socket(sock_fd, ping);
    INFO() << addr << ": [ping] nonce=" << ping.nonce;

    proto::pong pong{ping.nonce};
    to_socket(sock_fd, make_header("pong", pong));
    to_socket(sock_fd, pong);

    if (state != STATE_CHAIN_DOWNLOADING)
      send_block_headers(db.last_height());
  }

  void handle_pong(proto::header const&) {
    proto::pong pong;
    from_socket(sock_fd, pong);
    INFO() << addr << ": [pong] nonce=" << pong.nonce;
  }

  void handle_addr(proto::header const&) {
    proto::addr payload;
    from_socket(sock_fd, payload);
    INFO() << addr << ": [addr] " << payload.addrs.size() << " peers";
    if (!payload.addrs.empty()) {
      auto&& e = payload.addrs.back();
      INFO() << "\t\t" << addr_to_s(e.addr) << ':' << e.port;
    }
  }

  void handle_block(proto::header const&) {
    proto::block payload;
    from_socket(sock_fd, payload);
    INFO() << addr << ": [block] " << payload.txs.size() << " txs";
    unsigned limit = 45;
    for (auto&& e : payload.txs) {
      if (e.tx_witnesses.empty())
        continue;
      INFO() << "\ttx:     " << to_string(compute_hash(e));
      for (auto& t: e.txs_in)
        INFO() << "\ttx_in:  " << btc::proto::script{{t.signature_script}};
      for (auto& t: e.txs_out) {
        INFO() << "\ttx_out: " << std::setfill(' ') << std::setw(16) << std::right << t.value << " satoshis";
        INFO() << "\ttx_out: " << btc::proto::script{{t.pk_script}};
      }
      for (auto& t: e.tx_witnesses)
        INFO() << "\ttx_wt:  " << btc::proto::script{{t.data}};
      if (!--limit)
        break;
    }
    INFO() << "\t\tmerkle tree: " << prettify_hash(to_string(merkle_tree(payload.txs)));
  }

  void handle_inv(proto::header const&) {
    proto::inv payload;
    from_socket(sock_fd, payload);
    INFO() << addr << ": [inv] " << payload.inventory.size() << " items";
    unsigned limit = 3;
    for (auto&& e : payload.inventory) {
      INFO() << addr << ": [inv] \t" << e.type << ' ' << to_string(e.hash);
      if (!--limit)
        break;
    }

    switch (state) {
    case STATE_MEMPOOL_REQUESTING:
      {
        proto::getdata getdata;
        for (auto&& i : payload.inventory) {
          if (i.type != proto::inv_vect::MSG_TX)
            continue;
          getdata.inventory.push_back(proto::inv_vect{i.type, i.hash});
          mempool_transactions.insert(i.hash);
        }
        INFO() << addr << " <== getdata (" << mempool_transactions.size() << " mempool txs)";
        to_socket(sock_fd, make_header("getdata", getdata));
        to_socket(sock_fd, getdata);

        state = STATE_MEMPOOL_TX_REQUESTING;
        break;
      }
    // case STATE_TX_REQUESTING:
    //   {
    //     proto::getdata getdata;
    //     for (auto&& i : payload.inventory) {
    //       getdata.emplace_back(i.type, i.hash);
    //     }
    //     INFO() << " <== getdata (" << getdata.inventory.size() << " items)";
    //     to_socket(sock_fd, make_header("getdata", getdata));
    //     to_socket(sock_fd, getdata);

    //     state = STATE_MEMPOOL_TX_REQUESTING;
    //     break;
    //   }
    default:
      break;
    }
  }

  void handle_notfound(proto::header const&) {
    proto::notfound payload;
    from_socket(sock_fd, payload);

    switch (state) {
    case STATE_MEMPOOL_TX_REQUESTING:
      WARN() << payload.inventory.size() << " mempool txs are not found";
      for (auto&& i : payload.inventory) {
        if (i.type != proto::inv_vect::MSG_TX)
          continue;
        if (auto iter = mempool_transactions.find(i.hash);
            iter != mempool_transactions.end()) {
          // WARN() << "mempool tx " << to_string(i.hash) << " is not found";
          mempool_transactions.erase(iter);
        }
      }
      break;

    case STATE_MEMPOOL_FEE_REQUESTING:
      WARN() << payload.inventory.size() << " fee txs are not found";
      for (auto&& i : payload.inventory) {
        if (i.type != proto::inv_vect::MSG_TX)
          continue;
        if (auto iter = fee_transactions.find(i.hash);
            iter != fee_transactions.end()) {
          // WARN() << "fee tx " << to_string(i.hash) << " is not found";
          fee_transactions.erase(iter);
        }
      }
      break;

    default:
      break;
    };
  }

  void handle_tx(proto::header const&) {
    proto::tx payload;
    from_socket(sock_fd, payload);
    // INFO() << addr << ": [tx]";

    auto hash = compute_hash(payload);

    switch (state) {
    case STATE_MEMPOOL_TX_REQUESTING:
      if (auto iter = mempool_transactions.find(hash);
          iter != mempool_transactions.end()) {
        transactions[hash] = std::move(payload);
        mempool_transactions.erase(iter);
      }
      break;

    case STATE_MEMPOOL_FEE_REQUESTING:
      if (auto iter = fee_transactions.find(hash);
          iter != fee_transactions.end()) {
        transactions[hash] = std::move(payload);
        fee_transactions.erase(iter);
      }
      break;

    default:
      break;
    };
  }

  void handle_unknown(proto::header const& hdr) {
    char buf[128];
    std::size_t len = hdr.length;
    while (len > 0) {
      std::size_t to_read = std::min(sizeof(buf), len);
      int rv = read(sock_fd, buf, to_read);
      if (rv <= 0)
        throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)),
                                "read failed");
      len -= to_read;
    }
  }
};

void usage(char const* progname) {
  std::cerr << "Usage: " << progname << " <peer>\n";
}

int main(int argc, char* argv[]) {
  char const* peer_addr = nullptr;
  unsigned platform_id = 0;
  unsigned device_id = 0;
  int argc_i;
  for (argc_i = 1; argc_i < argc; ++argc_i) {
    if (strcmp(argv[argc_i], "--platform-id") == 0) {
      platform_id = std::atoi(argv[++argc_i]);
    } else if (strcmp(argv[argc_i], "--device-id") == 0) {
      device_id = std::atoi(argv[++argc_i]);
    } else if (strcmp(argv[argc_i], "--opencl-info") == 0) {
      opencl::print_info(std::cerr);
      return 0;
    } else {
      peer_addr = argv[argc_i];
    }
  }

  if (0) {
    opencl::context ctx;
    hash32_t target_hash = {0x00000000, 0x00000000, 0x0031d97c, 0xffffffff,
                            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    std::fill(target_hash.begin(), target_hash.end(), 0x00);
    ctx.init(platform_id, device_id);

    sha256_program hasher_prog(ctx);
    std::string msg = "The quick brown fox jumps over the lazy dog";
    auto [min_hash, min_nonce] = hasher_prog(target_hash,
                                             std::vector<std::uint8_t>(std::cbegin(msg), std::cend(msg)),
                                             0, 0x0fffffff);
    std::cerr << "[opencl] min_hash: " << to_string(min_hash);
    std::cerr << "[opencl] min_nonce: " << min_nonce;
    ctx.cleanup();
    return 0;
  }

  if (!peer_addr) {
    usage(argv[0]);
    return 1;
  }

  try {
    db_t db("block_headers.db");
    node_t node{peer_addr, db};

    g_ctx = std::make_unique<opencl::context>();
    g_ctx->init(platform_id, device_id);

    node.run();

    g_ctx->cleanup();

  } catch (std::system_error const& err) {
    ERROR() << "Error occurred (" << err.code() << "): " << err.what();
    return 1;
  }

  return 0;
}
