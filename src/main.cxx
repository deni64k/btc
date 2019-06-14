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

#include "common/crypto.hxx"
#include "common/logging.hxx"
#include "common/types.hxx"
#include "hasher.hxx"
#include "opencl.hxx"
#include "proto/commands.hxx"
#include "io/io.hxx"
#include "proto/script.hxx"
#include "utility.hxx"

static_assert(__cpp_concepts >= 201500, "Compile with -fconcepts");
static_assert(__cplusplus >= 201500, "C++17 at least required");

using namespace std::chrono_literals;

template <typename... Payloads> hash_t compute_hash(Payloads&&... payloads);

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
  
  static int conn4(char const* addr) {
    int sock_fd = -1;
    int ret;
    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1) {
      throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)),
                              "socket failed");
    }
    struct sockaddr_in server_addr;
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, addr, &server_addr.sin_addr);
    server_addr.sin_port = htons(8333);
    ret = connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret == -1) {
      close(sock_fd);
      throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)),
                              "connect failed");
    }
    return sock_fd;
  }

  static int conn6(char const* addr) {
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

  static int conn(char const* addr) {
    return strchr(addr, ':') ? conn6(addr) : conn4(addr);
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

        auto const last_height = db.last_height();
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

          auto const total_value = tx.total_value();
          auto const fee = prev_value - total_value;
          mining_txs.emplace_back(hash, fee);
          // INFO() << "mempool tx " << to_string(hash)
          //        << "\thas fee " << prev_value << '-' << total_value << '=' << fee;
        }

        auto by_fee = [](auto const& lhs, auto const& rhs) {
                        return lhs.second > rhs.second;
                      };
        std::sort(mining_txs.begin(), mining_txs.end(), by_fee);
        std::uint64_t total_fee = std::accumulate(
            mining_txs.cbegin(), mining_txs.cend(), 0,
            [](auto state, auto const& x) {
              return state + x.second;
            });
        INFO() << "We go for fee of " << total_fee << " satoshis from " << mining_txs.size() << " txs";

        proto::block_headers last_block;
        db.load_block(last_height, last_block);

        state = STATE_END;
        auto target_hash = target_to_hash32(last_block.bits);
        auto mine = [last_height, last_block, total_fee, target_hash](
            std::vector<std::pair<hash_t, std::size_t>> const& mining_txs,
            sha256_program& hasher_prog,
            std::uint32_t const nonce_begin,
            std::uint32_t const nonce_end) mutable {
          std::vector<hash_t> txs;
          txs.reserve(1 + mining_txs.size());

          auto tx = reward_tx(reward(last_height) + total_fee);
          txs.push_back(compute_hash(tx));
          std::transform(mining_txs.cbegin(), mining_txs.cend(), std::back_inserter(txs),
                         [](auto const &x) {
                           return x.first;
                         });
          auto merkle_root = merkle_tree(txs);

          proto::block_headers block = {
            proto::VERSION,
            last_block.hash(),
            merkle_root,
            static_cast<uint32_t>(::time(nullptr) + 600),
            last_block.bits,
            0
          };
          auto buf = block_hash_buf(block);

          auto digest_state = btc::crypto::sha256_first_block(buf.data(), buf.size());

          INFO() << "target: " << prettify_hash(target_to_s(block.bits));
          INFO() << "mining with block:\n" << block;

          // std::this_thread::sleep_for(30ms);
          auto [min_hash, min_nonce] = hasher_prog(target_hash, buf,
                                                   digest_state.W, digest_state.hash,
                                                   nonce_begin, nonce_end);

          INFO() << "\tmin_hash:  " << prettify_hash(to_string(min_hash));
          INFO() << "\tmin_nonce: " << min_nonce;

          if (compare_hashes(min_hash, target_to_hash32(block.bits)) <= 0) {
            INFO() << "===>>> found! <<<===";
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

        std::thread miner_thr([mine, mining_txs, by_fee]() mutable {
          sha256_program hasher_prog(*g_ctx);
          do {
            mine(mining_txs,
                 hasher_prog,
                 std::numeric_limits<std::uint32_t>::min(),
                 std::numeric_limits<std::uint32_t>::max());
          } while (std::next_permutation(mining_txs.begin(), mining_txs.end(), by_fee));
          INFO() << "all permutations have been attempted";
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
  bool test_mining = false;
  std::uint32_t test_height;

  int argc_i;
  for (argc_i = 1; argc_i < argc; ++argc_i) {
    if (strcmp(argv[argc_i], "--platform-id") == 0) {
      platform_id = std::atoi(argv[++argc_i]);
    } else if (strcmp(argv[argc_i], "--device-id") == 0) {
      device_id = std::atoi(argv[++argc_i]);
    } else if (strcmp(argv[argc_i], "--opencl-info") == 0) {
      opencl::print_info(std::cerr);
      return 0;
    } else if (strcmp(argv[argc_i], "--test-mining") == 0) {
      test_mining = true;
      test_height = std::uint32_t(std::atoll(argv[++argc_i]));
    } else {
      peer_addr = argv[argc_i];
    }
  }

  if (test_mining) {
    std::uint32_t const height = test_height;
    proto::block_headers block;
    db_t db("block_headers.db");
    db.load_block(height, block);
    auto buf = block_hash_buf(block);

    auto digest_state = btc::crypto::sha256_first_block(buf.data(), buf.size());

    auto target_hash = target_to_hash32(block.bits);
    INFO() << "target: " << prettify_hash(to_string(target_hash));
    INFO() << "hash: "   << prettify_hash(to_string(block.hash()));
    INFO() << "mining with block:\n" << block;

    opencl::context ctx;
    ctx.init(platform_id, device_id);

    sha256_program hasher_prog(ctx);
    // auto [min_hash, min_nonce] = hasher_prog(target_hash, buf, 0, 1);
    auto [min_hash, min_nonce] = hasher_prog(target_hash, buf,
                                             digest_state.W, digest_state.hash,
                                             // block.nonce-1, block.nonce+1);
                                             0x00000000, 0xffffffff);

    INFO() << "min_hash <=> target_hash: " << compare_hashes(min_hash, target_hash);
    INFO() << "min_hash: " << to_string(min_hash);
    INFO() << "min_nonce: " << min_nonce;
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
