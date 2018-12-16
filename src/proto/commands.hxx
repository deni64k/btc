#pragma once

#include <cstdlib>
#include <vector>

#include "common/types.hxx"
#include "serdes.hxx"
#include "utility.hxx"

template <typename... Payloads> hash_t compute_hash(Payloads&&... payloads);

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
