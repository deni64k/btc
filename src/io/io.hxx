#pragma once

#include "proto/commands.hxx"
#include "io/ops.hxx"

namespace {

std::vector<std::uint8_t> block_hash_buf(proto::block_headers const& block) {
  std::ostringstream os;
  ostream_ops ops(os);
  ops.write(block.version);
  ops.write(block.prev_block);
  ops.write(block.merkle_root);
  ops.write(block.timestamp);
  ops.write(block.bits);
  ops.write(block.nonce);
  std::string buf_s = os.str();
  return {buf_s.cbegin(), buf_s.cend()};
}

}
