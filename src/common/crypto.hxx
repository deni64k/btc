#pragma once

#include <array>
#include <cstdlib>

#include "common/types.hxx"

namespace btc::crypto {

static constexpr std::uint32_t K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

enum: std::uint32_t {
  H0 = 0x6a09e667,
  H1 = 0xbb67ae85,
  H2 = 0x3c6ef372,
  H3 = 0xa54ff53a,
  H4 = 0x510e527f,
  H5 = 0x9b05688c,
  H6 = 0x1f83d9ab,
  H7 = 0x5be0cd19
};

inline std::uint32_t rotate(std::uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

inline std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (~x & z);
}

inline std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline std::uint32_t sigma0(std::uint32_t x) {
  return rotate(x, 30u) ^ rotate(x, 19u) ^ rotate(x, 10u);
}

inline std::uint32_t sigma1(std::uint32_t x) {
  return rotate(x, 26u) ^ rotate(x, 21u) ^ rotate(x, 7u);
}

inline std::uint32_t gamma0(std::uint32_t x) {
  return rotate(x, 25u) ^ rotate(x, 14u) ^ (x >> 3);
}

inline std::uint32_t gamma1(std::uint32_t x) {
  return rotate(x, 15u) ^ rotate(x, 13u) ^ (x >> 10);
}

inline hash32_t sha256_init(void) {
  return {H0, H1, H2, H3, H4, H5, H6, H7};
}

struct sha256_mining_state {
  std::array<std::uint32_t, 16> W;
  hash32_t hash;
};

inline sha256_mining_state
sha256_first_block(std::uint8_t const* message, std::uint32_t ulen) {
  std::array<std::uint32_t, 64> W;
  std::uint32_t A, B, C, D, E, F, G, H, T1, T2;
  std::uint_fast32_t t;

  A = H0;
  B = H1;
  C = H2;
  D = H3;
  E = H4;
  F = H5;
  G = H6;
  H = H7;

  for (t = 0; t < 16; ++t) {
    W[t]  = ((std::uint32_t)(*message) & 0x000000ff) << 24; ++message;
    W[t] |= ((std::uint32_t)(*message) & 0x000000ff) << 16; ++message;
    W[t] |= ((std::uint32_t)(*message) & 0x000000ff) <<  8; ++message;
    W[t] |= ((std::uint32_t)(*message) & 0x000000ff) <<  0; ++message;
  }

  for (t = 0; t < 64; ++t) {
    if (t >= 16)
      W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
    T1 = H + sigma1(E) + ch(E, F, G) + K[t] + W[t];
    T2 = sigma0(A) + maj(A, B, C);
    H = G;
    G = F;
    F = E;
    E = D + T1;
    D = C;
    C = B;
    B = A;
    A = T1 + T2;
  }

  return sha256_mining_state{
    {W[0], W[1],  W[2],  W[3],  W[4],  W[5],  W[6],  W[7],
     W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15]},
    hash32_t{A + H0, B + H1, C + H2, D + H3,
             E + H4, F + H5, G + H6, H + H7}
  };
}

} // namespace btc::crypto
