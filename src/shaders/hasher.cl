#ifndef __ENDIAN_LITTLE__
# error Kernel requires little endian device
#endif

#ifndef uint32_t
#define uint32_t unsigned int
#endif

#define countof(X) sizeof(X) / sizeof(X[0])

/* #undef printf
 * #define printf(...) */

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

#define K_CONSTS                                                        \
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, \
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, \
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, \
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, \
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, \
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, \
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, \
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

#define K0 0x428a2f98
#define K1 0x71374491
#define K2 0xb5c0fbcf
#define K3 0xe9b5dba5
#define K4 0x3956c25b
#define K5 0x59f111f1
#define K6 0x923f82a4
#define K7 0xab1c5ed5
#define K8 0xd807aa98
#define K9 0x12835b01
#define K10 0x243185be
#define K11 0x550c7dc3
#define K12 0x72be5d74
#define K13 0x80deb1fe
#define K14 0x9bdc06a7
#define K15 0xc19bf174
#define K16 0xe49b69c1
#define K17 0xefbe4786
#define K18 0xfc19dc6
#define K19 0x240ca1cc
#define K20 0x2de92c6f
#define K21 0x4a7484aa
#define K22 0x5cb0a9dc
#define K23 0x76f988da
#define K24 0x983e5152
#define K25 0xa831c66d
#define K26 0xb00327c8
#define K27 0xbf597fc7
#define K28 0xc6e00bf3
#define K29 0xd5a79147
#define K30 0x6ca6351
#define K31 0x14292967
#define K32 0x27b70a85
#define K33 0x2e1b2138
#define K34 0x4d2c6dfc
#define K35 0x53380d13
#define K36 0x650a7354
#define K37 0x766a0abb
#define K38 0x81c2c92e
#define K39 0x92722c85
#define K40 0xa2bfe8a1
#define K41 0xa81a664b
#define K42 0xc24b8b70
#define K43 0xc76c51a3
#define K44 0xd192e819
#define K45 0xd6990624
#define K46 0xf40e3585
#define K47 0x106aa070
#define K48 0x19a4c116
#define K49 0x1e376c08
#define K50 0x2748774c
#define K51 0x34b0bcb5
#define K52 0x391c0cb3
#define K53 0x4ed8aa4a
#define K54 0x5b9cca4f
#define K55 0x682e6ff3
#define K56 0x748f82ee
#define K57 0x78a5636f
#define K58 0x84c87814
#define K59 0x8cc70208
#define K60 0x90befffa
#define K61 0xa4506ceb
#define K62 0xbef9a3f7
#define K63 0xc67178f2

#define sha_round_16(t)                                                 \
  T1 = H + sigma1(E) + ch(E, F, G) + K##t + W##t;                       \
  T2 = sigma0(A) + maj(A, B, C);                                        \
  H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;    \

#define sha_round(t, t2, t7, t15, t16)                                  \
  W##t = gamma1(W##t2) + W##t7 + gamma0(W##t15) + W##t16;               \
  T1 = H + sigma1(E) + ch(E, F, G) + K##t + W##t;                       \
  T2 = sigma0(A) + maj(A, B, C);                                        \
  H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;    \

struct block_state {
  uint merkle_root;
  uint timestamp;
  uint target_bits;
  uint nonce;
  uint A, B, C, D, E, F, G, H, T1, T2;
  uint W16, W17, W19;
  uint W16_K, W17_K, W19_K;
};

#define htonl(x)                                 \
  ((((x) & 0xff000000U) >> 24)                   \
   | (((x) & 0x00ff0000U) >>  8)                 \
   | (((x) & 0x0000ff00U) <<  8)                 \
   | (((x) & 0x000000ffU) << 24))

#define ntohl(x)                                 \
  ((((x) & 0xff000000U) >> 24)                   \
   | (((x) & 0x00ff0000U) >>  8)                 \
   | (((x) & 0x0000ff00U) <<  8)                 \
   | (((x) & 0x000000ffU) << 24))

#if 1

inline uint ch(uint x, uint y, uint z);
inline uint maj(uint x, uint y, uint z);
inline uint sigma0(uint x);
inline uint sigma1(uint x);
inline uint gamma0(uint x);
inline uint gamma1(uint x);

inline uint ch(uint x, uint y, uint z) {
  return (x & y) ^ (~x & z);
}

inline uint maj(uint x, uint y, uint z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline uint sigma0(uint x) {
  return rotate(x, 30u) ^ rotate(x, 19u) ^ rotate(x, 10u);
}

inline uint sigma1(uint x) {
  return rotate(x, 26u) ^ rotate(x, 21u) ^ rotate(x, 7u);
}

inline uint gamma0(uint x) {
  return rotate(x, 25u) ^ rotate(x, 14u) ^ (x >> 3);
}

inline uint gamma1(uint x) {
  return rotate(x, 15u) ^ rotate(x, 13u) ^ (x >> 10);
}

#else

#define ch(x, y, z) \
  (((x) & (y)) ^ (~(x) & (z)))

#define maj(x, y, z)                            \
  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define sigma0(x)                                                       \
  (rotate((uint)(x), 30u) ^ rotate((uint)(x), 19u) ^ rotate((uint)(x), 10u))

#define sigma1(x) \
  (rotate((uint)(x), 26u) ^ rotate((uint)(x), 21u) ^ rotate((uint)(x), 7u))

#define gamma0(x) \
  (rotate((uint)(x), 25u) ^ rotate((uint)(x), 14u) ^ ((uint)(x) >> 3))

#define gamma1(x) \
  (rotate((uint)(x), 15u) ^ rotate((uint)(x), 13u) ^ ((uint)(x) >> 10))

#endif

#if 0

inline uint8 sha256_init(void);
uint8 sha256_update(char* message, uint8 digest);
uint8 sha256_finish_padded(char* message, uint ulen, uint orig_ulen, uint8 digest);
uint8 sha256_finish(char* message, uint ulen, uint, uint8 digest);

inline uint8 sha256_init(void) {
  return (uint8)(H0, H1, H2, H3, H4, H5, H6, H7);
}

uint8 sha256_update(char* message, uint8 digest) {
  uint K[64] = { K_CONSTS };

  uint W[64];
  uint A, B, C, D, E, F, G, H, T1, T2;
  uint t;

  A = digest.s0;
  B = digest.s1;
  C = digest.s2;
  D = digest.s3;
  E = digest.s4;
  F = digest.s5;
  G = digest.s6;
  H = digest.s7;

#pragma unroll
  for (t = 0; t < 16; ++t) {
    W[t]  = (uchar)(*message) << 24; ++message;
    W[t] |= (uchar)(*message) << 16; ++message;
    W[t] |= (uchar)(*message) <<  8; ++message;
    W[t] |= (uchar)(*message) <<  0; ++message;
  }

#pragma unroll
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

  digest += (uint8)(A, B, C, D, E, F, G, H);

  return digest;
}

uint8 sha256_finish_padded(char* message, uint ulen, uint orig_ulen, uint8 digest) {
  uint K[64] = { K_CONSTS };

  uint W[64];
  uint A, B, C, D, E, F, G, H, T1, T2;
  uint t;

  A = digest.s0;
  B = digest.s1;
  C = digest.s2;
  D = digest.s3;
  E = digest.s4;
  F = digest.s5;
  G = digest.s6;
  H = digest.s7;

#pragma unroll
  for (t = 0; t < ulen / 4; ++t) {
    W[t]  = (uchar)(*message) << 24; ++message;
    W[t] |= (uchar)(*message) << 16; ++message;
    W[t] |= (uchar)(*message) << 8;  ++message;
    W[t] |= (uchar)(*message) << 0;  ++message;
  }
  W[t++] = 0x80000000;
  for (; t < 15; ++t)
    W[t] = 0;
  W[15] = orig_ulen * 8;

#pragma unroll
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

  digest += (uint8)(A, B, C, D, E, F, G, H);

  return digest;
}

inline uint8 sha256_second_hash(uint8 digest) {
  uint K[64] = { K_CONSTS };

  uint W[64];
  uint A, B, C, D, E, F, G, H, T1, T2;
  uint t, ulen = 32;

  W[0] = digest.s0;
  W[1] = digest.s1;
  W[2] = digest.s2;
  W[3] = digest.s3;
  W[4] = digest.s4;
  W[5] = digest.s5;
  W[6] = digest.s6;
  W[7] = digest.s7;
  W[8] = 0x80000000;
#pragma unroll
  for (t = 9; t < 15; ++t)
    W[t] = 0;
  W[15] = ulen * 8;

  A = H0;
  B = H1;
  C = H2;
  D = H3;
  E = H4;
  F = H5;
  G = H6;
  H = H7;

#pragma unroll
  for (t = 0; t < 61; ++t) {
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

  if (E != 0xa41f32e7)
    return (uint8)(UINT_MAX);

  for (; t < 64; ++t) {
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

  return (uint8)(H0, H1, H2, H3, H4, H5, H6, H7) + (uint8)(A, B, C, D, E, F, G, H);
}

uint8 sha256_finish(char* message, uint ulen, uint orig_len, uint8 digest) {
  uint K[64] = { K_CONSTS };

  unsigned t;
  uint msg_pad;
  unsigned stop;
  uint i, item, total;
  uint W[64], A, B, C, D, E, F, G, H, T1, T2;
  int  current_pad;

  msg_pad = 0;

  total  = ulen / 64 + 1;
  total += (ulen % 64 >= 56) ? 1 : 0;

  for (item = 0; item < total; ++item) {
    A = digest.s0;
    B = digest.s1;
    C = digest.s2;
    D = digest.s3;
    E = digest.s4;
    F = digest.s5;
    G = digest.s6;
    H = digest.s7;

#pragma unroll
    for (t = 0; t < countof(W); ++t) {
      W[t] = 0x00000000;
    }

    msg_pad = item * 64;
    if (ulen > msg_pad) {
      current_pad = min(64u, ulen - msg_pad);
    } else {
      current_pad = -1;
    }

    //  printf("current_pad: %d\n",current_pad);
    if (current_pad > 0) {
      i = current_pad;

      stop = i / 4;
      for (t = 0 ; t < stop ; t++){
        W[t]  = ((uchar) message[msg_pad + t * 4 + 0]) << 24;
        W[t] |= ((uchar) message[msg_pad + t * 4 + 1]) << 16;
        W[t] |= ((uchar) message[msg_pad + t * 4 + 2]) << 8;
        W[t] |= (uchar)  message[msg_pad + t * 4 + 3];
      }

      switch (i % 4) {
      case 3:
        W[t]  = ((uchar) message[msg_pad + t * 4 + 0]) << 24;
        W[t] |= ((uchar) message[msg_pad + t * 4 + 1]) << 16;
        W[t] |= ((uchar) message[msg_pad + t * 4 + 2]) << 8;
        W[t] |= ((uchar) 0x80);
        break;
      case 2:
        W[t]  = ((uchar) message[msg_pad + t * 4 + 0]) << 24;
        W[t] |= ((uchar) message[msg_pad + t * 4 + 1]) << 16;
        W[t] |= 0x8000;
        break;
      case 1:
        W[t]  = ((uchar) message[msg_pad + t * 4]) << 24;
        W[t] |= 0x800000;
        break;
      case 0:
        W[t]  = 0x80000000;
        break;
      }

      if (current_pad < 56) {
        W[15] = orig_len * 8;
      }
    } else if (current_pad < 0) {
      if (orig_len % 64 == 0)
        W[0] = 0x80000000;
      W[15] = orig_len * 8;
    }

#pragma unroll
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

    digest += (uint8)(A, B, C, D, E, F, G, H);
  }

  return digest;
}
#endif

uint8 sha256_nonce_block(struct block_state* s);

uint8 sha256_nonce_block(struct block_state* s) {
  uint A = s->A, B = s->B, C = s->C, D = s->D;
  uint E = s->E, F = s->F, G = s->G, H = s->H;
  uint T1 = s->T1, T2 = s->T2;
#define W0  s->merkle_root
#define W1  s->timestamp
#define W2  s->target_bits
#define W3  s->nonce
#define W4  0x80000000U
#define W5  0x00000000U
#define W6  0x00000000U
#define W7  0x00000000U
#define W8  0x00000000U
#define W9  0x00000000U
#define W10 0x00000000U
#define W11 0x00000000U
#define W12 0x00000000U
#define W13 0x00000000U
#define W14 0x00000000U
#define W15 0x00000280U
#define W16 s->W16
#define W17 s->W17
#define W19 s->W19
#define W16_K s->W16_K
#define W17_K s->W17_K
#define W19_K s->W19_K
  uint           W18,      W20, W21, W22, W23;
  uint W24, W25, W26, W27, W28, W29, W30, W31;
  uint W32, W33, W34, W35, W36, W37, W38, W39;
  uint W40, W41, W42, W43, W44, W45, W46, W47;
  uint W48, W49, W50, W51, W52, W53, W54, W55;
  uint W56, W57, W58, W59, W60, W61, W62, W63;

  sha_round_16(4);
  sha_round_16(5);
  sha_round_16(6);
  sha_round_16(7);
  sha_round_16(8);
  sha_round_16(9);
  sha_round_16(10);
  sha_round_16(11);
  sha_round_16(12);
  sha_round_16(13);
  sha_round_16(14);
  sha_round_16(15);
  T1 = H + sigma1(E) + ch(E, F, G) + W16_K; T2 = sigma0(A) + maj(A, B, C); H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
  T1 = H + sigma1(E) + ch(E, F, G) + W17_K; T2 = sigma0(A) + maj(A, B, C); H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
  sha_round(18, 16, 11,  3,  2);
  T1 = H + sigma1(E) + ch(E, F, G) + W19_K; T2 = sigma0(A) + maj(A, B, C); H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
  sha_round(20, 18, 13,  5,  4);
  sha_round(21, 19, 14,  6,  5);
  sha_round(22, 20, 15,  7,  6);
  sha_round(23, 21, 16,  8,  7);
  sha_round(24, 22, 17,  9,  8);
  sha_round(25, 23, 18, 10,  9);
  sha_round(26, 24, 19, 11, 10);
  sha_round(27, 25, 20, 12, 11);
  sha_round(28, 26, 21, 13, 12);
  sha_round(29, 27, 22, 14, 13);
  sha_round(30, 28, 23, 15, 14);
  sha_round(31, 29, 24, 16, 15);
  sha_round(32, 30, 25, 17, 16);
  sha_round(33, 31, 26, 18, 17);
  sha_round(34, 32, 27, 19, 18);
  sha_round(35, 33, 28, 20, 19);
  sha_round(36, 34, 29, 21, 20);
  sha_round(37, 35, 30, 22, 21);
  sha_round(38, 36, 31, 23, 22);
  sha_round(39, 37, 32, 24, 23);
  sha_round(40, 38, 33, 25, 24);
  sha_round(41, 39, 34, 26, 25);
  sha_round(42, 40, 35, 27, 26);
  sha_round(43, 41, 36, 28, 27);
  sha_round(44, 42, 37, 29, 28);
  sha_round(45, 43, 38, 30, 29);
  sha_round(46, 44, 39, 31, 30);
  sha_round(47, 45, 40, 32, 31);
  sha_round(48, 46, 41, 33, 32);
  sha_round(49, 47, 42, 34, 33);
  sha_round(50, 48, 43, 35, 34);
  sha_round(51, 49, 44, 36, 35);
  sha_round(52, 50, 45, 37, 36);
  sha_round(53, 51, 46, 38, 37);
  sha_round(54, 52, 47, 39, 38);
  sha_round(55, 53, 48, 40, 39);
  sha_round(56, 54, 49, 41, 40);
  sha_round(57, 55, 50, 42, 41);
  sha_round(58, 56, 51, 43, 42);
  sha_round(59, 57, 52, 44, 43);
  sha_round(60, 58, 53, 45, 44);
  sha_round(61, 59, 54, 46, 45);
  sha_round(62, 60, 55, 47, 46);
  sha_round(63, 61, 56, 48, 47);

#undef W0
#undef W1
#undef W2
#undef W3
#undef W4
#undef W5
#undef W6
#undef W7
#undef W8
#undef W9
#undef W10
#undef W11
#undef W12
#undef W13
#undef W14
#undef W15
#undef W16
#undef W17
#undef W19
#undef W16_K
#undef W17_K
#undef W19_K

  return (uint8)(A, B, C, D, E, F, G, H);
}

inline bool compare_hash(uint8 min_hash, uint8 hash);

inline bool compare_hash(uint8 min_hash, uint8 hash) {
  if (hash.s7 < min_hash.s7) return true;
  if (hash.s7 > min_hash.s7) return false;

  if (hash.s6 < min_hash.s6) return true;
  if (hash.s6 > min_hash.s6) return false;

  if (hash.s5 < min_hash.s5) return true;
  if (hash.s5 > min_hash.s5) return false;

  if (hash.s4 < min_hash.s4) return true;
  if (hash.s4 > min_hash.s4) return false;

  if (hash.s3 < min_hash.s3) return true;
  if (hash.s3 > min_hash.s3) return false;

  if (hash.s2 < min_hash.s2) return true;
  if (hash.s2 > min_hash.s2) return false;

  if (hash.s1 < min_hash.s1) return true;
  if (hash.s1 > min_hash.s1) return false;

  if (hash.s0 < min_hash.s0) return true;

  return false;
}

__kernel void mine(uint  merkle_root__,
                   uint  timestamp__,
                   uint  target_bits__,
                   uint8 hash_prenonce__,
                   uint  batch_offset__,
                   __local    uint8* min_hash_group,
                   __local    uint*  min_nonce_group,
                   __global   uint* digests,
                   __global   uint* min_nonces) {

  __private uint  id = get_global_id(0);
  __private uint  local_id = get_local_id(0);
  __private uint  group_id = get_group_id(0);
  __private uint  local_size = get_local_size(0);
  __private uint  nonce_start = (id + batch_offset__) * 4*1024;
  __private uint  nonce_finish = nonce_start + 4*1024;
  __private uint8 min_hash = (uint8)(UINT_MAX);
  __private uint  min_nonce;
  if (nonce_finish < nonce_start)
    nonce_finish = 0xffffffffU;

  __private uint  merkle_root   = merkle_root__;
  __private uint  timestamp     = timestamp__;
  __private uint  target_bits   = target_bits__;
  __private uint8 hash_prenonce = hash_prenonce__;
  __private uint8 hash_nonce;
  __private uint8 hash2_nonce;

  uint A = hash_prenonce.s0;
  uint B = hash_prenonce.s1;
  uint C = hash_prenonce.s2;
  uint D = hash_prenonce.s3;
  uint E = hash_prenonce.s4;
  uint F = hash_prenonce.s5;
  uint G = hash_prenonce.s6;
  uint H = hash_prenonce.s7;
  uint T1, T2;
  uint W16, W17, W18, W19, W20, W21, W22, W23;
  uint W24, W25, W26, W27, W28, W29, W30, W31;
  uint W32, W33, W34, W35, W36, W37, W38, W39;
  uint W40, W41, W42, W43, W44, W45, W46, W47;
  uint W48, W49, W50, W51, W52, W53, W54, W55;
  uint W56, W57, W58, W59, W60, W61, W62, W63;

  uint nonce = nonce_start;
#define W0  merkle_root
#define W1  timestamp
#define W2  target_bits
#define W3  nonce
  sha_round_16(0);
  sha_round_16(1);
  sha_round_16(2);
  sha_round_16(3);
#undef W0
#undef W1
#undef W2
#undef W3

  W16 = gamma0(timestamp) + merkle_root;
  W17 = gamma1(0x00000280U) + 0x00000000U + gamma0(target_bits) + timestamp;
  W19 = gamma1(W17) + 0x00000000U + gamma0(0x80000000) + nonce;
  struct block_state prenonce_state = {
    merkle_root, timestamp, target_bits, nonce,
    A, B, C, D, E, F, G, H,
    T1, T2,
    W16, W17, W19,
    W16 + K16, W17 + K17, W19 + K19
  };
  do {
    hash_nonce  = sha256_nonce_block(&prenonce_state);
    hash_nonce += hash_prenonce;

    ++prenonce_state.nonce;
    ++prenonce_state.A;
    ++prenonce_state.E;
    ++prenonce_state.W19;
    ++prenonce_state.W19_K;

    /* hash2_nonce = sha256_second_hash(hash_nonce);
     * if (hash2_nonce.s7 != 0)
     *   continue; */
#define W0  hash_nonce.s0
#define W1  hash_nonce.s1
#define W2  hash_nonce.s2
#define W3  hash_nonce.s3
#define W4  hash_nonce.s4
#define W5  hash_nonce.s5
#define W6  hash_nonce.s6
#define W7  hash_nonce.s7
#define W8  0x80000000U
#define W9  0x00000000U
#define W10 0x00000000U
#define W11 0x00000000U
#define W12 0x00000000U
#define W13 0x00000000U
#define W14 0x00000000U
#define W15 0x00000100U

    A = H0; B = H1; C = H2; D = H3; E = H4; F = H5; G = H6; H = H7;

    sha_round_16(0);
    sha_round_16(1);
    sha_round_16(2);
    sha_round_16(3);
    sha_round_16(4);
    sha_round_16(5);
    sha_round_16(6);
    sha_round_16(7);
    sha_round_16(8);
    sha_round_16(9);
    sha_round_16(10);
    sha_round_16(11);
    sha_round_16(12);
    sha_round_16(13);
    sha_round_16(14);
    sha_round_16(15);

    sha_round(16, 14,  9,  1,  0);
    sha_round(17, 15, 10,  2,  1);
    sha_round(18, 16, 11,  3,  2);
    sha_round(19, 17, 12,  4,  3);
    sha_round(20, 18, 13,  5,  4);
    sha_round(21, 19, 14,  6,  5);
    sha_round(22, 20, 15,  7,  6);
    sha_round(23, 21, 16,  8,  7);
    sha_round(24, 22, 17,  9,  8);
    sha_round(25, 23, 18, 10,  9);
    sha_round(26, 24, 19, 11, 10);
    sha_round(27, 25, 20, 12, 11);
    sha_round(28, 26, 21, 13, 12);
    sha_round(29, 27, 22, 14, 13);
    sha_round(30, 28, 23, 15, 14);
    sha_round(31, 29, 24, 16, 15);
    sha_round(32, 30, 25, 17, 16);
    sha_round(33, 31, 26, 18, 17);
    sha_round(34, 32, 27, 19, 18);
    sha_round(35, 33, 28, 20, 19);
    sha_round(36, 34, 29, 21, 20);
    sha_round(37, 35, 30, 22, 21);
    sha_round(38, 36, 31, 23, 22);
    sha_round(39, 37, 32, 24, 23);
    sha_round(40, 38, 33, 25, 24);
    sha_round(41, 39, 34, 26, 25);
    sha_round(42, 40, 35, 27, 26);
    sha_round(43, 41, 36, 28, 27);
    sha_round(44, 42, 37, 29, 28);
    sha_round(45, 43, 38, 30, 29);
    sha_round(46, 44, 39, 31, 30);
    sha_round(47, 45, 40, 32, 31);
    sha_round(48, 46, 41, 33, 32);
    sha_round(49, 47, 42, 34, 33);
    sha_round(50, 48, 43, 35, 34);
    sha_round(51, 49, 44, 36, 35);
    sha_round(52, 50, 45, 37, 36);
    sha_round(53, 51, 46, 38, 37);
    sha_round(54, 52, 47, 39, 38);
    sha_round(55, 53, 48, 40, 39);
    sha_round(56, 54, 49, 41, 40);
    sha_round(57, 55, 50, 42, 41);
    sha_round(58, 56, 51, 43, 42);
    sha_round(59, 57, 52, 44, 43);
    sha_round(60, 58, 53, 45, 44);

    if (E != 0xa41f32e7)
      continue;

    sha_round(61, 59, 54, 46, 45);
    sha_round(62, 60, 55, 47, 46);
    sha_round(63, 61, 56, 48, 47);

#undef W0
#undef W1
#undef W2
#undef W3
#undef W4
#undef W5
#undef W6
#undef W7
#undef W8
#undef W9
#undef W10
#undef W11
#undef W12
#undef W13
#undef W14
#undef W15

    hash2_nonce = (uint8)(H0, H1, H2, H3, H4, H5, H6, H7) + (uint8)(A, B, C, D, E, F, G, H);

    if (compare_hash(min_hash, hash2_nonce)) {
      min_hash  = hash2_nonce;
      min_nonce = nonce;
    }
  } while (nonce++ != nonce_finish);

  min_hash_group[local_id]  = min_hash;
  min_nonce_group[local_id] = min_nonce;

  write_mem_fence(CLK_LOCAL_MEM_FENCE);

  if (local_id > 0)
    return;

  for (uint i = 1; i < local_size; ++i)
    if (compare_hash(min_hash_group[0], min_hash_group[i])) {
    min_hash_group[0] = min_hash_group[i];
    min_nonce_group[0] = min_nonce_group[i];
  }

  mem_fence(CLK_LOCAL_MEM_FENCE);

  __global uint* digest = digests + (group_id * 8);
  digest[0] = htonl(min_hash_group[0].s7);
  digest[1] = htonl(min_hash_group[0].s6);
  digest[2] = htonl(min_hash_group[0].s5);
  digest[3] = htonl(min_hash_group[0].s4);
  digest[4] = htonl(min_hash_group[0].s3);
  digest[5] = htonl(min_hash_group[0].s2);
  digest[6] = htonl(min_hash_group[0].s1);
  digest[7] = htonl(min_hash_group[0].s0);

  min_nonces[group_id] = ntohl(min_nonce_group[0]);
}
