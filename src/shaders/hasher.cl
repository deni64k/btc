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

uint htonl(uint x);

uint rotr(uint x, uint n);
uint ch(uint x, uint y, uint z);
uint maj(uint x, uint y, uint z);
uint sigma0(uint x);
uint sigma1(uint x);
uint gamma0(uint x);
uint gamma1(uint x);

bool compare_hash(uint8 min_hash, uint8 hash);
uint8 sha256_update(char* message, uint ulen, uint8 digest);
uint8 sha256_finish_padded(char* message, uint ulen, uint orig_ulen, uint8 digest);
uint8 sha256_finish(char* message, uint ulen, uint, uint8 digest);
uint8 sha256_init(void);

void flatten_hash(char* msg, uint bytes);

inline uint htonl(uint x) {
  return ((x & 0xff000000) >> 24)
       | ((x & 0x00ff0000) >>  8)
       | ((x & 0x0000ff00) <<  8)
       | ((x & 0x000000ff) << 24);
}

//#define rotr(x, n) rotate((uint)x, (uint)(32 - n))
inline uint rotr(uint x, uint n) {
  return rotate(x, 32 - n);
}

inline uint ch(uint x, uint y, uint z) {
  return (x & y) ^ (~x & z);
}

inline uint maj(uint x, uint y, uint z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline uint sigma0(uint x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint sigma1(uint x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint gamma0(uint x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint gamma1(uint x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

inline uint8 sha256_init(void) {
  return (uint8)(H0, H1, H2, H3, H4, H5, H6, H7);
}

uint8 sha256_update(char* message, uint ulen, uint8 digest) {
  uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  uint W[64];
  uint A, B, C, D, E, F, G, H, T1, T2;
  uint t, item, total;

  total = ulen / 64;
  /* printf("sha256_update: ulen=%u total=%u\n", ulen, total); */

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
    for (t = 0; t < 16; ++t) {
      W[t] = 0x00000000;
    }

#pragma unroll
    for (t = 0; t < 16; ++t) {
      W[t]  = (uchar)(*message) << 24; message++;
      W[t] |= (uchar)(*message) << 16; message++;
      W[t] |= (uchar)(*message) << 8;  message++;
      W[t] |= (uchar)(*message) << 0;  message++;

      /* printf("update: W[%u]: %08x\n", t, W[t]); */
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

    /* printf("sha256_update: item=%u, A=%08x\n", item, A); */

    //  for (t = 0; t < 80; t++)
    //    {
    //    printf("W[%d]: %u\n",t,W[t]);
    //    }
  }

  /* digest = (uint8)(A, B, C, D, E, F, G, H); */

  return digest;
  /* *digest_result = digest;
   * 
   * return total * 64; */
}

uint8 sha256_finish_padded(char* message, uint ulen, uint orig_ulen, uint8 digest) {
  uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

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
    W[t]  = (uchar)(*message) << 24; message++;
    W[t] |= (uchar)(*message) << 16; message++;
    W[t] |= (uchar)(*message) << 8;  message++;
    W[t] |= (uchar)(*message) << 0;  message++;
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

uint8 sha256_finish(char* message, uint ulen, uint orig_len, uint8 digest) {
  uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

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

bool compare_hash(uint8 min_hash, uint8 hash) {
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

void flatten_hash(char* msg, uint bytes) {
  msg[0] = bytes >> 24;
  msg[1] = bytes >> 16;
  msg[2] = bytes >>  8;
  msg[3] = bytes >>  0;
}

__kernel void mine(__global uint* target,
                   __global char* message_ptr,
                   __global uint* message_len_ptr,
                   __global uint* nonce_begins,
                   __global uint* nonce_ends,
                   __global uint* digests,
                   __global uint* min_nonces) {
  uint id = get_global_id(0);
  uint nonce_begin = nonce_begins[id];
  uint nonce_end = nonce_ends[id];
  char message_prenonce[64];
  char message_nonce[16];
  char message2[32];
  uint message_len = message_len_ptr[0];
  uint nonce_off   = message_len - 64;
  uint i, j;

  prefetch(message_ptr, message_len);

#pragma unroll
  for (i = 0; i < countof(message_prenonce); ++i) {
    message_prenonce[i] = message_ptr[i];
  }
#pragma unroll
  for (i = 0, j = 64; j < message_len; ++i, ++j) {
    message_nonce[i] = message_ptr[j];
  }

  uint8 min_hash = (uint8)(UINT_MAX);
  uint  min_nonce;

  uint8 hash_prenonce;
  uint8 hash_nonce;
  uint8 hash2_nonce;

  hash_prenonce = sha256_init();
  hash_prenonce = sha256_update(message_prenonce, 64, hash_prenonce);

  for (uint nonce = nonce_begin; ; ++nonce) {
    message_nonce[nonce_off - 1] = (uchar)((nonce >>  0) & 0xff);
    message_nonce[nonce_off - 2] = (uchar)((nonce >>  8) & 0xff);
    message_nonce[nonce_off - 3] = (uchar)((nonce >> 16) & 0xff);
    message_nonce[nonce_off - 4] = (uchar)((nonce >> 24) & 0xff);

    hash_nonce = sha256_finish_padded(message_nonce, 16, message_len, hash_prenonce);

    flatten_hash(&message2[0*4], hash_nonce.s0);
    flatten_hash(&message2[1*4], hash_nonce.s1);
    flatten_hash(&message2[2*4], hash_nonce.s2);
    flatten_hash(&message2[3*4], hash_nonce.s3);
    flatten_hash(&message2[4*4], hash_nonce.s4);
    flatten_hash(&message2[5*4], hash_nonce.s5);
    flatten_hash(&message2[6*4], hash_nonce.s6);
    flatten_hash(&message2[7*4], hash_nonce.s7);

    hash2_nonce = sha256_finish_padded(message2, 32, 32, sha256_init());

    hash2_nonce.s0 = htonl(hash2_nonce.s0);
    hash2_nonce.s1 = htonl(hash2_nonce.s1);
    hash2_nonce.s2 = htonl(hash2_nonce.s2);
    hash2_nonce.s3 = htonl(hash2_nonce.s3);
    hash2_nonce.s4 = htonl(hash2_nonce.s4);
    hash2_nonce.s5 = htonl(hash2_nonce.s5);
    hash2_nonce.s6 = htonl(hash2_nonce.s6);
    hash2_nonce.s7 = htonl(hash2_nonce.s7);
    
    if (compare_hash(min_hash, hash2_nonce)) {
      min_hash  = hash2_nonce;
      min_nonce = nonce;
    }

    if (nonce == nonce_end)
      break;
  }

  __global uint* digest = digests + (id * 8);
  digest[0] = min_hash.s7;
  digest[1] = min_hash.s6;
  digest[2] = min_hash.s5;
  digest[3] = min_hash.s4;
  digest[4] = min_hash.s3;
  digest[5] = min_hash.s2;
  digest[6] = min_hash.s1;
  digest[7] = min_hash.s0;

  min_nonces[id] = min_nonce;

  /* barrier(CLK_LOCAL_MEM_FENCE);
   * barrier(CLK_GLOBAL_MEM_FENCE); */
}
