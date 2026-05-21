/*
 * kolhaam-network Server - End-to-end encrypted IRC-style chat server.
 *
 * Build:
 *   Linux x86_64 : gcc -O2 -Wall -Wextra -o khn-server server.c -lpthread
 *   Windows i686 : i686-w64-mingw32-gcc -O2 -o khn-server.exe server.c -lws2_32 -ladvapi32
 *
 * Usage:
 *   ./khn-server <port> <keyphrase>
 *
 * The server is a pure relay. All wire traffic is AES-256-CBC encrypted with
 * a key derived from <keyphrase> via 100k iterations of SHA-256.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <wincrypt.h>
  typedef SOCKET sock_t;
  typedef int slen_t;
  #define CLOSESOCK(s) closesocket(s)
  #define SOCK_INVALID INVALID_SOCKET
  #define SOCK_ERROR SOCKET_ERROR
  typedef HANDLE thread_t;
  typedef CRITICAL_SECTION mutex_t;
  #define MUTEX_INIT(m)   InitializeCriticalSection(&(m))
  #define MUTEX_LOCK(m)   EnterCriticalSection(&(m))
  #define MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
  #define SEND_FLAGS 0
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <pthread.h>
  #include <signal.h>
  #include <errno.h>
  typedef int sock_t;
  typedef socklen_t slen_t;
  #define CLOSESOCK(s) close(s)
  #define SOCK_INVALID (-1)
  #define SOCK_ERROR   (-1)
  typedef pthread_t thread_t;
  typedef pthread_mutex_t mutex_t;
  #define MUTEX_INIT(m)   pthread_mutex_init(&(m), NULL)
  #define MUTEX_LOCK(m)   pthread_mutex_lock(&(m))
  #define MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
  #define SEND_FLAGS MSG_NOSIGNAL
#endif

#define APP_NAME           "kolhaam-network"
#define APP_VERSION        "0.1.1"
#define KDF_TAG            "KolHaAmNet-v1"
#define KDF_TAG_LEN        13

#define MAX_NICK           32
#define MAX_ROOM           32
#define MAX_TEXT           1024
#define MAX_USERS_PER_ROOM 25
#define MAX_ROOMS_PER_USER 10
#define MAX_CLIENTS        200
#define MAX_ROOMS          100

#define AES_BLOCK          16
#define AES_KEY_BYTES      32
#define AES_ROUNDS         14
#define KDF_ITER           100000

#define MAX_FILE_BYTES     (10 * 1024 * 1024)
#define MAX_FILE_HDR       1024
#define MAX_PAYLOAD        (MAX_FILE_BYTES + MAX_FILE_HDR)
#define MAX_PLAINTEXT      (MAX_PAYLOAD + 1)
#define MAX_FRAME          (16 + MAX_PLAINTEXT + 16)

/* Packet type identifiers (first byte of decrypted plaintext). */
#define PKT_HELLO 'H'
#define PKT_MSG   'M'
#define PKT_EMOTE 'O'
#define PKT_DM    'D'
#define PKT_FILE  'F'
#define PKT_WHO   'W'
#define PKT_LIST  'L'
#define PKT_NICK  'N'
#define PKT_JOIN  'J'
#define PKT_PART  'T'
#define PKT_SYS   'X'
#define PKT_ERR   'E'
#define PKT_PING  'P'
#define PKT_QUIT  'Q'

/* ===== SHA-256 ===== */

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct { uint8_t buf[64]; uint32_t H[8]; uint64_t bits; size_t buflen; } sha256_t;

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(sha256_t *c) {
    uint32_t W[64], a, b, ce, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)c->buf[i*4]   << 24) |
               ((uint32_t)c->buf[i*4+1] << 16) |
               ((uint32_t)c->buf[i*4+2] <<  8) |
               ((uint32_t)c->buf[i*4+3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(W[i-15], 7)  ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = rotr32(W[i-2], 17)  ^ rotr32(W[i-2],  19) ^ (W[i-2]  >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    a=c->H[0]; b=c->H[1]; ce=c->H[2]; d=c->H[3];
    e=c->H[4]; f=c->H[5]; g=c->H[6]; h=c->H[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & ce) ^ (b & ce);
        t1 = h + S1 + ch + SHA256_K[i] + W[i];
        t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = ce; ce = b; b = a; a = t1 + t2;
    }
    c->H[0]+=a; c->H[1]+=b; c->H[2]+=ce; c->H[3]+=d;
    c->H[4]+=e; c->H[5]+=f; c->H[6]+=g;  c->H[7]+=h;
}

static void sha256_init(sha256_t *c) {
    c->H[0]=0x6a09e667; c->H[1]=0xbb67ae85; c->H[2]=0x3c6ef372; c->H[3]=0xa54ff53a;
    c->H[4]=0x510e527f; c->H[5]=0x9b05688c; c->H[6]=0x1f83d9ab; c->H[7]=0x5be0cd19;
    c->bits = 0; c->buflen = 0;
}

static void sha256_update(sha256_t *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    c->bits += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - c->buflen;
        if (take > len) take = len;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; len -= take;
        if (c->buflen == 64) { sha256_compress(c); c->buflen = 0; }
    }
}

static void sha256_final(sha256_t *c, uint8_t out[32]) {
    uint64_t bits = c->bits;
    int i;
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        while (c->buflen < 64) c->buf[c->buflen++] = 0;
        sha256_compress(c); c->buflen = 0;
    }
    while (c->buflen < 56) c->buf[c->buflen++] = 0;
    for (i = 7; i >= 0; i--) c->buf[c->buflen++] = (uint8_t)(bits >> (i * 8));
    sha256_compress(c);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->H[i] >> 24);
        out[i*4+1] = (uint8_t)(c->H[i] >> 16);
        out[i*4+2] = (uint8_t)(c->H[i] >>  8);
        out[i*4+3] = (uint8_t)(c->H[i]);
    }
}

/* ===== AES-256-CBC + PKCS#7 ===== */

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t AES_INVSBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t AES_RCON[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

typedef struct { uint8_t rk[(AES_ROUNDS + 1) * 16]; } aes_ctx;

static uint8_t aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
static uint8_t aes_gmul(uint8_t x, uint8_t y) {
    uint8_t r = 0;
    while (y) { if (y & 1) r ^= x; x = aes_xtime(x); y >>= 1; }
    return r;
}

static void aes_key_expansion(aes_ctx *ctx, const uint8_t key[32]) {
    int i;
    uint8_t *rk = ctx->rk;
    memcpy(rk, key, 32);
    for (i = 8; i < 4 * (AES_ROUNDS + 1); i++) {
        uint8_t t[4];
        memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 8 == 0) {
            uint8_t k = t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=k;
            t[0]=AES_SBOX[t[0]]; t[1]=AES_SBOX[t[1]];
            t[2]=AES_SBOX[t[2]]; t[3]=AES_SBOX[t[3]];
            t[0]^=AES_RCON[i / 8];
        } else if (i % 8 == 4) {
            t[0]=AES_SBOX[t[0]]; t[1]=AES_SBOX[t[1]];
            t[2]=AES_SBOX[t[2]]; t[3]=AES_SBOX[t[3]];
        }
        rk[i*4]   = rk[(i-8)*4]   ^ t[0];
        rk[i*4+1] = rk[(i-8)*4+1] ^ t[1];
        rk[i*4+2] = rk[(i-8)*4+2] ^ t[2];
        rk[i*4+3] = rk[(i-8)*4+3] ^ t[3];
    }
}

static void aes_add_round_key(uint8_t s[16], const uint8_t *rk) {
    int i; for (i = 0; i < 16; i++) s[i] ^= rk[i];
}
static void aes_sub_bytes(uint8_t s[16])     { int i; for (i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]]; }
static void aes_inv_sub_bytes(uint8_t s[16]) { int i; for (i = 0; i < 16; i++) s[i] = AES_INVSBOX[s[i]]; }

static void aes_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
static void aes_inv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
}
static void aes_mix_columns(uint8_t s[16]) {
    int i;
    for (i = 0; i < 4; i++) {
        uint8_t a0=s[i*4], a1=s[i*4+1], a2=s[i*4+2], a3=s[i*4+3];
        uint8_t t = a0 ^ a1 ^ a2 ^ a3;
        s[i*4]   ^= t ^ aes_xtime(a0 ^ a1);
        s[i*4+1] ^= t ^ aes_xtime(a1 ^ a2);
        s[i*4+2] ^= t ^ aes_xtime(a2 ^ a3);
        s[i*4+3] ^= t ^ aes_xtime(a3 ^ a0);
    }
}
static void aes_inv_mix_columns(uint8_t s[16]) {
    int i;
    for (i = 0; i < 4; i++) {
        uint8_t a0=s[i*4], a1=s[i*4+1], a2=s[i*4+2], a3=s[i*4+3];
        s[i*4]   = aes_gmul(a0,0x0e) ^ aes_gmul(a1,0x0b) ^ aes_gmul(a2,0x0d) ^ aes_gmul(a3,0x09);
        s[i*4+1] = aes_gmul(a0,0x09) ^ aes_gmul(a1,0x0e) ^ aes_gmul(a2,0x0b) ^ aes_gmul(a3,0x0d);
        s[i*4+2] = aes_gmul(a0,0x0d) ^ aes_gmul(a1,0x09) ^ aes_gmul(a2,0x0e) ^ aes_gmul(a3,0x0b);
        s[i*4+3] = aes_gmul(a0,0x0b) ^ aes_gmul(a1,0x0d) ^ aes_gmul(a2,0x09) ^ aes_gmul(a3,0x0e);
    }
}

static void aes_encrypt_block(const aes_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16]; int r;
    memcpy(s, in, 16);
    aes_add_round_key(s, ctx->rk);
    for (r = 1; r < AES_ROUNDS; r++) {
        aes_sub_bytes(s); aes_shift_rows(s); aes_mix_columns(s);
        aes_add_round_key(s, ctx->rk + r * 16);
    }
    aes_sub_bytes(s); aes_shift_rows(s);
    aes_add_round_key(s, ctx->rk + AES_ROUNDS * 16);
    memcpy(out, s, 16);
}
static void aes_decrypt_block(const aes_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16]; int r;
    memcpy(s, in, 16);
    aes_add_round_key(s, ctx->rk + AES_ROUNDS * 16);
    for (r = AES_ROUNDS - 1; r >= 1; r--) {
        aes_inv_shift_rows(s); aes_inv_sub_bytes(s);
        aes_add_round_key(s, ctx->rk + r * 16);
        aes_inv_mix_columns(s);
    }
    aes_inv_shift_rows(s); aes_inv_sub_bytes(s);
    aes_add_round_key(s, ctx->rk);
    memcpy(out, s, 16);
}

static size_t aes_cbc_encrypt(const aes_ctx *ctx, const uint8_t iv[16],
                              const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t prev[16], last[16];
    size_t i, blocks = inlen / 16, rem = inlen % 16;
    uint8_t pad = (uint8_t)(16 - rem);
    int j;
    memcpy(prev, iv, 16);
    for (i = 0; i < blocks; i++) {
        uint8_t blk[16];
        for (j = 0; j < 16; j++) blk[j] = in[i*16+j] ^ prev[j];
        aes_encrypt_block(ctx, blk, out + i*16);
        memcpy(prev, out + i*16, 16);
    }
    memcpy(last, in + blocks*16, rem);
    for (j = (int)rem; j < 16; j++) last[j] = pad;
    for (j = 0; j < 16; j++) last[j] ^= prev[j];
    aes_encrypt_block(ctx, last, out + blocks*16);
    return (blocks + 1) * 16;
}
static long aes_cbc_decrypt(const aes_ctx *ctx, const uint8_t iv[16],
                            const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t prev[16];
    size_t i, blocks = inlen / 16;
    uint8_t pad;
    if (inlen == 0 || inlen % 16) return -1;
    memcpy(prev, iv, 16);
    for (i = 0; i < blocks; i++) {
        uint8_t blk[16]; int j;
        aes_decrypt_block(ctx, in + i*16, blk);
        for (j = 0; j < 16; j++) out[i*16+j] = blk[j] ^ prev[j];
        memcpy(prev, in + i*16, 16);
    }
    pad = out[inlen - 1];
    if (pad < 1 || pad > 16) return -1;
    for (i = 0; i < pad; i++) if (out[inlen - 1 - i] != pad) return -1;
    return (long)(inlen - pad);
}

/* ===== Secure RNG + KDF ===== */

static int random_bytes(void *buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) return -1;
    if (!CryptGenRandom(hProv, (DWORD)len, (BYTE *)buf)) {
        CryptReleaseContext(hProv, 0); return -1;
    }
    CryptReleaseContext(hProv, 0);
    return 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    if (fread(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
#endif
}

static void derive_key(const char *passphrase, uint8_t key[32]) {
    uint8_t buf[32];
    sha256_t c;
    size_t plen = strlen(passphrase), i;
    sha256_init(&c);
    sha256_update(&c, passphrase, plen);
    sha256_update(&c, KDF_TAG, KDF_TAG_LEN);
    sha256_final(&c, buf);
    for (i = 0; i < KDF_ITER; i++) {
        sha256_init(&c);
        sha256_update(&c, buf, 32);
        sha256_update(&c, passphrase, plen);
        sha256_final(&c, buf);
    }
    memcpy(key, buf, 32);
}

/* ===== Wire I/O ===== */

static int send_all(sock_t s, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        int n = send(s, p, (int)len, SEND_FLAGS);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}
static int recv_all(sock_t s, void *buf, size_t len) {
    char *p = (char *)buf;
    while (len > 0) {
        int n = recv(s, p, (int)len, 0);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int send_packet(sock_t s, const aes_ctx *ctx,
                       uint8_t type, const uint8_t *payload, size_t plen) {
    uint8_t iv[16], hdr[4];
    size_t pt_len = 1 + plen;
    size_t ct_len = ((pt_len / 16) + 1) * 16;
    size_t framelen = 16 + ct_len;
    uint8_t *pt, *ct;
    if (pt_len > MAX_PLAINTEXT) return -1;
    pt = (uint8_t *)malloc(pt_len);
    ct = (uint8_t *)malloc(ct_len);
    if (!pt || !ct) { free(pt); free(ct); return -1; }
    pt[0] = type;
    if (plen) memcpy(pt + 1, payload, plen);
    if (random_bytes(iv, 16) != 0) { free(pt); free(ct); return -1; }
    aes_cbc_encrypt(ctx, iv, pt, pt_len, ct);
    free(pt);
    hdr[0] = (uint8_t)(framelen >> 24);
    hdr[1] = (uint8_t)(framelen >> 16);
    hdr[2] = (uint8_t)(framelen >>  8);
    hdr[3] = (uint8_t)(framelen);
    if (send_all(s, hdr, 4) != 0)     { free(ct); return -1; }
    if (send_all(s, iv,  16) != 0)    { free(ct); return -1; }
    if (send_all(s, ct, ct_len) != 0) { free(ct); return -1; }
    free(ct);
    return 0;
}

static int recv_packet(sock_t s, const aes_ctx *ctx,
                       uint8_t **out_payload, size_t *out_len, uint8_t *out_type) {
    uint8_t hdr[4], iv[16];
    uint32_t framelen;
    size_t ct_len;
    uint8_t *ct = NULL, *pt = NULL;
    long plen;
    if (recv_all(s, hdr, 4) != 0) return -1;
    framelen = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
               ((uint32_t)hdr[2] <<  8) | ((uint32_t)hdr[3]);
    if (framelen < 32 || framelen > MAX_FRAME) return -1;
    if (recv_all(s, iv, 16) != 0) return -1;
    ct_len = framelen - 16;
    ct = (uint8_t *)malloc(ct_len);
    pt = (uint8_t *)malloc(ct_len);
    if (!ct || !pt) goto fail;
    if (recv_all(s, ct, ct_len) != 0) goto fail;
    plen = aes_cbc_decrypt(ctx, iv, ct, ct_len, pt);
    if (plen < 1) goto fail;
    *out_type = pt[0];
    *out_len  = (size_t)(plen - 1);
    if (*out_len) {
        memmove(pt, pt + 1, *out_len);
        *out_payload = pt;
    } else {
        free(pt);
        *out_payload = NULL;
    }
    free(ct);
    return 0;
fail:
    free(ct); free(pt);
    return -1;
}

static void set_keepalive(sock_t s) {
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&yes, sizeof(yes));
#if defined(__linux__)
    {
        int idle = 60, intvl = 15, cnt = 4;
        setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle));
        setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
        setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt));
    }
#endif
}

/* ===== Validation ===== */

static int name_is_valid(const char *s, size_t maxlen) {
    size_t n, i;
    if (!s) return 0;
    n = strlen(s);
    if (n == 0 || n >= maxlen) return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c == 0x7f || c == ':' || c == ',') return 0;
    }
    return 1;
}

/* ===== Server state ===== */

typedef struct {
    int    active;
    sock_t sock;
    char   nick[MAX_NICK];
    char   addr[64];
    int    rooms[MAX_ROOMS_PER_USER];   /* indices into g_rooms[] */
    int    nrooms;
} client_t;

typedef struct {
    int  in_use;
    char name[MAX_ROOM];
    int  members[MAX_USERS_PER_ROOM];   /* indices into g_clients[] */
    int  nmembers;
} room_t;

static aes_ctx  g_aes;
static client_t g_clients[MAX_CLIENTS];
static room_t   g_rooms[MAX_ROOMS];
static mutex_t  g_lock;
static int      g_run = 1;

static void log_line(const char *s) {
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    char ts[32];
    if (lt) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", lt);
    else    snprintf(ts, sizeof(ts), "?");
    fprintf(stderr, "[%s] %s\n", ts, s);
}

static void log_fmt(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_line(buf);
}

/* ===== State helpers (caller must hold g_lock) ===== */

static int find_room_idx_unlocked(const char *name) {
    int i;
    for (i = 0; i < MAX_ROOMS; i++) {
        if (g_rooms[i].in_use && strcmp(g_rooms[i].name, name) == 0) return i;
    }
    return -1;
}

static int find_or_create_room_unlocked(const char *name) {
    int i, idx = find_room_idx_unlocked(name);
    if (idx >= 0) return idx;
    for (i = 0; i < MAX_ROOMS; i++) {
        if (!g_rooms[i].in_use) {
            g_rooms[i].in_use = 1;
            strncpy(g_rooms[i].name, name, MAX_ROOM - 1);
            g_rooms[i].name[MAX_ROOM - 1] = 0;
            g_rooms[i].nmembers = 0;
            return i;
        }
    }
    return -1;
}

static int find_client_by_nick_unlocked(const char *nick) {
    int i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active && strcmp(g_clients[i].nick, nick) == 0) return i;
    }
    return -1;
}

static int nick_in_use_unlocked(const char *nick) {
    return find_client_by_nick_unlocked(nick) >= 0;
}

static int client_in_room_unlocked(int cidx, int ridx) {
    int i;
    for (i = 0; i < g_clients[cidx].nrooms; i++) {
        if (g_clients[cidx].rooms[i] == ridx) return 1;
    }
    return 0;
}

/* Returns 0 ok, -1 full, -2 already in. */
static int add_client_to_room_unlocked(int cidx, int ridx) {
    int i;
    if (g_rooms[ridx].nmembers >= MAX_USERS_PER_ROOM) return -1;
    if (g_clients[cidx].nrooms  >= MAX_ROOMS_PER_USER) return -1;
    for (i = 0; i < g_rooms[ridx].nmembers; i++) {
        if (g_rooms[ridx].members[i] == cidx) return -2;
    }
    g_rooms[ridx].members[g_rooms[ridx].nmembers++] = cidx;
    g_clients[cidx].rooms[g_clients[cidx].nrooms++] = ridx;
    return 0;
}

static void remove_client_from_room_unlocked(int cidx, int ridx) {
    int i;
    for (i = 0; i < g_rooms[ridx].nmembers; i++) {
        if (g_rooms[ridx].members[i] == cidx) {
            g_rooms[ridx].members[i] = g_rooms[ridx].members[--g_rooms[ridx].nmembers];
            break;
        }
    }
    for (i = 0; i < g_clients[cidx].nrooms; i++) {
        if (g_clients[cidx].rooms[i] == ridx) {
            g_clients[cidx].rooms[i] = g_clients[cidx].rooms[--g_clients[cidx].nrooms];
            break;
        }
    }
    if (g_rooms[ridx].nmembers == 0) {
        g_rooms[ridx].in_use = 0;
        g_rooms[ridx].name[0] = 0;
    }
}

/* ===== Random nick / room generation ===== */

static const char *g_adj_words[] = {
    "anon","brisk","calm","dark","quiet","wild","still","quick","faint","hidden",
    "lone","gentle","silent","misty","stormy","glowing","velvet","amber","scarlet","azure"
};
static const char *g_noun_words[] = {
    "fox","owl","wolf","raven","river","stone","ember","cloud","pine","echo",
    "drift","moon","sun","mist","shade","blade","spark","leaf","wave","comet"
};

/* Caller must hold g_lock so duplicate-check is meaningful. */
static void random_nick_unlocked(char out[MAX_NICK]) {
    uint8_t r[4];
    int retries = 0;
    do {
        if (random_bytes(r, 4) != 0) { memset(r, 0, 4); }
        snprintf(out, MAX_NICK, "%s_%s%u",
                 g_adj_words[r[0] % (sizeof(g_adj_words)/sizeof(*g_adj_words))],
                 g_noun_words[r[1] % (sizeof(g_noun_words)/sizeof(*g_noun_words))],
                 (unsigned)(((uint16_t)r[2] << 8 | r[3]) % 1000));
        retries++;
    } while (nick_in_use_unlocked(out) && retries < 32);
}

/* Caller must hold g_lock. */
static void random_room_unlocked(char out[MAX_ROOM]) {
    int i, candidates[MAX_ROOMS], n = 0;
    uint8_t r[2];
    /* Skip secret rooms (names beginning with '+') when picking a random one. */
    for (i = 0; i < MAX_ROOMS; i++) {
        if (g_rooms[i].in_use && g_rooms[i].nmembers < MAX_USERS_PER_ROOM
            && g_rooms[i].name[0] != '+') {
            candidates[n++] = i;
        }
    }
    if (n > 0) {
        random_bytes(r, 2);
        strncpy(out, g_rooms[candidates[r[0] % n]].name, MAX_ROOM - 1);
        out[MAX_ROOM - 1] = 0;
        return;
    }
    random_bytes(r, 2);
    snprintf(out, MAX_ROOM, "lobby_%u",
             (unsigned)((((uint16_t)r[0] << 8) | r[1]) % 1000));
}

/* ===== Senders / payload builders ===== */

static void send_err(sock_t s, const char *text) {
    send_packet(s, &g_aes, PKT_ERR, (const uint8_t *)text, strlen(text));
}

static int build_sys_payload(const char *room, const char *text,
                             uint8_t **out, size_t *outlen) {
    size_t rl = strlen(room), tl = strlen(text);
    uint8_t *b;
    if (rl == 0 || rl > 255 || tl > MAX_TEXT) return -1;
    *outlen = 1 + rl + tl;
    b = (uint8_t *)malloc(*outlen);
    if (!b) return -1;
    b[0] = (uint8_t)rl;
    memcpy(b + 1, room, rl);
    memcpy(b + 1 + rl, text, tl);
    *out = b;
    return 0;
}

/* Server->client room MSG/EMOTE payload:
 *   [u8 rlen][room][u8 slen][sender][text] */
static int build_room_msg(const char *room, const char *sender,
                          const char *text, size_t tlen,
                          uint8_t **out, size_t *outlen) {
    size_t rl = strlen(room), sl = strlen(sender);
    uint8_t *b;
    size_t o = 0;
    if (rl == 0 || rl > 255 || sl == 0 || sl > 255 || tlen > MAX_TEXT) return -1;
    *outlen = 1 + rl + 1 + sl + tlen;
    b = (uint8_t *)malloc(*outlen);
    if (!b) return -1;
    b[o++] = (uint8_t)rl; memcpy(b + o, room,   rl); o += rl;
    b[o++] = (uint8_t)sl; memcpy(b + o, sender, sl); o += sl;
    memcpy(b + o, text, tlen);
    *out = b;
    return 0;
}

/* J/T notice: [u8 rlen][room][u8 nlen][nick] */
static int build_join_part(const char *room, const char *nick,
                           uint8_t **out, size_t *outlen) {
    size_t rl = strlen(room), nl = strlen(nick);
    uint8_t *b;
    if (rl == 0 || rl > 255 || nl == 0 || nl > 255) return -1;
    *outlen = 1 + rl + 1 + nl;
    b = (uint8_t *)malloc(*outlen);
    if (!b) return -1;
    b[0] = (uint8_t)rl;        memcpy(b + 1, room, rl);
    b[1 + rl] = (uint8_t)nl;   memcpy(b + 2 + rl, nick, nl);
    *out = b;
    return 0;
}

/* Hello-ack: [u8 nlen][nick][u8 rlen][room] */
static int build_hello_ack(const char *nick, const char *room,
                           uint8_t **out, size_t *outlen) {
    size_t nl = strlen(nick), rl = strlen(room);
    uint8_t *b;
    *outlen = 1 + nl + 1 + rl;
    b = (uint8_t *)malloc(*outlen);
    if (!b) return -1;
    b[0] = (uint8_t)nl;       memcpy(b + 1, nick, nl);
    b[1 + nl] = (uint8_t)rl;  memcpy(b + 2 + nl, room, rl);
    *out = b;
    return 0;
}

/* Broadcast a packet to every member of a room except exclude_cidx (-1 = none).
 * Caller must NOT hold g_lock. Snapshots socket list first, then sends. */
static void broadcast_room(int ridx, uint8_t type,
                           const uint8_t *payload, size_t plen,
                           int exclude_cidx) {
    sock_t targets[MAX_USERS_PER_ROOM];
    int    n = 0, i;
    MUTEX_LOCK(g_lock);
    if (ridx < 0 || ridx >= MAX_ROOMS || !g_rooms[ridx].in_use) {
        MUTEX_UNLOCK(g_lock); return;
    }
    for (i = 0; i < g_rooms[ridx].nmembers; i++) {
        int c = g_rooms[ridx].members[i];
        if (c == exclude_cidx) continue;
        if (g_clients[c].active) {
            targets[n++] = g_clients[c].sock;
        }
    }
    MUTEX_UNLOCK(g_lock);
    for (i = 0; i < n; i++) {
        send_packet(targets[i], &g_aes, type, payload, plen);
    }
}

static int unicast_to_cidx(int cidx, uint8_t type, const uint8_t *p, size_t plen) {
    sock_t s = SOCK_INVALID;
    MUTEX_LOCK(g_lock);
    if (cidx >= 0 && cidx < MAX_CLIENTS && g_clients[cidx].active) s = g_clients[cidx].sock;
    MUTEX_UNLOCK(g_lock);
    if (s == SOCK_INVALID) return -1;
    return send_packet(s, &g_aes, type, p, plen);
}

/* ===== Payload helpers ===== */

static int read_u8_string(const uint8_t *p, size_t plen, size_t *off,
                          char *out, size_t outsz) {
    uint8_t n;
    if (*off + 1 > plen) return -1;
    n = p[(*off)++];
    if (*off + n > plen) return -1;
    if ((size_t)n + 1 > outsz) return -1;
    memcpy(out, p + *off, n);
    out[n] = 0;
    *off += n;
    return 0;
}

/* ===== Handlers ===== */

static int handle_hello(sock_t sock, const char *addr, int *out_cidx) {
    uint8_t  *payload = NULL;
    size_t    plen = 0;
    uint8_t   type = 0;
    char      req_nick[MAX_NICK] = {0};
    char      req_room[MAX_ROOM] = {0};
    char      nick[MAX_NICK];
    char      room[MAX_ROOM];
    size_t    off = 0;
    int       i, slot = -1, ridx = -1, rc;
    uint8_t  *ack = NULL;
    size_t    acklen = 0;

    if (recv_packet(sock, &g_aes, &payload, &plen, &type) != 0) return -1;
    if (type != PKT_HELLO) { free(payload); send_err(sock, "expected HELLO"); return -1; }
    if (read_u8_string(payload, plen, &off, req_nick, sizeof(req_nick)) != 0) {
        free(payload); send_err(sock, "bad hello"); return -1;
    }
    if (read_u8_string(payload, plen, &off, req_room, sizeof(req_room)) != 0) {
        free(payload); send_err(sock, "bad hello"); return -1;
    }
    free(payload);

    MUTEX_LOCK(g_lock);

    if (req_nick[0] == 0) {
        random_nick_unlocked(nick);
    } else {
        if (!name_is_valid(req_nick, MAX_NICK)) {
            MUTEX_UNLOCK(g_lock);
            send_err(sock, "invalid nickname");
            return -1;
        }
        if (nick_in_use_unlocked(req_nick)) {
            MUTEX_UNLOCK(g_lock);
            send_err(sock, "nickname in use");
            return -1;
        }
        strncpy(nick, req_nick, MAX_NICK - 1);
        nick[MAX_NICK - 1] = 0;
    }

    if (req_room[0] == 0) {
        random_room_unlocked(room);
    } else {
        if (!name_is_valid(req_room, MAX_ROOM)) {
            MUTEX_UNLOCK(g_lock);
            send_err(sock, "invalid room name");
            return -1;
        }
        strncpy(room, req_room, MAX_ROOM - 1);
        room[MAX_ROOM - 1] = 0;
    }

    for (i = 0; i < MAX_CLIENTS; i++) {
        if (!g_clients[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        MUTEX_UNLOCK(g_lock);
        send_err(sock, "server full");
        return -1;
    }
    g_clients[slot].active = 1;
    g_clients[slot].sock   = sock;
    g_clients[slot].nrooms = 0;
    snprintf(g_clients[slot].nick, sizeof(g_clients[slot].nick), "%s", nick);
    snprintf(g_clients[slot].addr, sizeof(g_clients[slot].addr), "%s", addr);

    ridx = find_or_create_room_unlocked(room);
    if (ridx < 0) {
        g_clients[slot].active = 0;
        MUTEX_UNLOCK(g_lock);
        send_err(sock, "no free room slots");
        return -1;
    }
    rc = add_client_to_room_unlocked(slot, ridx);
    if (rc < 0) {
        if (g_rooms[ridx].nmembers == 0) {
            g_rooms[ridx].in_use = 0;
            g_rooms[ridx].name[0] = 0;
        }
        g_clients[slot].active = 0;
        MUTEX_UNLOCK(g_lock);
        send_err(sock, "room full");
        return -1;
    }

    MUTEX_UNLOCK(g_lock);

    if (build_hello_ack(nick, room, &ack, &acklen) != 0) return -1;
    if (send_packet(sock, &g_aes, PKT_HELLO, ack, acklen) != 0) { free(ack); return -1; }
    free(ack);

    {
        uint8_t *jp; size_t jpl;
        if (build_join_part(room, nick, &jp, &jpl) == 0) {
            broadcast_room(ridx, PKT_JOIN, jp, jpl, slot);
            free(jp);
        }
    }

    log_fmt("connect: %s as \"%s\" -> room \"%s\"", addr, nick, room);
    *out_cidx = slot;
    return 0;
}

static void handle_msg_or_emote(int cidx, uint8_t type,
                                const uint8_t *payload, size_t plen) {
    char room[MAX_ROOM], sender[MAX_NICK];
    size_t off = 0;
    int ridx;
    const uint8_t *text;
    size_t tlen;
    uint8_t *out = NULL;
    size_t outlen = 0;

    if (read_u8_string(payload, plen, &off, room, sizeof(room)) != 0) return;
    if (plen < off) return;
    text = payload + off;
    tlen = plen - off;
    if (tlen == 0 || tlen > MAX_TEXT) return;

    MUTEX_LOCK(g_lock);
    ridx = find_room_idx_unlocked(room);
    if (ridx < 0 || !client_in_room_unlocked(cidx, ridx)) {
        sock_t s = g_clients[cidx].sock;
        MUTEX_UNLOCK(g_lock);
        send_err(s, "you are not in that room");
        return;
    }
    strncpy(sender, g_clients[cidx].nick, MAX_NICK - 1);
    sender[MAX_NICK - 1] = 0;
    MUTEX_UNLOCK(g_lock);

    if (build_room_msg(room, sender, (const char *)text, tlen, &out, &outlen) != 0) return;
    broadcast_room(ridx, type, out, outlen, -1);
    free(out);
}

static void handle_dm(int cidx, const uint8_t *payload, size_t plen) {
    char recip[MAX_NICK], sender[MAX_NICK];
    size_t off = 0;
    const uint8_t *text;
    size_t tlen;
    int target;
    uint8_t *out;
    size_t outlen, sl;

    if (read_u8_string(payload, plen, &off, recip, sizeof(recip)) != 0) return;
    if (plen <= off) return;
    text = payload + off;
    tlen = plen - off;
    if (tlen == 0 || tlen > MAX_TEXT) return;

    MUTEX_LOCK(g_lock);
    strncpy(sender, g_clients[cidx].nick, MAX_NICK - 1);
    sender[MAX_NICK - 1] = 0;
    target = find_client_by_nick_unlocked(recip);
    MUTEX_UNLOCK(g_lock);

    if (target < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "no such user \"%s\"", recip);
        send_err(g_clients[cidx].sock, buf);
        return;
    }
    sl = strlen(sender);
    outlen = 1 + sl + tlen;
    out = (uint8_t *)malloc(outlen);
    if (!out) return;
    out[0] = (uint8_t)sl;
    memcpy(out + 1, sender, sl);
    memcpy(out + 1 + sl, text, tlen);
    unicast_to_cidx(target, PKT_DM, out, outlen);
    free(out);
}

static void handle_file(int cidx, const uint8_t *payload, size_t plen) {
    /* Client wire: [u8 rlen][recip][u8 fnlen][fname][u32 size][bytes]
     * Server fwd : [u8 slen][sender][u8 fnlen][fname][u32 size][bytes] */
    char recip[MAX_NICK], sender[MAX_NICK];
    size_t off = 0, o;
    uint8_t fnl;
    char fname[256];
    uint32_t fsz;
    int target;
    uint8_t *out;
    size_t outlen, sl;

    if (read_u8_string(payload, plen, &off, recip, sizeof(recip)) != 0) return;
    if (off + 1 > plen) return;
    fnl = payload[off++];
    if (fnl == 0) return;                         /* fnl < 256 < sizeof(fname) */
    if (off + (size_t)fnl + 4 > plen) return;
    memcpy(fname, payload + off, fnl); fname[fnl] = 0;
    off += fnl;
    fsz = ((uint32_t)payload[off]   << 24) | ((uint32_t)payload[off+1] << 16) |
          ((uint32_t)payload[off+2] <<  8) | ((uint32_t)payload[off+3]);
    off += 4;
    if (fsz > MAX_FILE_BYTES) return;
    if (off + fsz != plen) return;

    MUTEX_LOCK(g_lock);
    strncpy(sender, g_clients[cidx].nick, MAX_NICK - 1);
    sender[MAX_NICK - 1] = 0;
    target = find_client_by_nick_unlocked(recip);
    MUTEX_UNLOCK(g_lock);

    if (target < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "no such user \"%s\"; file not delivered", recip);
        send_err(g_clients[cidx].sock, buf);
        return;
    }
    sl = strlen(sender);
    outlen = 1 + sl + 1 + (size_t)fnl + 4 + (size_t)fsz;
    out = (uint8_t *)malloc(outlen);
    if (!out) return;
    o = 0;
    out[o++] = (uint8_t)sl; memcpy(out + o, sender, sl); o += sl;
    out[o++] = fnl;         memcpy(out + o, fname,  fnl); o += fnl;
    out[o++] = (uint8_t)(fsz >> 24);
    out[o++] = (uint8_t)(fsz >> 16);
    out[o++] = (uint8_t)(fsz >>  8);
    out[o++] = (uint8_t)(fsz);
    memcpy(out + o, payload + (plen - fsz), fsz);
    unicast_to_cidx(target, PKT_FILE, out, outlen);
    free(out);
    log_fmt("file relay: %s -> %s (%s, %u bytes)", sender, recip, fname, (unsigned)fsz);
}

static void handle_who(int cidx, const uint8_t *payload, size_t plen) {
    char room[MAX_ROOM];
    size_t off = 0, o = 0, count_off;
    int ridx, i;
    uint8_t buf[2048];
    uint8_t count = 0;
    sock_t s;

    if (read_u8_string(payload, plen, &off, room, sizeof(room)) != 0) return;

    MUTEX_LOCK(g_lock);
    s = g_clients[cidx].sock;
    ridx = find_room_idx_unlocked(room);
    if (ridx < 0) {
        MUTEX_UNLOCK(g_lock);
        send_err(s, "no such room");
        return;
    }
    {
        size_t rl = strlen(room);
        buf[o++] = (uint8_t)rl;
        memcpy(buf + o, room, rl); o += rl;
        count_off = o++;
        for (i = 0; i < g_rooms[ridx].nmembers && o + 1 + MAX_NICK < sizeof(buf); i++) {
            int c = g_rooms[ridx].members[i];
            size_t nl = strlen(g_clients[c].nick);
            buf[o++] = (uint8_t)nl;
            memcpy(buf + o, g_clients[c].nick, nl); o += nl;
            count++;
        }
        buf[count_off] = count;
    }
    MUTEX_UNLOCK(g_lock);
    send_packet(s, &g_aes, PKT_WHO, buf, o);
}

static void handle_list(int cidx) {
    int i;
    uint8_t buf[4096];
    size_t o = 0, count_off;
    uint8_t count = 0;
    sock_t s;

    MUTEX_LOCK(g_lock);
    s = g_clients[cidx].sock;
    count_off = o++;
    for (i = 0; i < MAX_ROOMS && o + 1 + MAX_ROOM + 2 < sizeof(buf); i++) {
        if (!g_rooms[i].in_use) continue;
        /* Secret rooms ('+'-prefixed) are hidden from listings. */
        if (g_rooms[i].name[0] == '+') continue;
        size_t rl = strlen(g_rooms[i].name);
        buf[o++] = (uint8_t)rl;
        memcpy(buf + o, g_rooms[i].name, rl); o += rl;
        {
            uint16_t nm = (uint16_t)g_rooms[i].nmembers;
            buf[o++] = (uint8_t)(nm >> 8);
            buf[o++] = (uint8_t)(nm & 0xff);
        }
        count++;
    }
    buf[count_off] = count;
    MUTEX_UNLOCK(g_lock);
    send_packet(s, &g_aes, PKT_LIST, buf, o);
}

static void handle_nick(int cidx, const uint8_t *payload, size_t plen) {
    char newnick[MAX_NICK], oldnick[MAX_NICK];
    size_t off = 0;
    int i, nrooms;
    int rooms_snap[MAX_ROOMS_PER_USER];
    sock_t s;

    if (read_u8_string(payload, plen, &off, newnick, sizeof(newnick)) != 0) return;
    if (!name_is_valid(newnick, MAX_NICK)) {
        send_err(g_clients[cidx].sock, "invalid nickname");
        return;
    }
    MUTEX_LOCK(g_lock);
    s = g_clients[cidx].sock;
    if (strcmp(newnick, g_clients[cidx].nick) == 0) {
        MUTEX_UNLOCK(g_lock); return;
    }
    if (nick_in_use_unlocked(newnick)) {
        MUTEX_UNLOCK(g_lock);
        send_err(s, "nickname in use");
        return;
    }
    snprintf(oldnick, sizeof(oldnick), "%s", g_clients[cidx].nick);
    snprintf(g_clients[cidx].nick, sizeof(g_clients[cidx].nick), "%s", newnick);

    nrooms = g_clients[cidx].nrooms;
    for (i = 0; i < nrooms; i++) rooms_snap[i] = g_clients[cidx].rooms[i];
    MUTEX_UNLOCK(g_lock);

    send_packet(s, &g_aes, PKT_NICK, (const uint8_t *)newnick, strlen(newnick));

    for (i = 0; i < nrooms; i++) {
        char note[160], rname[MAX_ROOM];
        uint8_t *p; size_t pl;
        MUTEX_LOCK(g_lock);
        if (rooms_snap[i] < 0 || !g_rooms[rooms_snap[i]].in_use) {
            MUTEX_UNLOCK(g_lock); continue;
        }
        strncpy(rname, g_rooms[rooms_snap[i]].name, MAX_ROOM - 1);
        rname[MAX_ROOM - 1] = 0;
        MUTEX_UNLOCK(g_lock);
        snprintf(note, sizeof(note), "* %s is now known as %s *", oldnick, newnick);
        if (build_sys_payload(rname, note, &p, &pl) == 0) {
            broadcast_room(rooms_snap[i], PKT_SYS, p, pl, -1);
            free(p);
        }
    }
    log_fmt("rename: %s -> %s", oldnick, newnick);
}

static void handle_join(int cidx, const uint8_t *payload, size_t plen) {
    char room[MAX_ROOM], nick[MAX_NICK];
    size_t off = 0;
    int ridx, rc;
    sock_t s;
    uint8_t *jp; size_t jpl;

    if (read_u8_string(payload, plen, &off, room, sizeof(room)) != 0) return;
    if (!name_is_valid(room, MAX_ROOM)) {
        send_err(g_clients[cidx].sock, "invalid room name");
        return;
    }
    MUTEX_LOCK(g_lock);
    s = g_clients[cidx].sock;
    strncpy(nick, g_clients[cidx].nick, MAX_NICK - 1);
    nick[MAX_NICK - 1] = 0;

    if (g_clients[cidx].nrooms >= MAX_ROOMS_PER_USER) {
        MUTEX_UNLOCK(g_lock);
        send_err(s, "you are already in the maximum number of rooms");
        return;
    }
    ridx = find_or_create_room_unlocked(room);
    if (ridx < 0) {
        MUTEX_UNLOCK(g_lock);
        send_err(s, "no free room slots");
        return;
    }
    rc = add_client_to_room_unlocked(cidx, ridx);
    if (rc == -2) {
        MUTEX_UNLOCK(g_lock);
        send_err(s, "already in that room");
        return;
    }
    if (rc < 0) {
        if (g_rooms[ridx].nmembers == 0) {
            g_rooms[ridx].in_use = 0;
            g_rooms[ridx].name[0] = 0;
        }
        MUTEX_UNLOCK(g_lock);
        send_err(s, "room full");
        return;
    }
    MUTEX_UNLOCK(g_lock);

    if (build_join_part(room, nick, &jp, &jpl) == 0) {
        broadcast_room(ridx, PKT_JOIN, jp, jpl, -1);
        free(jp);
    }
    log_fmt("join: %s -> %s", nick, room);
}

static void handle_part(int cidx, const uint8_t *payload, size_t plen) {
    char room[MAX_ROOM], nick[MAX_NICK];
    size_t off = 0;
    int ridx;
    sock_t s;
    uint8_t *jp; size_t jpl;

    if (read_u8_string(payload, plen, &off, room, sizeof(room)) != 0) return;
    MUTEX_LOCK(g_lock);
    s = g_clients[cidx].sock;
    strncpy(nick, g_clients[cidx].nick, MAX_NICK - 1);
    nick[MAX_NICK - 1] = 0;
    ridx = find_room_idx_unlocked(room);
    if (ridx < 0 || !client_in_room_unlocked(cidx, ridx)) {
        MUTEX_UNLOCK(g_lock);
        send_err(s, "you are not in that room");
        return;
    }
    MUTEX_UNLOCK(g_lock);

    /* Announce first so the leaver also gets the notice. */
    if (build_join_part(room, nick, &jp, &jpl) == 0) {
        broadcast_room(ridx, PKT_PART, jp, jpl, -1);
        free(jp);
    }
    MUTEX_LOCK(g_lock);
    remove_client_from_room_unlocked(cidx, ridx);
    MUTEX_UNLOCK(g_lock);
    log_fmt("part: %s <- %s", nick, room);
}

/* ===== Client cleanup / thread ===== */

static void client_cleanup(int cidx) {
    int rooms_snap[MAX_ROOMS_PER_USER], nrooms, i;
    char nick[MAX_NICK];
    sock_t sock;

    if (cidx < 0) return;
    MUTEX_LOCK(g_lock);
    if (!g_clients[cidx].active) { MUTEX_UNLOCK(g_lock); return; }
    nrooms = g_clients[cidx].nrooms;
    for (i = 0; i < nrooms; i++) rooms_snap[i] = g_clients[cidx].rooms[i];
    strncpy(nick, g_clients[cidx].nick, MAX_NICK - 1);
    nick[MAX_NICK - 1] = 0;
    sock = g_clients[cidx].sock;
    MUTEX_UNLOCK(g_lock);

    for (i = 0; i < nrooms; i++) {
        char rname[MAX_ROOM];
        uint8_t *jp; size_t jpl;
        MUTEX_LOCK(g_lock);
        if (rooms_snap[i] < 0 || !g_rooms[rooms_snap[i]].in_use) {
            MUTEX_UNLOCK(g_lock); continue;
        }
        strncpy(rname, g_rooms[rooms_snap[i]].name, MAX_ROOM - 1);
        rname[MAX_ROOM - 1] = 0;
        MUTEX_UNLOCK(g_lock);
        if (build_join_part(rname, nick, &jp, &jpl) == 0) {
            broadcast_room(rooms_snap[i], PKT_PART, jp, jpl, cidx);
            free(jp);
        }
    }
    MUTEX_LOCK(g_lock);
    for (i = 0; i < nrooms; i++) {
        remove_client_from_room_unlocked(cidx, rooms_snap[i]);
    }
    g_clients[cidx].active = 0;
    g_clients[cidx].nick[0] = 0;
    g_clients[cidx].nrooms = 0;
    MUTEX_UNLOCK(g_lock);
    CLOSESOCK(sock);
    log_fmt("disconnect: %s", nick);
}

typedef struct {
    sock_t sock;
    char   addr[64];
} accept_arg_t;

#ifdef _WIN32
static DWORD WINAPI client_thread(LPVOID arg)
#else
static void *client_thread(void *arg)
#endif
{
    accept_arg_t *a = (accept_arg_t *)arg;
    sock_t sock = a->sock;
    char   addr[64];
    int    cidx = -1;
    strncpy(addr, a->addr, sizeof(addr) - 1); addr[sizeof(addr) - 1] = 0;
    free(a);

    set_keepalive(sock);

    if (handle_hello(sock, addr, &cidx) != 0) {
        CLOSESOCK(sock);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    for (;;) {
        uint8_t *payload = NULL;
        size_t   plen = 0;
        uint8_t  type = 0;
        if (recv_packet(sock, &g_aes, &payload, &plen, &type) != 0) break;
        switch (type) {
            case PKT_MSG:
            case PKT_EMOTE: handle_msg_or_emote(cidx, type, payload, plen); break;
            case PKT_DM:    handle_dm(cidx, payload, plen); break;
            case PKT_FILE:  handle_file(cidx, payload, plen); break;
            case PKT_WHO:   handle_who(cidx, payload, plen); break;
            case PKT_LIST:  handle_list(cidx); break;
            case PKT_NICK:  handle_nick(cidx, payload, plen); break;
            case PKT_JOIN:  handle_join(cidx, payload, plen); break;
            case PKT_PART:  handle_part(cidx, payload, plen); break;
            case PKT_QUIT:  free(payload); goto done;
            case PKT_PING:  /* ignore */ break;
            default:        /* ignore unknown */ break;
        }
        free(payload);
    }
done:
    client_cleanup(cidx);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ===== main / accept loop ===== */

#ifndef _WIN32
static void handle_sigint(int sig) { (void)sig; g_run = 0; }
#endif

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <port> <keyphrase>\n", prog);
}

int main(int argc, char **argv) {
    int port;
    const char *passphrase;
    uint8_t key[32];
    sock_t lsn;
    struct sockaddr_in sa;
    int yes = 1;

    if (argc != 3) { usage(argv[0]); return 2; }
    port = atoi(argv[1]);
    if (port <= 0 || port > 65535) { usage(argv[0]); return 2; }
    passphrase = argv[2];
    if (strlen(passphrase) == 0) {
        fprintf(stderr, "keyphrase cannot be empty\n");
        return 2;
    }

#ifdef _WIN32
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "WSAStartup failed\n");
            return 1;
        }
    }
#else
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  handle_sigint);
    signal(SIGTERM, handle_sigint);
#endif

    MUTEX_INIT(g_lock);
    derive_key(passphrase, key);
    aes_key_expansion(&g_aes, key);
    memset(key, 0, sizeof(key));
    memset(g_clients, 0, sizeof(g_clients));
    memset(g_rooms,   0, sizeof(g_rooms));

    lsn = socket(AF_INET, SOCK_STREAM, 0);
    if (lsn == SOCK_INVALID) { perror("socket"); return 1; }
    setsockopt(lsn, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port        = htons((uint16_t)port);
    if (bind(lsn, (struct sockaddr *)&sa, sizeof(sa)) == SOCK_ERROR) {
        perror("bind"); CLOSESOCK(lsn); return 1;
    }
    if (listen(lsn, 32) == SOCK_ERROR) {
        perror("listen"); CLOSESOCK(lsn); return 1;
    }

    log_fmt("%s %s server listening on port %d", APP_NAME, APP_VERSION, port);

    while (g_run) {
        struct sockaddr_in ca;
        slen_t cal = sizeof(ca);
        sock_t cs = accept(lsn, (struct sockaddr *)&ca, &cal);
        if (cs == SOCK_INVALID) {
#ifndef _WIN32
            if (errno == EINTR) continue;
#endif
            if (g_run) perror("accept");
            break;
        }
        {
            accept_arg_t *aa = (accept_arg_t *)malloc(sizeof(*aa));
            if (!aa) { CLOSESOCK(cs); continue; }
            aa->sock = cs;
            {
                char ip[INET_ADDRSTRLEN] = "?";
                inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
                snprintf(aa->addr, sizeof(aa->addr), "%s:%u", ip, ntohs(ca.sin_port));
            }
#ifdef _WIN32
            {
                HANDLE th = CreateThread(NULL, 0, client_thread, aa, 0, NULL);
                if (th) CloseHandle(th); else { CLOSESOCK(aa->sock); free(aa); }
            }
#else
            {
                pthread_t th;
                if (pthread_create(&th, NULL, client_thread, aa) == 0) {
                    pthread_detach(th);
                } else {
                    CLOSESOCK(aa->sock); free(aa);
                }
            }
#endif
        }
    }

    CLOSESOCK(lsn);
    log_fmt("%s server shutting down", APP_NAME);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
