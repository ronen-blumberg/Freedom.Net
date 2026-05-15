/*
 * Freedom Net Client - terminal IM client for the Freedom Net server.
 *
 * Build:
 *   Linux x86_64 : gcc -O2 -Wall -Wextra -o fdn-client client.c -lpthread
 *   Windows i686 : i686-w64-mingw32-gcc -O2 -o fdn-client.exe client.c -lws2_32 -ladvapi32
 *
 * Usage (all but <server> <port> <keyphrase> are optional):
 *   ./fdn-client <server> <port> <keyphrase> [<nickname>] [<room>]
 *
 * Pass an empty string for nickname or room ("") to let the server pick one
 * randomly.
 *
 * Once connected, commands at the prompt:
 *   /connect <host> <port> <keyphrase> [<nick>] [<room>]  - reconnect (only
 *                                                          before connecting,
 *                                                          or after /quit)
 *   /join <room>          - join a room (or switch to it if already in)
 *   /part [<room>]        - leave a room (default: current)
 *   /msg  <nick> <text>   - private message
 *   /send <nick> <path>   - send a file (<= 10 MB) to one user
 *   /me   <action>        - emote in current room
 *   /nick <newnick>       - change your nickname
 *   /who  [<room>]        - list users in a room (default: current)
 *   /list                 - list all rooms on the server
 *   /quit                 - disconnect
 *   /help                 - show this list
 *   //text                - send a literal chat line that starts with '/'
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
  #include <io.h>
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
  #define PATH_SEP '\\'
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
  #define PATH_SEP '/'
#endif

#define APP_NAME           "Freedom Net"
#define APP_VERSION        "0.1.0"
#define KDF_TAG            "FreedomNet-v1"
#define KDF_TAG_LEN        13

#define MAX_NICK           32
#define MAX_ROOM           32
#define MAX_TEXT           1024
#define MAX_ROOMS_PER_USER 10

#define AES_BLOCK          16
#define AES_KEY_BYTES      32
#define AES_ROUNDS         14
#define KDF_ITER           100000

#define MAX_FILE_BYTES     (10 * 1024 * 1024)
#define MAX_FILE_HDR       1024
#define MAX_PAYLOAD        (MAX_FILE_BYTES + MAX_FILE_HDR)
#define MAX_PLAINTEXT      (MAX_PAYLOAD + 1)
#define MAX_FRAME          (16 + MAX_PLAINTEXT + 16)

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

/* ===== AES-256-CBC ===== */

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

static uint8_t aes_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }
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

static void aes_add_round_key(uint8_t s[16], const uint8_t *rk) { int i; for (i=0;i<16;i++) s[i] ^= rk[i]; }
static void aes_sub_bytes(uint8_t s[16])     { int i; for (i=0;i<16;i++) s[i] = AES_SBOX[s[i]]; }
static void aes_inv_sub_bytes(uint8_t s[16]) { int i; for (i=0;i<16;i++) s[i] = AES_INVSBOX[s[i]]; }
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

/* ===== Terminal + log ===== */

typedef enum { LINE_CHAT, LINE_SYSTEM, LINE_FILE, LINE_DM, LINE_EMOTE } line_kind;

static int     g_use_colors = 0;
static mutex_t g_print_lock;
static FILE   *g_log = NULL;
static char    g_nick[MAX_NICK];

static void term_init(void) {
    MUTEX_INIT(g_print_lock);
#ifdef _WIN32
    {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD  type = (h != INVALID_HANDLE_VALUE) ? GetFileType(h) : FILE_TYPE_UNKNOWN;
        if (type == FILE_TYPE_CHAR) {
            DWORD mode = 0;
            if (GetConsoleMode(h, &mode)
                && SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */)) {
                g_use_colors = 1;
            }
        }
    }
#else
    if (isatty(STDOUT_FILENO)) g_use_colors = 1;
#endif
}

static void term_putline(const char *text, line_kind kind) {
    char ts[16], ts_log[32];
    time_t now;
    struct tm lt;
    const char *cR = g_use_colors ? "\x1b[0m"    : "";
    const char *cT = g_use_colors ? "\x1b[90m"   : "";  /* timestamp gray */
    const char *cS = g_use_colors ? "\x1b[1;36m" : "";  /* self bold cyan */
    const char *cO = g_use_colors ? "\x1b[1;32m" : "";  /* other bold green */
    const char *cY = g_use_colors ? "\x1b[33m"   : "";  /* system yellow */
    const char *cM = g_use_colors ? "\x1b[1;35m" : "";  /* file bold magenta */
    const char *cB = g_use_colors ? "\x1b[1;34m" : "";  /* DM bold blue */
    const char *cE = g_use_colors ? "\x1b[35m"   : "";  /* emote magenta */
    const char *colon;

    MUTEX_LOCK(g_print_lock);
    now = time(NULL);
    { struct tm *tmp = localtime(&now);
      if (tmp) lt = *tmp; else memset(&lt, 0, sizeof(lt)); }
    strftime(ts,     sizeof(ts),     "%H:%M:%S",          &lt);
    strftime(ts_log, sizeof(ts_log), "%Y-%m-%d %H:%M:%S", &lt);

    if (kind == LINE_CHAT && (colon = strstr(text, ": ")) != NULL
        && (size_t)(colon - text) < 256) {
        /* Lines like "[room] alice: hi" - try to colourise the nickname. */
        const char *first = text;
        const char *space = strchr(first, ' ');
        int is_self = 0;
        const char *nick_start = first;
        if (space && first[0] == '[') nick_start = space + 1;
        {
            size_t nicklen = (size_t)(colon - nick_start);
            if (nicklen == strlen(g_nick)
                && memcmp(nick_start, g_nick, nicklen) == 0) is_self = 1;
        }
        printf("%s[%s]%s ", cT, ts, cR);
        printf("%.*s", (int)(nick_start - first), first);
        printf("%s%.*s%s: %s\n",
               is_self ? cS : cO,
               (int)(colon - nick_start), nick_start, cR,
               colon + 2);
    } else if (kind == LINE_FILE) {
        printf("%s[%s]%s %s%s%s\n", cT, ts, cR, cM, text, cR);
    } else if (kind == LINE_DM) {
        printf("%s[%s]%s %s%s%s\n", cT, ts, cR, cB, text, cR);
    } else if (kind == LINE_EMOTE) {
        printf("%s[%s]%s %s%s%s\n", cT, ts, cR, cE, text, cR);
    } else {
        printf("%s[%s]%s %s%s%s\n", cT, ts, cR, cY, text, cR);
    }
    fflush(stdout);

    if (g_log) {
        fprintf(g_log, "[%s] %s\n", ts_log, text);
        fflush(g_log);
    }
    MUTEX_UNLOCK(g_print_lock);
}

static void term_putlinef(line_kind kind, const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    term_putline(buf, kind);
}

static void log_open(const char *nick) {
    char fn[256], safe[64], ts[32];
    size_t i, n;
    time_t now;
    struct tm *lt;
    n = strlen(nick);
    if (n >= sizeof(safe)) n = sizeof(safe) - 1;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)nick[i];
        safe[i] = (c == '/' || c == '\\' || c == ':' || c < 0x20 || c == 0x7f)
                  ? '_' : (char)c;
    }
    safe[n] = 0;
    if (n == 0) snprintf(safe, sizeof(safe), "anon");
    snprintf(fn, sizeof(fn), "freedom-net-%s.log", safe);
    if (g_log) { fclose(g_log); g_log = NULL; }
    g_log = fopen(fn, "ab");
    if (!g_log) {
        term_putlinef(LINE_SYSTEM, "Could not open log file %s - logging disabled.", fn);
        return;
    }
    now = time(NULL);
    lt = localtime(&now);
    if (lt) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", lt);
    else    snprintf(ts, sizeof(ts), "?");
    fprintf(g_log,
        "\n========== %s %s session %s as \"%s\" ==========\n",
        APP_NAME, APP_VERSION, ts, nick);
    fflush(g_log);
    term_putlinef(LINE_SYSTEM, "Logging this session to ./%s", fn);
}

/* ===== Send under lock ===== */

static mutex_t g_send_lock;
static aes_ctx g_aes;
static sock_t  g_sock = SOCK_INVALID;

static int send_packet_locked(uint8_t type, const uint8_t *payload, size_t plen) {
    uint8_t iv[16], hdr[4];
    size_t pt_len = 1 + plen;
    size_t ct_len = ((pt_len / 16) + 1) * 16;
    size_t framelen = 16 + ct_len;
    uint8_t *pt, *ct;
    int rc;
    if (g_sock == SOCK_INVALID) return -1;
    if (pt_len > MAX_PLAINTEXT) return -1;
    pt = (uint8_t *)malloc(pt_len);
    ct = (uint8_t *)malloc(ct_len);
    if (!pt || !ct) { free(pt); free(ct); return -1; }
    pt[0] = type;
    if (plen) memcpy(pt + 1, payload, plen);
    if (random_bytes(iv, 16) != 0) { free(pt); free(ct); return -1; }
    aes_cbc_encrypt(&g_aes, iv, pt, pt_len, ct);
    free(pt);
    hdr[0] = (uint8_t)(framelen >> 24);
    hdr[1] = (uint8_t)(framelen >> 16);
    hdr[2] = (uint8_t)(framelen >>  8);
    hdr[3] = (uint8_t)(framelen);
    MUTEX_LOCK(g_send_lock);
    rc = 0;
    if (send_all(g_sock, hdr, 4) != 0)     rc = -1;
    else if (send_all(g_sock, iv,  16) != 0) rc = -1;
    else if (send_all(g_sock, ct, ct_len) != 0) rc = -1;
    MUTEX_UNLOCK(g_send_lock);
    free(ct);
    return rc;
}

static int recv_packet_into(sock_t s,
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
    plen = aes_cbc_decrypt(&g_aes, iv, ct, ct_len, pt);
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

/* ===== Validation / path utils ===== */

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

static const char *path_basename(const char *p) {
    const char *last = p, *q;
    for (q = p; *q; q++) if (*q == '/' || *q == '\\') last = q + 1;
    return last;
}
static int path_is_absolute(const char *p) {
    if (!p || !*p) return 0;
    if (p[0] == '/') return 1;
    if (((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':')
        return 1;
    return 0;
}
static int file_exists(const char *p) {
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

/* ===== Client room state ===== */

static char    g_rooms_list[MAX_ROOMS_PER_USER][MAX_ROOM];
static int     g_nrooms = 0;
static int     g_current_room = -1;        /* index into g_rooms_list, or -1 */
static mutex_t g_state_lock;

static int find_room_local_unlocked(const char *r) {
    int i;
    for (i = 0; i < g_nrooms; i++)
        if (strcmp(g_rooms_list[i], r) == 0) return i;
    return -1;
}

static void add_room_local(const char *r) {
    MUTEX_LOCK(g_state_lock);
    if (find_room_local_unlocked(r) < 0 && g_nrooms < MAX_ROOMS_PER_USER) {
        strncpy(g_rooms_list[g_nrooms], r, MAX_ROOM - 1);
        g_rooms_list[g_nrooms][MAX_ROOM - 1] = 0;
        g_current_room = g_nrooms;
        g_nrooms++;
    } else {
        int idx = find_room_local_unlocked(r);
        if (idx >= 0) g_current_room = idx;
    }
    MUTEX_UNLOCK(g_state_lock);
}

static void remove_room_local(const char *r) {
    int i;
    MUTEX_LOCK(g_state_lock);
    i = find_room_local_unlocked(r);
    if (i >= 0) {
        for (; i < g_nrooms - 1; i++)
            strcpy(g_rooms_list[i], g_rooms_list[i + 1]);
        g_nrooms--;
        if (g_nrooms == 0) g_current_room = -1;
        else if (g_current_room >= g_nrooms) g_current_room = g_nrooms - 1;
    }
    MUTEX_UNLOCK(g_state_lock);
}

static int get_current_room(char out[MAX_ROOM]) {
    int got = 0;
    MUTEX_LOCK(g_state_lock);
    if (g_current_room >= 0 && g_current_room < g_nrooms) {
        strncpy(out, g_rooms_list[g_current_room], MAX_ROOM - 1);
        out[MAX_ROOM - 1] = 0;
        got = 1;
    }
    MUTEX_UNLOCK(g_state_lock);
    return got;
}

/* ===== Encoders for client->server packets ===== */

static int send_hello(const char *nick, const char *room) {
    size_t nl = nick ? strlen(nick) : 0;
    size_t rl = room ? strlen(room) : 0;
    uint8_t *b;
    int rc;
    size_t total;
    if (nl > 255 || rl > 255) return -1;
    total = 1 + nl + 1 + rl;
    b = (uint8_t *)malloc(total);
    if (!b) return -1;
    b[0] = (uint8_t)nl; if (nl) memcpy(b + 1, nick, nl);
    b[1 + nl] = (uint8_t)rl; if (rl) memcpy(b + 2 + nl, room, rl);
    rc = send_packet_locked(PKT_HELLO, b, total);
    free(b);
    return rc;
}

static int send_room_text(uint8_t type, const char *room, const char *text) {
    size_t rl = strlen(room), tl = strlen(text);
    uint8_t *b;
    int rc;
    if (rl == 0 || rl > 255 || tl == 0 || tl > MAX_TEXT) return -1;
    b = (uint8_t *)malloc(1 + rl + tl);
    if (!b) return -1;
    b[0] = (uint8_t)rl;
    memcpy(b + 1, room, rl);
    memcpy(b + 1 + rl, text, tl);
    rc = send_packet_locked(type, b, 1 + rl + tl);
    free(b);
    return rc;
}

static int send_dm(const char *recip, const char *text) {
    size_t rl = strlen(recip), tl = strlen(text);
    uint8_t *b;
    int rc;
    if (rl == 0 || rl > 255 || tl == 0 || tl > MAX_TEXT) return -1;
    b = (uint8_t *)malloc(1 + rl + tl);
    if (!b) return -1;
    b[0] = (uint8_t)rl;
    memcpy(b + 1, recip, rl);
    memcpy(b + 1 + rl, text, tl);
    rc = send_packet_locked(PKT_DM, b, 1 + rl + tl);
    free(b);
    return rc;
}

static int send_file_to(const char *recip, const char *abspath) {
    FILE *f;
    long fsz;
    size_t rl = strlen(recip), bnl;
    const char *base;
    uint8_t *b;
    size_t total, o;
    int rc;
    if (rl == 0 || rl > 255) {
        term_putline("Invalid recipient.", LINE_SYSTEM); return -1;
    }
    if (!path_is_absolute(abspath)) {
        term_putline("File path must be absolute.", LINE_SYSTEM); return -1;
    }
    base = path_basename(abspath);
    bnl = strlen(base);
    if (bnl == 0 || bnl > 255) {
        term_putline("Bad filename.", LINE_SYSTEM); return -1;
    }
    f = fopen(abspath, "rb");
    if (!f) {
        term_putlinef(LINE_SYSTEM, "Cannot open file: %s", abspath); return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    fsz = ftell(f);
    if (fsz < 0 || fsz > MAX_FILE_BYTES) {
        term_putlinef(LINE_SYSTEM, "File too large or unreadable: %ld bytes (limit %d)",
                      fsz, MAX_FILE_BYTES);
        fclose(f); return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    total = 1 + rl + 1 + bnl + 4 + (size_t)fsz;
    b = (uint8_t *)malloc(total);
    if (!b) { fclose(f); return -1; }
    o = 0;
    b[o++] = (uint8_t)rl;  memcpy(b + o, recip, rl); o += rl;
    b[o++] = (uint8_t)bnl; memcpy(b + o, base,  bnl); o += bnl;
    b[o++] = (uint8_t)((uint32_t)fsz >> 24);
    b[o++] = (uint8_t)((uint32_t)fsz >> 16);
    b[o++] = (uint8_t)((uint32_t)fsz >>  8);
    b[o++] = (uint8_t)((uint32_t)fsz);
    if ((long)fread(b + o, 1, (size_t)fsz, f) != fsz) {
        fclose(f); free(b);
        term_putlinef(LINE_SYSTEM, "Read error on %s", abspath);
        return -1;
    }
    fclose(f);
    rc = send_packet_locked(PKT_FILE, b, total);
    free(b);
    if (rc == 0) {
        term_putlinef(LINE_FILE, "--> file to %s: \"%s\" (%ld bytes)", recip, base, fsz);
    }
    return rc;
}

static int send_simple_string(uint8_t type, const char *s) {
    size_t sl = strlen(s);
    uint8_t *b;
    int rc;
    if (sl == 0 || sl > 255) return -1;
    b = (uint8_t *)malloc(1 + sl);
    if (!b) return -1;
    b[0] = (uint8_t)sl;
    memcpy(b + 1, s, sl);
    rc = send_packet_locked(type, b, 1 + sl);
    free(b);
    return rc;
}

/* ===== Decoder for server->client packets ===== */

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

static void save_received_file(const char *sender, const char *fname,
                               const uint8_t *bytes, uint32_t bsize) {
    char savepath[600];
    const char *base = path_basename(fname);
    int idx;
    FILE *f;
    if (!*base || strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
        term_putlinef(LINE_SYSTEM, "Bad filename from %s, ignored.", sender);
        return;
    }
    snprintf(savepath, sizeof(savepath), "%s", base);
    idx = 1;
    while (file_exists(savepath)) {
        if (idx > 9999) {
            term_putline("Too many name collisions, dropping file.", LINE_SYSTEM);
            return;
        }
        snprintf(savepath, sizeof(savepath), "%s.%d", base, idx++);
    }
    f = fopen(savepath, "wb");
    if (!f) {
        term_putlinef(LINE_SYSTEM, "Could not create file %s", savepath);
        return;
    }
    if (fwrite(bytes, 1, bsize, f) != bsize) {
        fclose(f); remove(savepath);
        term_putlinef(LINE_SYSTEM, "Write failed for %s", savepath);
        return;
    }
    fclose(f);
    term_putlinef(LINE_FILE, "<-- file from %s: \"%s\" (%u bytes) saved as ./%s",
                  sender, fname, (unsigned)bsize, savepath);
}

static void on_pkt_msg(const uint8_t *p, size_t plen) {
    char room[MAX_ROOM], sender[MAX_NICK];
    size_t off = 0;
    if (read_u8_string(p, plen, &off, room,   sizeof(room))   != 0) return;
    if (read_u8_string(p, plen, &off, sender, sizeof(sender)) != 0) return;
    {
        size_t tlen = plen - off;
        char  text[MAX_TEXT + 1];
        if (tlen > MAX_TEXT) tlen = MAX_TEXT;
        memcpy(text, p + off, tlen); text[tlen] = 0;
        term_putlinef(LINE_CHAT, "[%s] %s: %s", room, sender, text);
    }
}

static void on_pkt_emote(const uint8_t *p, size_t plen) {
    char room[MAX_ROOM], sender[MAX_NICK];
    size_t off = 0;
    if (read_u8_string(p, plen, &off, room,   sizeof(room))   != 0) return;
    if (read_u8_string(p, plen, &off, sender, sizeof(sender)) != 0) return;
    {
        size_t tlen = plen - off;
        char text[MAX_TEXT + 1];
        if (tlen > MAX_TEXT) tlen = MAX_TEXT;
        memcpy(text, p + off, tlen); text[tlen] = 0;
        term_putlinef(LINE_EMOTE, "[%s] * %s %s *", room, sender, text);
    }
}

static void on_pkt_sys(const uint8_t *p, size_t plen) {
    char room[MAX_ROOM];
    size_t off = 0;
    if (read_u8_string(p, plen, &off, room, sizeof(room)) != 0) return;
    {
        size_t tlen = plen - off;
        char text[MAX_TEXT + 1];
        if (tlen > MAX_TEXT) tlen = MAX_TEXT;
        memcpy(text, p + off, tlen); text[tlen] = 0;
        term_putlinef(LINE_SYSTEM, "[%s] %s", room, text);
    }
}

static void on_pkt_err(const uint8_t *p, size_t plen) {
    char buf[MAX_TEXT + 1];
    if (plen > MAX_TEXT) plen = MAX_TEXT;
    memcpy(buf, p, plen); buf[plen] = 0;
    term_putlinef(LINE_SYSTEM, "[server] %s", buf);
}

static void on_pkt_dm(const uint8_t *p, size_t plen) {
    char sender[MAX_NICK];
    size_t off = 0;
    if (read_u8_string(p, plen, &off, sender, sizeof(sender)) != 0) return;
    {
        size_t tlen = plen - off;
        char text[MAX_TEXT + 1];
        if (tlen > MAX_TEXT) tlen = MAX_TEXT;
        memcpy(text, p + off, tlen); text[tlen] = 0;
        term_putlinef(LINE_DM, "[DM from %s] %s", sender, text);
    }
}

static void on_pkt_file(const uint8_t *p, size_t plen) {
    char sender[MAX_NICK], fname[256];
    size_t off = 0;
    uint8_t fnl;
    uint32_t fsz;
    if (read_u8_string(p, plen, &off, sender, sizeof(sender)) != 0) return;
    if (off + 1 > plen) return;
    fnl = p[off++];
    if (fnl == 0) return;                         /* fnl < 256 < sizeof(fname) */
    if (off + (size_t)fnl + 4 > plen) return;
    memcpy(fname, p + off, fnl); fname[fnl] = 0; off += fnl;
    fsz = ((uint32_t)p[off]   << 24) | ((uint32_t)p[off+1] << 16) |
          ((uint32_t)p[off+2] <<  8) | ((uint32_t)p[off+3]);
    off += 4;
    if (fsz > MAX_FILE_BYTES) return;
    if (off + fsz != plen) return;
    save_received_file(sender, fname, p + off, fsz);
}

static void on_pkt_who(const uint8_t *p, size_t plen) {
    char room[MAX_ROOM];
    size_t off = 0;
    uint8_t count, i;
    char line[2048];
    size_t lo = 0;
    if (read_u8_string(p, plen, &off, room, sizeof(room)) != 0) return;
    if (off + 1 > plen) return;
    count = p[off++];
    lo += (size_t)snprintf(line + lo, sizeof(line) - lo,
                           "[%s] users (%u):", room, (unsigned)count);
    for (i = 0; i < count; i++) {
        char nick[MAX_NICK];
        if (read_u8_string(p, plen, &off, nick, sizeof(nick)) != 0) break;
        lo += (size_t)snprintf(line + lo, sizeof(line) - lo, " %s%s",
                               nick, (i + 1 < count) ? "," : "");
        if (lo >= sizeof(line) - 64) break;
    }
    term_putline(line, LINE_SYSTEM);
}

static void on_pkt_list(const uint8_t *p, size_t plen) {
    size_t off = 0;
    uint8_t count, i;
    char line[4096];
    size_t lo = 0;
    if (off + 1 > plen) return;
    count = p[off++];
    lo += (size_t)snprintf(line + lo, sizeof(line) - lo,
                           "rooms (%u):", (unsigned)count);
    for (i = 0; i < count; i++) {
        char rname[MAX_ROOM];
        uint16_t nm;
        if (read_u8_string(p, plen, &off, rname, sizeof(rname)) != 0) break;
        if (off + 2 > plen) break;
        nm = ((uint16_t)p[off] << 8) | p[off + 1];
        off += 2;
        lo += (size_t)snprintf(line + lo, sizeof(line) - lo,
                               " %s(%u)%s",
                               rname, (unsigned)nm,
                               (i + 1 < count) ? "," : "");
        if (lo >= sizeof(line) - 64) break;
    }
    term_putline(line, LINE_SYSTEM);
}

static void on_pkt_join(const uint8_t *p, size_t plen) {
    char room[MAX_ROOM], nick[MAX_NICK];
    size_t off = 0;
    if (read_u8_string(p, plen, &off, room, sizeof(room)) != 0) return;
    if (read_u8_string(p, plen, &off, nick, sizeof(nick)) != 0) return;
    if (strcmp(nick, g_nick) == 0) {
        add_room_local(room);
        term_putlinef(LINE_SYSTEM, "* you joined %s *", room);
    } else {
        term_putlinef(LINE_SYSTEM, "[%s] * %s joined *", room, nick);
    }
}

static void on_pkt_part(const uint8_t *p, size_t plen) {
    char room[MAX_ROOM], nick[MAX_NICK];
    size_t off = 0;
    if (read_u8_string(p, plen, &off, room, sizeof(room)) != 0) return;
    if (read_u8_string(p, plen, &off, nick, sizeof(nick)) != 0) return;
    if (strcmp(nick, g_nick) == 0) {
        remove_room_local(room);
        term_putlinef(LINE_SYSTEM, "* you left %s *", room);
    } else {
        term_putlinef(LINE_SYSTEM, "[%s] * %s left *", room, nick);
    }
}

static void on_pkt_nick_ack(const uint8_t *p, size_t plen) {
    char newnick[MAX_NICK];
    if (plen == 0 || plen >= MAX_NICK) return;
    memcpy(newnick, p, plen); newnick[plen] = 0;
    MUTEX_LOCK(g_print_lock);
    strncpy(g_nick, newnick, MAX_NICK - 1);
    g_nick[MAX_NICK - 1] = 0;
    MUTEX_UNLOCK(g_print_lock);
    term_putlinef(LINE_SYSTEM, "* you are now known as %s *", newnick);
    log_open(newnick);
}

/* ===== Receive thread ===== */

#ifdef _WIN32
static DWORD WINAPI recv_thread(LPVOID arg)
#else
static void *recv_thread(void *arg)
#endif
{
    (void)arg;
    for (;;) {
        uint8_t *p = NULL;
        size_t   plen = 0;
        uint8_t  type = 0;
        if (recv_packet_into(g_sock, &p, &plen, &type) != 0) {
            term_putline("Connection closed by server.", LINE_SYSTEM);
            break;
        }
        switch (type) {
            case PKT_MSG:   on_pkt_msg(p, plen);   break;
            case PKT_EMOTE: on_pkt_emote(p, plen); break;
            case PKT_SYS:   on_pkt_sys(p, plen);   break;
            case PKT_ERR:   on_pkt_err(p, plen);   break;
            case PKT_DM:    on_pkt_dm(p, plen);    break;
            case PKT_FILE:  on_pkt_file(p, plen);  break;
            case PKT_WHO:   on_pkt_who(p, plen);   break;
            case PKT_LIST:  on_pkt_list(p, plen);  break;
            case PKT_JOIN:  on_pkt_join(p, plen);  break;
            case PKT_PART:  on_pkt_part(p, plen);  break;
            case PKT_NICK:  on_pkt_nick_ack(p, plen); break;
            case PKT_PING:  /* ignore */ break;
            default: break;
        }
        free(p);
    }
    /* signal the input loop to exit by closing the socket. */
    {
        sock_t s = g_sock;
        g_sock = SOCK_INVALID;
        if (s != SOCK_INVALID) CLOSESOCK(s);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ===== Connect ===== */

static int do_connect(const char *host, int port, const char *passphrase,
                      const char *want_nick, const char *want_room) {
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[8];
    sock_t s = SOCK_INVALID;
    uint8_t key[32];
    uint8_t *p = NULL;
    size_t plen = 0;
    uint8_t type = 0;
    char nick[MAX_NICK], room[MAX_ROOM];
    size_t off = 0;

    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        term_putlinef(LINE_SYSTEM, "DNS resolution failed for %s", host);
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == SOCK_INVALID) continue;
        if (connect(s, ai->ai_addr, (slen_t)ai->ai_addrlen) == 0) break;
        CLOSESOCK(s); s = SOCK_INVALID;
    }
    freeaddrinfo(res);
    if (s == SOCK_INVALID) {
        term_putlinef(LINE_SYSTEM, "Could not connect to %s:%d", host, port);
        return -1;
    }
    set_keepalive(s);

    derive_key(passphrase, key);
    aes_key_expansion(&g_aes, key);
    memset(key, 0, sizeof(key));

    g_sock = s;

    if (send_hello(want_nick ? want_nick : "", want_room ? want_room : "") != 0) {
        term_putline("Failed to send hello.", LINE_SYSTEM);
        CLOSESOCK(s); g_sock = SOCK_INVALID; return -1;
    }
    if (recv_packet_into(s, &p, &plen, &type) != 0) {
        term_putline("Server hung up during handshake (bad keyphrase?).", LINE_SYSTEM);
        CLOSESOCK(s); g_sock = SOCK_INVALID; return -1;
    }
    if (type == PKT_ERR) {
        char buf[MAX_TEXT + 1];
        if (plen > MAX_TEXT) plen = MAX_TEXT;
        memcpy(buf, p, plen); buf[plen] = 0;
        term_putlinef(LINE_SYSTEM, "Server rejected: %s", buf);
        free(p);
        CLOSESOCK(s); g_sock = SOCK_INVALID; return -1;
    }
    if (type != PKT_HELLO) {
        term_putline("Bad handshake from server.", LINE_SYSTEM);
        free(p);
        CLOSESOCK(s); g_sock = SOCK_INVALID; return -1;
    }
    if (read_u8_string(p, plen, &off, nick, sizeof(nick)) != 0
        || read_u8_string(p, plen, &off, room, sizeof(room)) != 0) {
        term_putline("Malformed hello-ack.", LINE_SYSTEM);
        free(p);
        CLOSESOCK(s); g_sock = SOCK_INVALID; return -1;
    }
    free(p);

    strncpy(g_nick, nick, MAX_NICK - 1);
    g_nick[MAX_NICK - 1] = 0;
    add_room_local(room);

    term_putlinef(LINE_SYSTEM, "Connected as \"%s\" in room \"%s\".", nick, room);
    log_open(nick);

#ifdef _WIN32
    {
        HANDLE th = CreateThread(NULL, 0, recv_thread, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
#else
    {
        pthread_t th;
        if (pthread_create(&th, NULL, recv_thread, NULL) == 0) pthread_detach(th);
    }
#endif
    return 0;
}

/* ===== Input loop ===== */

static void show_help(void) {
    term_putline("Commands:", LINE_SYSTEM);
    term_putline("  /join <room>          join a room (or switch to it)", LINE_SYSTEM);
    term_putline("  /part [<room>]        leave a room (default: current)", LINE_SYSTEM);
    term_putline("  /msg <nick> <text>    private message", LINE_SYSTEM);
    term_putline("  /send <nick> <abs-path>  send a file (<= 10 MB)", LINE_SYSTEM);
    term_putline("  /me <action>          emote in current room", LINE_SYSTEM);
    term_putline("  /nick <newnick>       change your nickname", LINE_SYSTEM);
    term_putline("  /who [<room>]         list users in a room", LINE_SYSTEM);
    term_putline("  /list                 list all rooms on the server", LINE_SYSTEM);
    term_putline("  /quit                 disconnect", LINE_SYSTEM);
    term_putline("  //text                send a literal line that starts with '/'", LINE_SYSTEM);
}

static char *trim(char *s) {
    char *e;
    while (*s && isspace((unsigned char)*s)) s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

/* Split the first two whitespace-delimited tokens off `s` (in place).
 * Returns pointer to remainder (may be empty). */
static char *take_token(char *s, char **tok) {
    while (*s && isspace((unsigned char)*s)) s++;
    *tok = s;
    while (*s && !isspace((unsigned char)*s)) s++;
    if (*s) { *s = 0; s++; while (*s && isspace((unsigned char)*s)) s++; }
    return s;
}

static void handle_input(char *line) {
    char curroom[MAX_ROOM];

    line = trim(line);
    if (!*line) return;

    if (line[0] == '/' && line[1] != '/') {
        char *cmd, *rest;
        rest = take_token(line, &cmd);
        if (strcmp(cmd, "/quit") == 0) {
            send_packet_locked(PKT_QUIT, NULL, 0);
            if (g_sock != SOCK_INVALID) {
                sock_t s = g_sock;
                g_sock = SOCK_INVALID;
                CLOSESOCK(s);
            }
            return;
        }
        if (strcmp(cmd, "/help") == 0) { show_help(); return; }
        if (strcmp(cmd, "/list") == 0) { send_packet_locked(PKT_LIST, NULL, 0); return; }
        if (strcmp(cmd, "/who") == 0) {
            char *room = trim(rest);
            char buf[MAX_ROOM];
            if (!*room) {
                if (!get_current_room(buf)) {
                    term_putline("Not in any room.", LINE_SYSTEM); return;
                }
                room = buf;
            }
            send_simple_string(PKT_WHO, room);
            return;
        }
        if (strcmp(cmd, "/join") == 0) {
            char *room = trim(rest);
            if (!*room) { term_putline("Usage: /join <room>", LINE_SYSTEM); return; }
            if (!name_is_valid(room, MAX_ROOM)) {
                term_putline("Invalid room name.", LINE_SYSTEM); return;
            }
            /* If already in this room, just switch active context. */
            MUTEX_LOCK(g_state_lock);
            {
                int idx = find_room_local_unlocked(room);
                if (idx >= 0) {
                    g_current_room = idx;
                    MUTEX_UNLOCK(g_state_lock);
                    term_putlinef(LINE_SYSTEM, "* switched to room %s *", room);
                    return;
                }
            }
            MUTEX_UNLOCK(g_state_lock);
            send_simple_string(PKT_JOIN, room);
            return;
        }
        if (strcmp(cmd, "/part") == 0) {
            char *room = trim(rest);
            char buf[MAX_ROOM];
            if (!*room) {
                if (!get_current_room(buf)) {
                    term_putline("Not in any room.", LINE_SYSTEM); return;
                }
                room = buf;
            }
            send_simple_string(PKT_PART, room);
            return;
        }
        if (strcmp(cmd, "/nick") == 0) {
            char *nn = trim(rest);
            if (!*nn) { term_putline("Usage: /nick <newnick>", LINE_SYSTEM); return; }
            if (!name_is_valid(nn, MAX_NICK)) {
                term_putline("Invalid nickname.", LINE_SYSTEM); return;
            }
            send_simple_string(PKT_NICK, nn);
            return;
        }
        if (strcmp(cmd, "/me") == 0) {
            char *text = trim(rest);
            if (!*text) { term_putline("Usage: /me <action>", LINE_SYSTEM); return; }
            if (!get_current_room(curroom)) {
                term_putline("Not in any room.", LINE_SYSTEM); return;
            }
            send_room_text(PKT_EMOTE, curroom, text);
            return;
        }
        if (strcmp(cmd, "/msg") == 0) {
            char *to, *text;
            text = take_token(rest, &to);
            text = trim(text);
            if (!*to || !*text) {
                term_putline("Usage: /msg <nick> <text>", LINE_SYSTEM); return;
            }
            send_dm(to, text);
            term_putlinef(LINE_DM, "[DM to %s] %s", to, text);
            return;
        }
        if (strcmp(cmd, "/send") == 0) {
            char *to, *path;
            path = take_token(rest, &to);
            path = trim(path);
            if (!*to || !*path) {
                term_putline("Usage: /send <nick> <absolute-path>", LINE_SYSTEM); return;
            }
            send_file_to(to, path);
            return;
        }
        if (strcmp(cmd, "/connect") == 0) {
            term_putline("Already connected; /quit first.", LINE_SYSTEM);
            return;
        }
        term_putlinef(LINE_SYSTEM, "Unknown command: %s  (try /help)", cmd);
        return;
    }

    /* Plain text -> current room. Strip a leading '/' escape if present. */
    {
        const char *text = (line[0] == '/' && line[1] == '/') ? line + 1 : line;
        if (!get_current_room(curroom)) {
            term_putline("Not in any room; /join one first.", LINE_SYSTEM);
            return;
        }
        send_room_text(PKT_MSG, curroom, text);
    }
}

/* ===== main ===== */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <server> <port> <keyphrase> [<nickname>] [<room>]\n"
        "Pass \"\" for nickname or room to let the server pick one.\n", prog);
}

int main(int argc, char **argv) {
    const char *server;
    int port;
    const char *passphrase;
    const char *want_nick = "";
    const char *want_room = "";
    char line[MAX_TEXT + 8];

    if (argc < 4 || argc > 6) { usage(argv[0]); return 2; }
    server = argv[1];
    port = atoi(argv[2]);
    if (port <= 0 || port > 65535) { usage(argv[0]); return 2; }
    passphrase = argv[3];
    if (strlen(passphrase) == 0) {
        fprintf(stderr, "keyphrase cannot be empty\n");
        return 2;
    }
    if (argc >= 5) want_nick = argv[4];
    if (argc >= 6) want_room = argv[5];

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
#endif

    term_init();
    MUTEX_INIT(g_send_lock);
    MUTEX_INIT(g_state_lock);
    g_nrooms = 0;
    g_current_room = -1;

    term_putlinef(LINE_SYSTEM, "%s %s client. Connecting to %s:%d ...",
                  APP_NAME, APP_VERSION, server, port);

    if (do_connect(server, port, passphrase, want_nick, want_room) != 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    while (g_sock != SOCK_INVALID) {
        if (!fgets(line, sizeof(line), stdin)) break;
        handle_input(line);
    }

    if (g_log) { fclose(g_log); g_log = NULL; }
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
