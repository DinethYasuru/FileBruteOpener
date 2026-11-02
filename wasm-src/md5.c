/* Freestanding (no libc) MD5 for compilation to WASM. The JS side writes the raw message
 * into the exported buffer, calls md5(len), then reads 16 digest bytes back from a fixed
 * offset within the same buffer - no malloc, no imports, nothing beyond raw memory.
 * Sized generously for this app's actual inputs (short password-derivation material, at
 * most ~90 bytes), not for general-purpose hashing. */

typedef unsigned char u8;
typedef unsigned int u32;

#define BUF_SIZE 256
#define OUT_OFFSET 224

static u8 buf[BUF_SIZE];

__attribute__((export_name("get_buffer")))
u8 *get_buffer(void) { return buf; }

static const u32 K[64] = {
  0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
  0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
  0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
  0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
  0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
  0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
  0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
  0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const int S[64] = {
  7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
  5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
  4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
  6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static inline u32 rotl(u32 x, int c) { return (x << c) | (x >> (32 - c)); }

__attribute__((export_name("md5")))
void wasm_md5(u32 len) {
  u32 bitlen = len * 8;
  buf[len] = 0x80;
  u32 i = len + 1;
  while (i % 64 != 56) buf[i++] = 0;
  for (int k = 0; k < 4; k++) buf[i + k] = (u8)(bitlen >> (8 * k));
  for (int k = 4; k < 8; k++) buf[i + k] = 0; // high 32 bits of length: always 0 for our inputs
  u32 totalLen = i + 8;

  u32 a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (u32 chunk = 0; chunk < totalLen; chunk += 64) {
    u32 M[16];
    for (int j = 0; j < 16; j++) {
      u32 o = chunk + j * 4;
      M[j] = buf[o] | (buf[o+1] << 8) | (buf[o+2] << 16) | (buf[o+3] << 24);
    }
    u32 A = a0, B = b0, C = c0, D = d0;
    for (int ii = 0; ii < 64; ii++) {
      u32 F; int g;
      if (ii < 16) { F = (B & C) | (~B & D); g = ii; }
      else if (ii < 32) { F = (D & B) | (~D & C); g = (5*ii + 1) % 16; }
      else if (ii < 48) { F = B ^ C ^ D; g = (3*ii + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7*ii) % 16; }
      F = F + A + K[ii] + M[g];
      A = D; D = C; C = B;
      B = B + rotl(F, S[ii]);
    }
    a0 += A; b0 += B; c0 += C; d0 += D;
  }

  u8 *out = buf + OUT_OFFSET;
  for (int k = 0; k < 4; k++) out[k] = (u8)(a0 >> (8 * k));
  for (int k = 0; k < 4; k++) out[4 + k] = (u8)(b0 >> (8 * k));
  for (int k = 0; k < 4; k++) out[8 + k] = (u8)(c0 >> (8 * k));
  for (int k = 0; k < 4; k++) out[12 + k] = (u8)(d0 >> (8 * k));
}
