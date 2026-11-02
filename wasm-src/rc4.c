/* Freestanding (no libc) RC4 for compilation to WASM. Mirrors js/rc4.js exactly. The JS side
 * writes key and data into the exported buffer at fixed offsets, calls rc4(keyLen, dataLen),
 * and reads the XORed result back from the same data offset (RC4 keystream XOR is naturally
 * in-place: ciphertext = plaintext ^ keystream, same operation either direction). */

typedef unsigned char u8;
typedef unsigned int u32;

#define S_OFF 0
#define KEY_OFF 256
#define DATA_OFF 320
#define BUF_SIZE 576

static u8 buf[BUF_SIZE];

__attribute__((export_name("get_buffer")))
u8 *get_buffer(void) { return buf; }

__attribute__((export_name("rc4")))
void wasm_rc4(u32 keyLen, u32 dataLen) {
  u8 *S = buf + S_OFF;
  u8 *key = buf + KEY_OFF;
  u8 *data = buf + DATA_OFF;

  for (u32 i = 0; i < 256; i++) S[i] = (u8)i;
  u32 j = 0;
  for (u32 i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % keyLen]) & 0xff;
    u8 tmp = S[i]; S[i] = S[j]; S[j] = tmp;
  }
  u32 i = 0;
  j = 0;
  for (u32 k = 0; k < dataLen; k++) {
    i = (i + 1) & 0xff;
    j = (j + S[i]) & 0xff;
    u8 tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    data[k] = data[k] ^ S[(S[i] + S[j]) & 0xff];
  }
}
