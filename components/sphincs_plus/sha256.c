#include <string.h>
#include "params.h"
#include "sha256.h"

/* FIPS 180-4 SHA-256 初始哈希值（前 8 个素数平方根小数部分的前 32 位） */
static const uint32_t sha256_iv[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

/* FIPS 180-4 轮常量（前 64 个素数立方根小数部分的前 32 位） */
static const uint32_t sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/*
 * SHA-256 压缩函数：处理一个 64 字节分组，更新 8 个工作变量。
 * 对应 FIPS 180-4 第 6.2.2 节。
 */
static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* 1. 消息扩展：前 16 个字按大端序读取，后 48 个字按递推式计算 */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    /* 2. 初始化工作变量 */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 3. 执行 64 轮压缩 */
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + sha256_k[i] + w[i];

        uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    /* 4. 把工作变量累加回状态 */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_inc_init(sha256ctx *state) {
    int i;
    for (i = 0; i < 8; i++) {
        state->state[i] = sha256_iv[i];
    }
    state->bytes = 0;
}

void sha256_inc_blocks(sha256ctx *state, const uint8_t *in, size_t inblocks) {
    while (inblocks > 0) {
        sha256_compress(state->state, in);
        in += SPX_SHA256_BLOCK_BYTES;
        state->bytes += SPX_SHA256_BLOCK_BYTES;
        inblocks--;
    }
}

void sha256_inc_finalize(uint8_t *out, sha256ctx *state, const uint8_t *in, size_t inlen) {
    uint8_t block[SPX_SHA256_BLOCK_BYTES * 2];
    uint64_t total_bits = (state->bytes + inlen) * 8;
    size_t rem;
    int i;

    /* 先吸收 in 中完整的 64 字节分组 */
    while (inlen >= SPX_SHA256_BLOCK_BYTES) {
        sha256_compress(state->state, in);
        in += SPX_SHA256_BLOCK_BYTES;
        inlen -= SPX_SHA256_BLOCK_BYTES;
    }
    rem = inlen;

    /* 填充：0x80、若干 0x00，以及 64 位消息长度（以比特计） */
    if (rem < 56) {
        memcpy(block, in, rem);
        block[rem] = 0x80;
        memset(block + rem + 1, 0, 56 - rem - 1);
        for (i = 0; i < 8; i++) {
            block[63 - i] = (uint8_t)(total_bits >> (8 * i));
        }
        sha256_compress(state->state, block);
    } else {
        memcpy(block, in, rem);
        block[rem] = 0x80;
        memset(block + rem + 1, 0, 64 - rem - 1);
        sha256_compress(state->state, block);
        memset(block, 0, 56);
        for (i = 0; i < 8; i++) {
            block[63 - i] = (uint8_t)(total_bits >> (8 * i));
        }
        sha256_compress(state->state, block);
    }

    /* 输出大端序的 32 字节摘要 */
    for (i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(state->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(state->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(state->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(state->state[i]);
    }
}

void sha256(uint8_t *out, const uint8_t *in, size_t inlen) {
    sha256ctx state;
    sha256_inc_init(&state);
    sha256_inc_finalize(out, &state, in, inlen);
}
