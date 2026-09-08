#include <string.h>

#include "thash.h"
#include "merkle.h" /* 提供 u32_to_bytes / bytes_to_ull 等字节序工具 */

/* ------------------------------------------------------------------ */
/* MGF1-SHA256：out = SHA-256(in || 0x00000000) || SHA-256(in || 0x00000001) || ... */
/* ------------------------------------------------------------------ */
void mgf1_256(unsigned char *out, unsigned long outlen,
              const unsigned char *in, unsigned long inlen) {
    unsigned char inbuf[inlen + 4];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint32_t i;

    memcpy(inbuf, in, inlen);

    /* 只要还能再输出一个完整 SHA-256 分组，就生成完整分组 */
    for (i = 0; (i + 1) * SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sha256(out, inbuf, inlen + 4);
        out += SPX_SHA256_OUTPUT_BYTES;
    }

    /* 最后不足一个分组的部分，生成后只截取需要的字节 */
    if (outlen > i * SPX_SHA256_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sha256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i * SPX_SHA256_OUTPUT_BYTES);
    }
}

/* ------------------------------------------------------------------ */
/* PRF(pk_seed, sk_seed, addr) = SHA-256(pk_seed || addr[0..21] || sk_seed) 截断到 n */
/* ------------------------------------------------------------------ */
void prf_addr(unsigned char *out, const spx_ctx *ctx, const uint32_t addr[8]) {
    unsigned char buf[SPX_N + SPX_SHA256_ADDR_BYTES + SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_SHA256_ADDR_BYTES, ctx->sk_seed, SPX_N);

    sha256(outbuf, buf, SPX_N + SPX_SHA256_ADDR_BYTES + SPX_N);
    memcpy(out, outbuf, SPX_N);
}

/* ------------------------------------------------------------------ */
/* thash（robust）：先 MGF1 生成掩码，再对输入异或掩码后做 SHA-256。        */
/* 输入 in 为 inblocks 个 n 字节块的拼接。                                */
/* ------------------------------------------------------------------ */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]) {
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    unsigned char bitmask[inblocks * SPX_N];
    unsigned char buf[SPX_N + SPX_SHA256_ADDR_BYTES + inblocks * SPX_N];
    unsigned int i;

    /* 1. MGF1 的种子 = pub_seed || addr[0..21] */
    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);

    /* 2. 生成位掩码 bitmask = MGF1-SHA256(pub_seed || addr, inblocks * n) */
    mgf1_256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* 3. 逐字节异或掩码，写入 buf 的输入区 */
    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    /* 4. thash = SHA-256(pub_seed || addr || (in XOR bitmask)) 截断到 n 字节 */
    sha256(outbuf, buf, SPX_N + SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
    memcpy(out, outbuf, SPX_N);
}

/* ------------------------------------------------------------------ */
/* PRF_msg：HMAC-SHA256(key = SK.prf, data = OptRand || M)，输出 R。       */
/* ------------------------------------------------------------------ */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, size_t mlen,
                        const spx_ctx *ctx) {
    (void)ctx;
    unsigned char buf[SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES];
    sha256ctx state;
    int i;

    /* ---- 内层哈希：H((0x36 ^ sk_prf) || OptRand || M) ---- */
    for (i = 0; i < SPX_N; i++) {
        buf[i] = (unsigned char)(0x36 ^ sk_prf[i]);
    }
    memset(buf + SPX_N, 0x36, SPX_SHA256_BLOCK_BYTES - SPX_N);

    sha256_inc_init(&state);
    sha256_inc_blocks(&state, buf, 1);

    memcpy(buf, optrand, SPX_N);
    if (SPX_N + mlen < SPX_SHA256_BLOCK_BYTES) {
        memcpy(buf + SPX_N, m, mlen);
        sha256_inc_finalize(buf + SPX_SHA256_BLOCK_BYTES, &state,
                            buf, mlen + SPX_N);
    } else {
        memcpy(buf + SPX_N, m, SPX_SHA256_BLOCK_BYTES - SPX_N);
        sha256_inc_blocks(&state, buf, 1);

        m += SPX_SHA256_BLOCK_BYTES - SPX_N;
        mlen -= SPX_SHA256_BLOCK_BYTES - SPX_N;
        sha256_inc_finalize(buf + SPX_SHA256_BLOCK_BYTES, &state, m, mlen);
    }

    /* ---- 外层哈希：H((0x5c ^ sk_prf) || 内层摘要) ---- */
    for (i = 0; i < SPX_N; i++) {
        buf[i] = (unsigned char)(0x5c ^ sk_prf[i]);
    }
    memset(buf + SPX_N, 0x5c, SPX_SHA256_BLOCK_BYTES - SPX_N);

    sha256(buf, buf, SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES);
    memcpy(R, buf, SPX_N);
}

/* ------------------------------------------------------------------ */
/* H_msg：输出消息摘要 digest（FORS 部分）、树索引 tree、叶子索引 leaf_idx。 */
/* 分两步：seed = SHA-256(R || pk || M)；md = MGF1-SHA256(R || PK.seed || seed)。 */
/* ------------------------------------------------------------------ */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, size_t mlen,
                  const spx_ctx *ctx) {
    (void)ctx;

    const uint32_t tree_bits = SPX_TREE_HEIGHT * (SPX_D - 1);   /* 54 */
    const uint32_t tree_bytes = (tree_bits + 7) / 8;            /* 7  */
    const uint32_t leaf_bits = SPX_TREE_HEIGHT;                 /* 9  */
    const uint32_t leaf_bytes = (leaf_bits + 7) / 8;            /* 2  */
    const uint32_t dgst_bytes = SPX_FORS_MSG_BYTES + tree_bytes + leaf_bytes; /* 30 */
    const uint32_t inblocks = ((SPX_N + SPX_PK_BYTES + SPX_SHA256_BLOCK_BYTES - 1) &
                               (~(uint32_t)(SPX_SHA256_BLOCK_BYTES - 1))) / SPX_SHA256_BLOCK_BYTES;

    unsigned char seed[(2 * SPX_N) + SPX_SHA256_OUTPUT_BYTES];
    unsigned char inbuf[inblocks * SPX_SHA256_BLOCK_BYTES];
    unsigned char buf[dgst_bytes];
    unsigned char *bufp = buf;
    sha256ctx state;

    /* 第一步：seed = SHA-256(R || pk || M) */
    sha256_inc_init(&state);
    memcpy(inbuf, R, SPX_N);
    memcpy(inbuf + SPX_N, pk, SPX_PK_BYTES);

    if (SPX_N + SPX_PK_BYTES + mlen < inblocks * SPX_SHA256_BLOCK_BYTES) {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, mlen);
        sha256_inc_finalize(seed + (2 * SPX_N), &state, inbuf,
                            SPX_N + SPX_PK_BYTES + mlen);
    } else {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m,
               inblocks * SPX_SHA256_BLOCK_BYTES - SPX_N - SPX_PK_BYTES);
        sha256_inc_blocks(&state, inbuf, inblocks);

        m += inblocks * SPX_SHA256_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        mlen -= inblocks * SPX_SHA256_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        sha256_inc_finalize(seed + (2 * SPX_N), &state, m, mlen);
    }

    /* 第二步：H_msg = MGF1-SHA256(R || PK.seed || seed) */
    memcpy(seed, R, SPX_N);
    memcpy(seed + SPX_N, pk, SPX_N);
    mgf1_256(bufp, dgst_bytes, seed, (2 * SPX_N) + SPX_SHA256_OUTPUT_BYTES);

    /* 解析：FORS 摘要 | 树索引 tree | 叶子索引 leaf_idx */
    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

    *tree = bytes_to_ull(bufp, tree_bytes);
    *tree &= (~(uint64_t)0) >> (64 - tree_bits);
    bufp += tree_bytes;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, leaf_bytes);
    *leaf_idx &= (~(uint32_t)0) >> (32 - leaf_bits);
}
