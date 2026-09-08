#include <string.h>

#include "wots.h"
#include "thash.h"
#include "merkle.h"

/*
 * WOTS+ 链函数：out 初始化为 in（链上第 start 个值），
 * 然后迭代 steps 次 thash，每次哈希地址中的 hash_addr 递增。
 */
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const spx_ctx *ctx, uint32_t addr[8]) {
    uint32_t i;

    memcpy(out, in, SPX_N);

    for (i = start; i < (start + steps) && i < SPX_WOTS_W; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}

/*
 * base_w：把字节串按“高比特在前”的方式解释为 out_len 个 base-w 整数。
 * 这里要求 log2(w) 能整除 8。
 */
static void base_w(uint32_t *output, int out_len, const unsigned char *input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W - 1);
        out++;
    }
}

/* WOTS+ 校验和：csum = sum(w-1 - msg_base_w[i])，再转成 base-w。 */
static void wots_checksum(uint32_t *csum_base_w, const uint32_t *msg_base_w) {
    unsigned int csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    unsigned int i;

    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    /* 把校验和左移对齐，使空的高位比特位于最低位（配合 base_w 的读取顺序） */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

void chain_lengths(uint32_t *lengths, const unsigned char *msg) {
    base_w(lengths, SPX_WOTS_LEN1, msg);
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

void wots_pk_gen(unsigned char *pk, const spx_ctx *ctx, uint32_t addr[8]) {
    unsigned char sk[SPX_N];
    uint32_t i;

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        set_hash_addr(addr, 0);

        /* 私钥元素 = PRF(pk_seed, sk_seed, addr)，类型域使用 WOTSPRF */
        set_type(addr, SPX_ADDR_TYPE_WOTSPRF);
        prf_addr(sk, ctx, addr);

        /* 链迭代使用类型域 WOTS */
        set_type(addr, SPX_ADDR_TYPE_WOTS);
        gen_chain(pk + i * SPX_N, sk, 0, SPX_WOTS_W - 1, ctx, addr);
    }
}

void wots_sign(unsigned char *sig, const unsigned char *msg,
               const spx_ctx *ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN];
    unsigned char sk[SPX_N];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        set_hash_addr(addr, 0);

        set_type(addr, SPX_ADDR_TYPE_WOTSPRF);
        prf_addr(sk, ctx, addr);

        set_type(addr, SPX_ADDR_TYPE_WOTS);
        gen_chain(sig + i * SPX_N, sk, 0, lengths[i], ctx, addr);
    }
}

void wots_pk_from_sig(unsigned char *pk, const unsigned char *sig,
                      const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        /* 从签名元素（链上第 lengths[i] 个值）继续迭代到链顶 */
        gen_chain(pk + i * SPX_N, sig + i * SPX_N,
                  lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx, addr);
    }
}

void wots_gen_leaf(unsigned char *leaf, const spx_ctx *ctx, uint32_t addr_idx,
                   const uint32_t tree_addr[8]) {
    uint32_t pk_addr[8] = {0};
    uint32_t wots_addr[8] = {0};
    unsigned char pk[SPX_WOTS_BYTES];

    /* WOTS 地址：只继承 layer/tree，再写类型和 keypair */
    copy_subtree_addr(wots_addr, tree_addr);
    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_keypair_addr(wots_addr, addr_idx);

    wots_pk_gen(pk, ctx, wots_addr);

    /* L-tree 压缩：类型 WOTSPK，keypair 不变 */
    copy_keypair_addr(pk_addr, wots_addr);
    set_type(pk_addr, SPX_ADDR_TYPE_WOTSPK);
    thash(leaf, pk, SPX_WOTS_LEN, ctx, pk_addr);
}
