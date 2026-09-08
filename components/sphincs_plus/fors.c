#include <string.h>

#include "fors.h"
#include "thash.h"
#include "merkle.h"

/* FORS 私钥元素 = PRF(pk_seed, sk_seed, addr)，类型域 FORSPRF */
static void fors_gen_sk(unsigned char *sk, const spx_ctx *ctx,
                        uint32_t fors_leaf_addr[8]) {
    prf_addr(sk, ctx, fors_leaf_addr);
}

/* FORS 叶子 = thash(私钥元素)，类型域 FORSTREE */
static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const spx_ctx *ctx, uint32_t fors_leaf_addr[8]) {
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

/* 生成 FORS 森林中第 addr_idx 个叶子（addr_idx 为跨森林的全局叶子索引） */
static void fors_gen_leaf(unsigned char *leaf, const spx_ctx *ctx,
                          uint32_t addr_idx, const uint32_t fors_tree_addr[8]) {
    uint32_t fors_leaf_addr[8] = {0};
    unsigned char sk[SPX_N];

    /* 只继承 layer/tree/keypair，类型和 tree_index 由本函数设置 */
    copy_keypair_addr(fors_leaf_addr, fors_tree_addr);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    set_tree_index(fors_leaf_addr, addr_idx);
    fors_gen_sk(sk, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf(leaf, sk, ctx, fors_leaf_addr);
}

/* 把消息摘要按“低位在前”解释为 t 个 k 比特索引 */
static void message_to_indices(uint32_t *indices, const unsigned char *m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}

void fors_sign(unsigned char *sig, unsigned char *pk, const unsigned char *m,
               const spx_ctx *ctx, const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* 1. 签名中的“秘密值”部分 */
        fors_gen_sk(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N;

        /* 2. 该叶子的认证路径（treehash 同时算出本棵树根） */
        treehash(roots + i * SPX_N, sig, ctx,
                 indices[i], idx_offset, SPX_FORS_HEIGHT,
                 fors_gen_leaf, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* 3. 横向哈希所有树根，得到 FORS 公钥 */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}

void fors_pk_from_sig(unsigned char *pk, const unsigned char *sig,
                      const unsigned char *m,
                      const spx_ctx *ctx, const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char leaf[SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* 1. 由签名中的秘密值恢复叶子 */
        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N;

        /* 2. 沿认证路径向上计算树根 */
        compute_root(roots + i * SPX_N, leaf, indices[i], idx_offset,
                     sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* 3. 横向哈希所有树根，得到 FORS 公钥 */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}
