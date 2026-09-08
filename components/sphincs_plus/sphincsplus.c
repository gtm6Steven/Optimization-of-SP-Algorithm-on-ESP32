#include <string.h>
#include <time.h>

#include "sphincsplus.h"
#include "fors.h"
#include "merkle.h"
#include "thash.h"
#include "wots.h"

/* ============================================================
 * sphincsplus.c：SPHINCS+ 顶层流程
 *
 * 调用链（对应 FIPS 205）：
 *
 * KeyGen：
 *   crypto_sign_keypair
 *     -> crypto_sign_seed_keypair
 *        -> merkle_gen_root  （生成最顶层子树根）
 *           -> merkle_sign / treehash / wots_gen_leaf / thash
 *
 * Sign：
 *   crypto_sign
 *     -> crypto_sign_signature
 *        -> gen_message_random  （PRF_msg -> R）
 *        -> hash_message        （H_msg -> FORS 摘要、tree、leaf）
 *        -> fors_sign           （FORS 少量次签名）
 *        -> merkle_sign x 7     （d 层超树，每层 WOTS+ + 认证路径）
 *
 * Verify：
 *   crypto_sign_open
 *     -> crypto_sign_verify
 *        -> hash_message        （恢复 tree、leaf）
 *        -> fors_pk_from_sig    （恢复 FORS 公钥/根）
 *        -> wots_pk_from_sig x 7（恢复每层 WOTS 公钥/根）
 *        -> compute_root x 7    （沿认证路径算回子树根）
 *        -> 比较 root 是否等于公钥中的 root
 * ============================================================ */

/* ------------------------------------------------------------------
 * 仅用于“学习演示”的随机数发生器。
 * 使用 xorshift64* 伪随机序列，种子来自 time(NULL)。
 * 正式产品必须替换为操作系统/硬件提供的 CSPRNG。
 * ------------------------------------------------------------------ */
static uint64_t rng_state;
static int rng_initialized = 0;

static void randombytes(unsigned char *out, size_t outlen) {
    if (!rng_initialized) {
        rng_state = (uint64_t)time(NULL) ^ 0x9E3779B97F4A7C15ULL;
        if (rng_state == 0) {
            rng_state = 0x123456789ABCDEF0ULL;
        }
        rng_initialized = 1;
    }

    while (outlen > 0) {
        uint64_t r;
        size_t i, n;

        /* xorshift64* 一步 */
        rng_state ^= rng_state >> 12;
        rng_state ^= rng_state << 25;
        rng_state ^= rng_state >> 27;
        r = rng_state * 0x2545F4914F6CDD1DULL;

        n = (outlen < 8) ? outlen : 8;
        for (i = 0; i < n; i++) {
            out[i] = (unsigned char)(r >> (8 * i));
        }
        out += n;
        outlen -= n;
    }
}

/* 内部：由 48 字节种子生成密钥对（把随机源与算法逻辑分离，便于学习） */
static int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                    const unsigned char *seed) {
    spx_ctx ctx;

    /* 私钥前 48 字节直接来自种子：
     *   SK.seed(16) || SK.prf(16) || PK.seed(16)
     */
    memcpy(sk, seed, SPX_SEED_BYTES);

    /* 公钥第一部分：PK.seed = 种子最后 16 字节 */
    memcpy(pk, sk + (2 * SPX_N), SPX_N);

    /* 准备哈希上下文：pub_seed 与 sk_seed */
    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);

    /* 生成最顶层子树根，写入私钥尾部 [48..63] */
    merkle_gen_root(sk + (3 * SPX_N), &ctx);

    /* 公钥第二部分：root */
    memcpy(pk + SPX_N, sk + (3 * SPX_N), SPX_N);

    return 0;
}

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    unsigned char seed[SPX_SEED_BYTES];

    if (pk == NULL || sk == NULL) {
        return -1;
    }

    randombytes(seed, SPX_SEED_BYTES);
    return crypto_sign_seed_keypair(pk, sk, seed);
}

/* 内部：生成“分离式签名”（只含签名，不含消息） */
static int crypto_sign_signature(unsigned char *sig, size_t *siglen,
                                 const unsigned char *m, size_t mlen,
                                 const unsigned char *sk) {
    spx_ctx ctx;

    const unsigned char *sk_prf = sk + SPX_N;        /* SK.prf */
    const unsigned char *pk = sk + (2 * SPX_N);      /* 嵌入私钥的公钥 */

    unsigned char optrand[SPX_N];                    /* 可选随机化值 */
    unsigned char mhash[SPX_FORS_MSG_BYTES];         /* H_msg 的 FORS 部分 */
    unsigned char root[SPX_N];                       /* 层间传递的“消息/根” */
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* 1. 生成 OptRand，并计算 R = PRF_msg(SK.prf, OptRand || M) */
    randombytes(optrand, SPX_N);
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    /* 2. H_msg(R, PK, M) -> (FORS 摘要, 超树地址 tree, 叶子编号 idx_leaf) */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* 3. FORS 签名，签的是 mhash；输出 FORS 公钥 root */
    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* 4. 自底向上逐层做 Merkle 超树签名（共 d 层） */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        /* 对当前层子树根 root 做 WOTS+ 签名 + 生成认证路径 */
        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* 更新到上一层：低 9 位作为新的叶子编号，其余作为新的树地址 */
        idx_leaf = (uint32_t)(tree & ((1ULL << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;
    return 0;
}

/* 内部：验证分离式签名 */
static int crypto_sign_verify(const unsigned char *sig, size_t siglen,
                              const unsigned char *m, size_t mlen,
                              const unsigned char *pk) {
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);
    /* 验证只用 pub_seed；sk_seed 不参与验证，清零以避免读到未初始化内容 */
    memset(ctx.sk_seed, 0, SPX_N);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* 1. 恢复 FORS 摘要、树地址、叶子编号 */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* 2. 从 FORS 签名恢复 FORS 公钥 root */
    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* 3. 自底向上逐层恢复子树根 */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* 3a. 从 WOTS 签名恢复 WOTS 公钥（把 root 当作 WOTS 消息） */
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* 3b. L-tree 压缩得到 Merkle 叶子 */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* 3c. 沿认证路径计算该子树根 */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* 更新到上一层 */
        idx_leaf = (uint32_t)(tree & ((1ULL << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* 4. 比较最终根与公钥中的 root */
    if (memcmp(root, pub_root, SPX_N) != 0) {
        return -1;
    }
    return 0;
}

int crypto_sign(unsigned char *sm, size_t *smlen,
                const unsigned char *m, size_t mlen,
                const unsigned char *sk) {
    size_t siglen = 0;

    if (sm == NULL || smlen == NULL || sk == NULL) {
        return -1;
    }
    if (mlen > 0 && m == NULL) {
        return -1;
    }

    /* 先写分离式签名到 sm 开头，再把消息拼接到签名后面 */
    crypto_sign_signature(sm, &siglen, m, mlen, sk);
    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;
    return 0;
}

int crypto_sign_open(unsigned char *m, size_t *mlen,
                     const unsigned char *sm, size_t smlen,
                     const unsigned char *pk) {
    if (m == NULL || mlen == NULL || sm == NULL || pk == NULL) {
        return -1;
    }

    if (smlen < SPX_BYTES) {
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, *mlen, pk)) {
        *mlen = 0;
        return -1;
    }

    /* 验证成功，把签名后面的消息移回输出缓冲区 */
    memmove(m, sm + SPX_BYTES, *mlen);
    return 0;
}
