#ifndef SPX_THASH_H
#define SPX_THASH_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "sha256.h"

/*
 * thash：可调整哈希函数（tweakable hash）。
 * robust 变体：先用 MGF1-SHA256 生成位掩码，再对输入逐字节异或掩码。
 * 对应 FIPS 205 中的 T_l / F / H 底层原语。
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);

/*
 * prf_addr：PRF(pk_seed, sk_seed, addr) = SHA-256(pk_seed || addr[0..21] || sk_seed)
 * 用于从私钥种子派生 WOTS+/FORS 的一次性私钥。
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx, const uint32_t addr[8]);

/*
 * mgf1_256：基于 SHA-256 的 MGF1 掩码生成函数。
 * out = SHA-256(in || 0) || SHA-256(in || 1) || ... 截断到 outlen 字节。
 */
void mgf1_256(unsigned char *out, unsigned long outlen,
              const unsigned char *in, unsigned long inlen);

/*
 * gen_message_random：PRF_msg，用 HMAC-SHA256 生成消息随机化值 R。
 * R = HMAC-SHA256(key = SK.prf, data = OptRand || M) 截断到 n 字节。
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, size_t mlen,
                        const spx_ctx *ctx);

/*
 * hash_message：H_msg，生成消息摘要、超树索引 tree 与叶子索引 leaf_idx。
 * 输出 digest 为 FORS 消息部分（SPX_FORS_MSG_BYTES 字节）。
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, size_t mlen,
                  const spx_ctx *ctx);

#endif
