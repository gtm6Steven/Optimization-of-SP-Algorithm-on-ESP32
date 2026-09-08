#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>

#include "params.h"

/*
 * chain_lengths：把 n 字节消息解释为 base-w 序列，并追加 base-w 校验和。
 * 输出长度为 SPX_WOTS_LEN 的链长度数组。
 */
void chain_lengths(uint32_t *lengths, const unsigned char *msg);

/* WOTS+ 公钥生成：对每个链从私钥元素迭代 w-1 次 thash。 */
void wots_pk_gen(unsigned char *pk, const spx_ctx *ctx, uint32_t addr[8]);

/* WOTS+ 签名：按链长度对每个私钥元素迭代对应次数。 */
void wots_sign(unsigned char *sig, const unsigned char *msg,
               const spx_ctx *ctx, uint32_t addr[8]);

/* 由 WOTS+ 签名恢复公钥（验证用）。 */
void wots_pk_from_sig(unsigned char *pk, const unsigned char *sig,
                      const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8]);

/* 计算 Merkle 超树叶子：WOTS 公钥的 L-tree 压缩。 */
void wots_gen_leaf(unsigned char *leaf, const spx_ctx *ctx, uint32_t addr_idx,
                   const uint32_t tree_addr[8]);

#endif
