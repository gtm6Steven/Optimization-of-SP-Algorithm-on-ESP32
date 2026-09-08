#ifndef SPX_FORS_H
#define SPX_FORS_H

#include <stdint.h>

#include "params.h"

/*
 * FORS（少量次签名）签名：对消息摘要 m 中每个 k 比特索引，
 * 输出对应叶子的秘密值与认证路径，并横向哈希得到 FORS 公钥 pk。
 * m 至少包含 SPX_FORS_HEIGHT * SPX_FORS_TREES 比特。
 */
void fors_sign(unsigned char *sig, unsigned char *pk, const unsigned char *m,
               const spx_ctx *ctx, const uint32_t fors_addr[8]);

/* 由 FORS 签名恢复 FORS 公钥（验证用）。 */
void fors_pk_from_sig(unsigned char *pk, const unsigned char *sig,
                      const unsigned char *m,
                      const spx_ctx *ctx, const uint32_t fors_addr[8]);

#endif
