#ifndef SPX_SPHINCS_H
#define SPX_SPHINCS_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

/* ============================================================
 * sphincsplus.h：SPHINCS+ 顶层三大接口
 *
 * 私钥格式（共 SPX_SK_BYTES = 64 字节）：
 *   [ SK.seed(16) || SK.prf(16) || PK.seed(16) || root(16) ]
 *
 * 公钥格式（共 SPX_PK_BYTES = 32 字节）：
 *   [ PK.seed(16) || root(16) ]
 *
 * 签名长度固定为 SPX_BYTES = 7856 字节。
 * ============================================================ */

/*
 * 功能：生成 SPHINCS+-SHA2-128s 密钥对。
 * 输入：pk  输出公钥缓冲区（至少 SPX_PK_BYTES 字节）
 *       sk  输出私钥缓冲区（至少 SPX_SK_BYTES 字节）
 * 返回：0 成功；非 0 失败。
 * 对应理论：SPHINCS+ KeyGen 流程。
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/*
 * 功能：对消息 m 生成签名，结果按“签名 || 消息”拼接写入 sm。
 * 输入：m     待签名消息
 *       mlen  m 的字节长度
 *       sk    私钥（SPX_SK_BYTES 字节）
 * 输出：sm    签名+消息（至少 SPX_BYTES + mlen 字节）
 *       smlen 实际写入长度 = SPX_BYTES + mlen
 * 返回：0 成功；非 0 失败。
 * 对应理论：SPHINCS+ Sign 流程。
 */
int crypto_sign(unsigned char *sm, size_t *smlen,
                const unsigned char *m, size_t mlen,
                const unsigned char *sk);

/*
 * 功能：验证“签名 || 消息”，验证通过时把消息写回 m。
 * 输入：sm    签名+消息
 *       smlen sm 的字节长度
 *       pk    公钥（SPX_PK_BYTES 字节）
 * 输出：m     验证通过后恢复出的消息
 *       mlen  恢复出的消息字节长度
 * 返回：0 验证通过；-1 验证失败。
 * 对应理论：SPHINCS+ Verify 流程。
 */
int crypto_sign_open(unsigned char *m, size_t *mlen,
                     const unsigned char *sm, size_t smlen,
                     const unsigned char *pk);

#endif
