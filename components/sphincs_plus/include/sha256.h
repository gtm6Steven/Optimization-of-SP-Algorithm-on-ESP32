#ifndef SPX_SHA256_H
#define SPX_SHA256_H

#include <stddef.h>
#include <stdint.h>

/*
 * SHA-256 增量式上下文。
 * 纯软件实现，栈上分配，不依赖任何硬件加速指令。
 */
typedef struct {
    uint32_t state[8]; /* 8 个 32 位工作变量（a..h） */
    uint64_t bytes;    /* 已通过 inc_blocks 吸收的字节数 */
} sha256ctx;

/* 初始化上下文：加载 FIPS 180-4 规定的初始哈希值 */
void sha256_inc_init(sha256ctx *state);

/* 吸收整数个 64 字节分组 */
void sha256_inc_blocks(sha256ctx *state, const uint8_t *in, size_t inblocks);

/* 吸收最后 inlen 个字节，做填充、追加长度并输出 32 字节摘要 */
void sha256_inc_finalize(uint8_t *out, sha256ctx *state, const uint8_t *in, size_t inlen);

/* 一次性 SHA-256：out 至少 32 字节 */
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

#endif
