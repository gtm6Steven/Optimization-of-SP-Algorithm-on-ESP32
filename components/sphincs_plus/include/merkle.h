#ifndef SPX_MERKLE_H
#define SPX_MERKLE_H

#include <stdint.h>

#include "params.h"

/* ============================================================
 * merkle.h：Merkle 超树 + 地址结构 + 字节序工具
 *
 * 本文件把 PQClean 中拆散在 address.c / utils.c / merkle.c
 * 的“基础设施”合并到一起，便于学习：
 *   1. 大端序字节转换（地址字段必须按大端序写入）
 *   2. ADRS 地址字段读写（layer / tree / type / keypair / chain / hash / height / index）
 *   3. Merkle 树 TreeHash 算法
 *   4. 由叶子 + 认证路径恢复根节点
 *   5. 顶层接口 merkle_sign / merkle_gen_root
 * ============================================================ */

/* ---------------- 字节序转换 ---------------- */

/* 把 uint32_t 按 4 字节大端序写入 out（地址里的 tree_index 等字段需要） */
void u32_to_bytes(unsigned char *out, uint32_t in);

/* 把 unsigned long long 按 outlen 字节大端序写入 out（tree 字段需要 8 字节） */
void ull_to_bytes(unsigned char *out, unsigned int outlen, unsigned long long in);

/* 把 in 的前 inlen 字节按大端序解释为整数 */
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen);

/* ---------------- ADRS 地址字段工具 ----------------
 * SPHINCS+ 的 ADRS 是 32 字节（uint32_t addr[8]），
 * 但 SHA2 系列实际只使用前 22 字节参与哈希。
 * 这些函数都直接操作 addr 的原始字节，保证与 PQClean 完全一致。
 */

/* 设置层号 layer（字节 0） */
void set_layer_addr(uint32_t addr[8], uint32_t layer);

/* 设置树地址 tree（字节 1..8，共 8 字节大端序） */
void set_tree_addr(uint32_t addr[8], uint64_t tree);

/* 设置地址类型/域分隔 type（字节 9） */
void set_type(uint32_t addr[8], uint32_t type);

/* 只复制 layer + tree 字段（字节 0..8），用于同棵子树的不同用途 */
void copy_subtree_addr(uint32_t out[8], const uint32_t in[8]);

/* 设置 OTS 密钥对编号 keypair（字节 12、13） */
void set_keypair_addr(uint32_t addr[8], uint32_t keypair);

/* 设置 WOTS 链编号 chain（字节 17） */
void set_chain_addr(uint32_t addr[8], uint32_t chain);

/* 设置 WOTS 链内位置 hash（字节 21） */
void set_hash_addr(uint32_t addr[8], uint32_t hash);

/* 复制 layer + tree + keypair 字段 */
void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]);

/* 设置 Merkle/FORS 树节点高度 tree_height（字节 17） */
void set_tree_height(uint32_t addr[8], uint32_t tree_height);

/* 设置 Merkle/FORS 树节点索引 tree_index（字节 18..21） */
void set_tree_index(uint32_t addr[8], uint32_t tree_index);

/* ---------------- Merkle 树算法 ---------------- */

/* gen_leaf 回调：给定全局叶子编号 addr_idx，生成 n 字节叶子值。
 * 这里统一定义成与 wots_gen_leaf / fors_gen_leaf 一致的函数指针类型。
 */
typedef void (*spx_gen_leaf_fn)(unsigned char *leaf,
                                const spx_ctx *ctx,
                                uint32_t addr_idx,
                                const uint32_t tree_addr[8]);

/*
 * TreeHash 算法（对应 SPHINCS+ 论文 / FIPS 205 的 TreeHash 流程）：
 * 输入层高 tree_height，生成 2^tree_height 个叶子，
 * 输出树根 root，并收集 leaf_idx 对应的认证路径 auth_path。
 * gen_leaf 用于生成叶子；idx_offset 用于跨树的叶子编号偏移。
 * 本实现与 PQClean utils.c 的 treehash 逐行等价。
 */
void treehash(unsigned char *root, unsigned char *auth_path,
              const spx_ctx *ctx,
              uint32_t leaf_idx, uint32_t idx_offset,
              uint32_t tree_height,
              spx_gen_leaf_fn gen_leaf,
              uint32_t tree_addr[8]);

/*
 * 由叶子 leaf 与认证路径 auth_path 计算根节点 root。
 * leaf_idx 是本层相对叶子编号，idx_offset 是跨树偏移，
 * tree_height 是树高。对应验证阶段从签名一路算回根的过程。
 */
void compute_root(unsigned char *root, const unsigned char *leaf,
                  uint32_t leaf_idx, uint32_t idx_offset,
                  const unsigned char *auth_path, uint32_t tree_height,
                  const spx_ctx *ctx, uint32_t addr[8]);

/*
 * 生成某一棵 Merkle 子树的签名：
 *   sig 的前 SPX_WOTS_BYTES 字节写 WOTS+ 签名，
 *   后面 SPX_TREE_HEIGHT * SPX_N 字节写认证路径。
 * root 是该子树的输入消息（上层 FORS 公钥或下层子树根）。
 * idx_leaf == ~0U 时只计算根、不生成 WOTS 签名（用于密钥生成）。
 */
void merkle_sign(unsigned char *sig, unsigned char *root,
                 const spx_ctx *ctx,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf);

/*
 * 生成最顶层（第 d-1 层）子树的根节点，即 SPHINCS+ 公钥中的 root。
 */
void merkle_gen_root(unsigned char *root, const spx_ctx *ctx);

#endif
