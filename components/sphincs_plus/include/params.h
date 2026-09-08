#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H

#include <stdint.h>

/* ============================================================
 * SPHINCS+-SHA2-128s (robust) 参数集
 * 严格对齐 NIST FIPS 205 与 PQClean 官方实现
 * ============================================================ */

/* n：哈希输出字节数（对应 128 比特安全级别） */
#define SPX_N 16

/* h：超树（hypertree）总高度 */
#define SPX_FULL_HEIGHT 63

/* d：超树层数 */
#define SPX_D 7

/* FORS 森林参数：每棵树高度 k、树的数量 t */
#define SPX_FORS_HEIGHT 12
#define SPX_FORS_TREES 14

/* WOTS+ 的 Winternitz 参数 w = 16 */
#define SPX_WOTS_W 16

/* log2(w) = 4 */
#define SPX_WOTS_LOGW 4

/* WOTS+ len1 = 8*n/log2(w) = 32（消息被拆成的 base-w 位数） */
#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

/* WOTS+ len2 = 3（校验和位数，按公式预计算） */
#define SPX_WOTS_LEN2 3

/* WOTS+ 链总长度 = len1 + len2 = 35 */
#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)

/* WOTS+ 签名/公钥字节数 = 35 * 16 = 560 */
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* 每棵子树高度 = h/d = 63/7 = 9 */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

/* FORS 消息摘要字节数 = ceil(k*t/8) = ceil(168/8) = 21 */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)

/* FORS 签名字节数 = (k+1)*t*n = 13*14*16 = 2912 */
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* ADRS 地址结构总字节数 */
#define SPX_ADDR_BYTES 32

/* 总签名字节数 = R(16) + FORS(2912) + d*WOTS(7*560) + h*n(1008) = 7856 */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)

/* 公钥字节数 = 公钥种子(16) + 根(16) = 32 */
#define SPX_PK_BYTES (2 * SPX_N)

/* 私钥字节数 = 私钥种子(16) + PRF种子(16) + 公钥(32) = 64 */
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* 生成密钥对所需的随机种子字节数 = 3*n = 48 */
#define SPX_SEED_BYTES (3 * SPX_N)

/* ---------------- SHA-256 相关常量 ---------------- */
#define SPX_SHA256_BLOCK_BYTES 64
#define SPX_SHA256_OUTPUT_BYTES 32

/* SPHINCS+ 中实际参与哈希的地址前缀字节数（SHA2 系列只使用前 22 字节） */
#define SPX_SHA256_ADDR_BYTES 22

/* ---------------- ADRS 地址结构中各字段的字节偏移 ---------------- */
#define SPX_OFFSET_LAYER       0  /* 层号 */
#define SPX_OFFSET_TREE        1  /* 树地址（8 字节大端） */
#define SPX_OFFSET_TYPE        9  /* 地址类型（域分隔） */
#define SPX_OFFSET_KP_ADDR2    12 /* OTS 密钥对地址高字节 */
#define SPX_OFFSET_KP_ADDR1    13 /* OTS 密钥对地址低字节 */
#define SPX_OFFSET_CHAIN_ADDR  17 /* WOTS 链地址（或树节点高度） */
#define SPX_OFFSET_HASH_ADDR   21 /* WOTS 哈希地址（或树节点索引一部分） */
#define SPX_OFFSET_TREE_HGT    17 /* 树节点高度（与 CHAIN_ADDR 同字节） */
#define SPX_OFFSET_TREE_INDEX  18 /* 树节点索引（4 字节大端） */

/* ---------------- 地址类型（用于域分隔，防止不同用途哈希碰撞） ---------------- */
#define SPX_ADDR_TYPE_WOTS     0  /* WOTS 哈希链 */
#define SPX_ADDR_TYPE_WOTSPK   1  /* WOTS 公钥压缩（L-tree） */
#define SPX_ADDR_TYPE_HASHTREE 2  /* Merkle 超树节点 */
#define SPX_ADDR_TYPE_FORSTREE 3  /* FORS 树节点 */
#define SPX_ADDR_TYPE_FORSPK   4  /* FORS 根压缩 */
#define SPX_ADDR_TYPE_WOTSPRF  5  /* WOTS 私钥 PRF */
#define SPX_ADDR_TYPE_FORSPRF  6  /* FORS 私钥 PRF */

/* ---------------- 哈希上下文：持有公钥种子与私钥种子 ---------------- */
typedef struct {
    uint8_t pub_seed[SPX_N]; /* 公钥种子 PK.seed，参与所有 thash/PRF 计算 */
    uint8_t sk_seed[SPX_N];  /* 私钥种子 SK.seed，仅参与 prf_addr 计算 */
} spx_ctx;

#endif
