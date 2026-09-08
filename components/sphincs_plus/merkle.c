#include <string.h>

#include "merkle.h"
#include "thash.h"
#include "wots.h"

/* ============================================================
 * merkle.c 实现说明
 *
 * 内容来源（均严格对齐 PQClean 官方实现）：
 *   - 字节序函数：utils.c
 *   - ADRS 字段函数：address.c
 *   - treehash / compute_root：utils.c
 *   - merkle_sign / merkle_gen_root：merkle.c
 *
 * 这里刻意不引入 PQClean 的 SHA-256 状态复用优化，
 * 让每一步哈希输入/输出都清晰可见，适合零基础阅读。
 * ============================================================ */

/* ---------------- 字节序转换 ---------------- */

void u32_to_bytes(unsigned char *out, uint32_t in) {
    /* 大端序：最高字节放在最前面 */
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

void ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in) {
    int i;

    /* 从最后一字节向前写，保证大端序 */
    for (i = (int)outlen - 1; i >= 0; i--) {
        out[i] = (unsigned char)(in & 0xffU);
        in = in >> 8;
    }
}

unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen) {
    unsigned long long retval = 0;
    unsigned int i;

    /* 从最高位字节开始累加 */
    for (i = 0; i < inlen; i++) {
        retval |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
    }
    return retval;
}

/* ---------------- ADRS 地址字段工具 ----------------
 * 地址是 uint32_t addr[8]（共 32 字节）。
 * SHA2 系列按“字节偏移”写字段，偏移定义见 params.h。
 */

void set_layer_addr(uint32_t addr[8], uint32_t layer) {
    /* layer 只需要低 1 字节 */
    ((unsigned char *)addr)[SPX_OFFSET_LAYER] = (unsigned char)layer;
}

void set_tree_addr(uint32_t addr[8], uint64_t tree) {
    /* tree 是 64 位，从地址字节 1 开始写 8 字节大端序 */
    ull_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE], 8, tree);
}

void set_type(uint32_t addr[8], uint32_t type) {
    /* type 是域分隔符，防止不同用途的哈希碰撞 */
    ((unsigned char *)addr)[SPX_OFFSET_TYPE] = (unsigned char)type;
}

void copy_subtree_addr(uint32_t out[8], const uint32_t in[8]) {
    /* 复制字节 0..8，即 layer(1 字节) + tree(8 字节) */
    memcpy(out, in, SPX_OFFSET_TREE + 8);
}

void set_keypair_addr(uint32_t addr[8], uint32_t keypair) {
    /* 底层叶子可能超过 256 个，因此 keypair 用两个字节表示 */
    ((unsigned char *)addr)[SPX_OFFSET_KP_ADDR2] = (unsigned char)(keypair >> 8);
    ((unsigned char *)addr)[SPX_OFFSET_KP_ADDR1] = (unsigned char)keypair;
}

void set_chain_addr(uint32_t addr[8], uint32_t chain) {
    /* WOTS 链编号，1 字节（WOTS_LEN=35 < 256） */
    ((unsigned char *)addr)[SPX_OFFSET_CHAIN_ADDR] = (unsigned char)chain;
}

void set_hash_addr(uint32_t addr[8], uint32_t hash) {
    /* WOTS 链内迭代位置，1 字节（w-1=15 < 256） */
    ((unsigned char *)addr)[SPX_OFFSET_HASH_ADDR] = (unsigned char)hash;
}

void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]) {
    /* 复制 layer + tree，再单独复制两个 keypair 字节 */
    memcpy(out, in, SPX_OFFSET_TREE + 8);
    ((unsigned char *)out)[SPX_OFFSET_KP_ADDR2] =
        ((unsigned char *)in)[SPX_OFFSET_KP_ADDR2];
    ((unsigned char *)out)[SPX_OFFSET_KP_ADDR1] =
        ((unsigned char *)in)[SPX_OFFSET_KP_ADDR1];
}

void set_tree_height(uint32_t addr[8], uint32_t tree_height) {
    /* 当前节点在 Merkle/FORS 树中的高度 */
    ((unsigned char *)addr)[SPX_OFFSET_TREE_HGT] = (unsigned char)tree_height;
}

void set_tree_index(uint32_t addr[8], uint32_t tree_index) {
    /* 当前节点在树中的水平位置，4 字节大端序 */
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE_INDEX], tree_index);
}

/* ---------------- TreeHash 算法 ----------------
 * 核心思想（与 PQClean utils.c 的 treehash 逐行等价）：
 *   1. 用一个“栈”保存尚未配对的左节点，heights 保存它们的高度。
 *   2. 逐个生成叶子（从 0 到 2^tree_height-1）。
 *   3. 每当栈顶两个节点高度相同，就把它们哈希成父节点。
 *   4. 需要时，把当前节点写入 auth_path（认证路径）。
 *   5. 全部叶子处理完后，栈里剩下的唯一节点就是树根。
 */

void treehash(unsigned char *root, unsigned char *auth_path,
              const spx_ctx *ctx,
              uint32_t leaf_idx, uint32_t idx_offset,
              uint32_t tree_height,
              spx_gen_leaf_fn gen_leaf,
              uint32_t tree_addr[8]) {
    /* stack 最多 tree_height+1 个 n 字节节点 */
    unsigned char stack[(tree_height + 1) * SPX_N];
    unsigned int heights[tree_height + 1];
    unsigned int offset = 0;   /* 当前栈里的节点数 */
    uint32_t idx;              /* 当前生成的叶子编号（相对本树） */
    uint32_t tree_idx;         /* 当前节点在更高层中的水平编号 */

    for (idx = 0; idx < (uint32_t)(1U << tree_height); idx++) {
        /* 1. 生成下一个叶子，压入栈顶 */
        gen_leaf(stack + (offset * SPX_N), ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* 2. 若这个叶子正好是认证路径上第一个节点，先保存它 */
        if ((leaf_idx ^ 0x1U) == idx) {
            memcpy(auth_path, stack + ((offset - 1) * SPX_N), SPX_N);
        }

        /* 3. 栈顶两个节点高度相等时，不断向上合并 */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* 新父节点在更高一层的水平编号 */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* 设置父节点地址：height + tree_index（含跨树偏移） */
            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                           tree_idx + (idx_offset >> (heights[offset - 1] + 1)));

            /* H(左 || 右)，结果就地写回栈的下层位置 */
            thash(stack + ((offset - 2) * SPX_N),
                  stack + ((offset - 2) * SPX_N), 2, ctx, tree_addr);
            offset--;
            /* 合并后，新栈顶节点高度 +1 */
            heights[offset - 1]++;

            /* 4. 判断新父节点是否属于认证路径 */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1U) == tree_idx) {
                memcpy(auth_path + (heights[offset - 1] * SPX_N),
                       stack + ((offset - 1) * SPX_N), SPX_N);
            }
        }
    }

    /* 全部叶子处理完，栈底就是根节点 */
    memcpy(root, stack, SPX_N);
}

/* ---------------- 由叶子 + 认证路径恢复根 ---------------- */

void compute_root(unsigned char *root, const unsigned char *leaf,
                  uint32_t leaf_idx, uint32_t idx_offset,
                  const unsigned char *auth_path, uint32_t tree_height,
                  const spx_ctx *ctx, uint32_t addr[8]) {
    uint32_t i;
    unsigned char buffer[2 * SPX_N];

    /* 第一步：把叶子和第一个路径节点按左右位置拼成 [left || right] */
    if (leaf_idx & 1) {
        /* 当前叶子是右孩子，认证节点在左边 */
        memcpy(buffer + SPX_N, leaf, SPX_N);
        memcpy(buffer, auth_path, SPX_N);
    } else {
        /* 当前叶子是左孩子，认证节点在右边 */
        memcpy(buffer, leaf, SPX_N);
        memcpy(buffer + SPX_N, auth_path, SPX_N);
    }
    auth_path += SPX_N;

    /* 中间 tree_height-1 层：每层一次 H(left||right) */
    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        if (leaf_idx & 1) {
            /* 当前节点是右孩子：哈希结果放到右半区，左半区取下一个路径节点 */
            thash(buffer + SPX_N, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N);
        } else {
            /* 当前节点是左孩子：哈希结果放到左半区，右半区取下一个路径节点 */
            thash(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N, auth_path, SPX_N);
        }
        auth_path += SPX_N;
    }

    /* 最后一层是特例：没有多余的认证路径节点可复制 */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash(root, buffer, 2, ctx, addr);
}

/* ---------------- Merkle 子树签名 / 根生成 ---------------- */

void merkle_sign(unsigned char *sig, unsigned char *root,
                 const spx_ctx *ctx,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf) {
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;

    /* 先生成该子树叶子对应的 WOTS+ 签名：
     *   sig[0 .. SPX_WOTS_BYTES-1]
     * 注意：密钥生成时 idx_leaf == ~0U，不需要 WOTS 签名。
     */
    if (idx_leaf != (uint32_t)~0U) {
        set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
        wots_sign(sig, root, ctx, wots_addr);
    }

    /* 再跑 TreeHash：得到子树根 + 认证路径。
     *   auth_path 写入 sig[SPX_WOTS_BYTES .. 末尾]
     * 因为 wots_gen_leaf 会按地址生成对应叶子，所以树根与签名自洽。
     */
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    treehash(root, auth_path, ctx,
             idx_leaf, 0, SPX_TREE_HEIGHT,
             wots_gen_leaf, tree_addr);
}

void merkle_gen_root(unsigned char *root, const spx_ctx *ctx) {
    /* 密钥生成不需要认证路径，但为了复用同一套 treehash 代码，
     * 仍给 auth_path 留够空间。idx_leaf 用 ~0U 表示“不收集路径/不签名”。
     */
    unsigned char auth_path[SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N];
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);

    merkle_sign(auth_path, root, ctx, wots_addr, top_tree_addr, ~0U);
}
