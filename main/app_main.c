#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sphincsplus.h"

/* ============================================================
 * SPHINCS+-SHA2-128s 软件基线基准测试驱动
 * 不修改算法，只循环调用：
 *   crypto_sign_keypair()
 *   crypto_sign()
 *   crypto_sign_open()
 * ============================================================ */

#define BENCH_MESSAGE              "Hello SPHINCS+ Learning"
#define BENCH_MESSAGE_LEN          (sizeof(BENCH_MESSAGE) - 1)
#define BENCH_SM_BUF_SIZE          (SPX_BYTES + BENCH_MESSAGE_LEN)
#define BENCH_RECOVERED_BUF_SIZE   BENCH_MESSAGE_LEN

/* 循环次数。注意：128s 单次签名约 174 秒，请按实验预算修改。 */
#define BENCH_ITERATIONS           3

typedef struct {
    uint64_t sum;
    uint64_t min;
    uint64_t max;
    uint32_t count;
} bench_stat_t;

static void bench_stat_init(bench_stat_t *st) {
    st->sum = 0;
    st->min = UINT64_MAX;
    st->max = 0;
    st->count = 0;
}

static void bench_stat_add(bench_stat_t *st, uint64_t us) {
    st->sum += us;
    st->min = (us < st->min) ? us : st->min;
    st->max = (us > st->max) ? us : st->max;
    st->count++;
}

static uint64_t bench_stat_avg(const bench_stat_t *st) {
    return st->count ? (st->sum / st->count) : 0;
}

static void bench_stat_print(const char *name, const bench_stat_t *st) {
    printf("%-18s n=%3u  avg=%12llu us  min=%12llu us  max=%12llu us\n",
           name,
           (unsigned)st->count,
           (unsigned long long)bench_stat_avg(st),
           (unsigned long long)st->min,
           (unsigned long long)st->max);
}

void app_main(void) {
    static uint8_t pk[SPX_PK_BYTES];
    static uint8_t sk[SPX_SK_BYTES];
    static uint8_t sm[BENCH_SM_BUF_SIZE];
    static uint8_t sm_bad[BENCH_SM_BUF_SIZE];
    static uint8_t recovered[BENCH_RECOVERED_BUF_SIZE];
    static const uint8_t message[BENCH_MESSAGE_LEN] = BENCH_MESSAGE;

    bench_stat_t keypair_stat;
    bench_stat_t sign_stat;
    bench_stat_t verify_stat;

    bool failed = false;
    uint32_t failed_iter = 0;
    uint32_t heap_min_sample = UINT32_MAX;

    bench_stat_init(&keypair_stat);
    bench_stat_init(&sign_stat);
    bench_stat_init(&verify_stat);

    printf("\n");
    printf("====================================================\n");
    printf(" SPHINCS+-SHA2-128s Software Baseline Benchmark\n");
    printf("====================================================\n");
    printf("iterations=%u\n", (unsigned)BENCH_ITERATIONS);
    printf("message_len=%u\n", (unsigned)BENCH_MESSAGE_LEN);
    printf("pk_bytes=%d sk_bytes=%d sig_bytes=%d\n",
           SPX_PK_BYTES, SPX_SK_BYTES, SPX_BYTES);
    printf("warning: sign may take about 3 minutes per iteration\n");
    printf("----------------------------------------------------\n");

    for (uint32_t i = 0; i < BENCH_ITERATIONS; ++i) {
        size_t smlen = 0;
        size_t recovered_len = 0;
        int64_t t0, t1;

        /* 每轮重置缓冲区，保证状态独立 */
        memset(pk, 0, sizeof(pk));
        memset(sk, 0, sizeof(sk));
        memset(sm, 0, sizeof(sm));
        memset(sm_bad, 0, sizeof(sm_bad));
        memset(recovered, 0, sizeof(recovered));

        /* 1. 密钥生成 */
        t0 = esp_timer_get_time();
        if (crypto_sign_keypair(pk, sk) != 0) {
            failed = true;
            failed_iter = i;
            break;
        }
        t1 = esp_timer_get_time();
        bench_stat_add(&keypair_stat, (uint64_t)(t1 - t0));

        /* 2. 签名 */
        t0 = esp_timer_get_time();
        if (crypto_sign(sm, &smlen, message, BENCH_MESSAGE_LEN, sk) != 0) {
            failed = true;
            failed_iter = i;
            break;
        }
        t1 = esp_timer_get_time();
        bench_stat_add(&sign_stat, (uint64_t)(t1 - t0));

        if (smlen > sizeof(sm) || smlen <= SPX_BYTES) {
            failed = true;
            failed_iter = i;
            break;
        }

        /* 3. 正常验签 */
        t0 = esp_timer_get_time();
        int ok = crypto_sign_open(recovered, &recovered_len, sm, smlen, pk);
        t1 = esp_timer_get_time();
        bench_stat_add(&verify_stat, (uint64_t)(t1 - t0));

        if (ok != 0 ||
            recovered_len != BENCH_MESSAGE_LEN ||
            recovered_len > sizeof(recovered) ||
            memcmp(recovered, message, BENCH_MESSAGE_LEN) != 0) {
            failed = true;
            failed_iter = i;
            break;
        }

        /* 4. 负向校验：篡改消息首字节，验签必须失败 */
        memcpy(sm_bad, sm, smlen);
        sm_bad[SPX_BYTES] ^= 0x01U;
        recovered_len = 0;

        if (crypto_sign_open(recovered, &recovered_len, sm_bad, smlen, pk) == 0) {
            failed = true;
            failed_iter = i;
            break;
        }

        /* 循环内不打印，只采样当前内部堆剩余内存 */
        uint32_t free_now = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        if (free_now < heap_min_sample) {
            heap_min_sample = free_now;
        }
    }

    if (failed) {
        printf("[FAIL] iteration %u: crypto operation failed or tampered signature verified\n",
               (unsigned)failed_iter);
    } else {
        printf("[PASS] all %u iterations passed\n", (unsigned)BENCH_ITERATIONS);
    }

    printf("----------------------------------------------------\n");
    bench_stat_print("keypair", &keypair_stat);
    bench_stat_print("sign", &sign_stat);
    bench_stat_print("verify", &verify_stat);

    printf("----------------------------------------------------\n");
    printf("heap_min_sample_internal=%u bytes\n", (unsigned)heap_min_sample);
    printf("heap_min_since_boot_internal=%u bytes\n",
           (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    printf("heap_free_now_internal=%u bytes\n",
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));

    UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
    printf("main_task_stack_hwm=%u bytes\n",
           (unsigned)(hwm * sizeof(StackType_t)));

    printf("====================================================\n");
}