//
// Created by chenwenjing on 12/3/18.
//

#ifndef CRYPTO_TOOLS_SM3_TEST_H
#define CRYPTO_TOOLS_SM3_TEST_H


#include <stdint-gcc.h>

typedef struct _qinn_sm3_ctx {
    uint32_t digest[8];
    uint8_t block[64];
    uint32_t num;
    uint32_t nblocks;
} qinn_sm3_ctx;

int qinn_sm3_init(qinn_sm3_ctx *ctx);
int qinn_sm3_update(qinn_sm3_ctx *ctx, uint8_t *data, uint32_t data_len);
int qinn_sm3_final(qinn_sm3_ctx *ctx, uint8_t digest[32]);
void qinn_sm3_test();
void print_hex_1(uint32_t a);

#endif //CRYPTO_TOOLS_SM3_TEST_H
