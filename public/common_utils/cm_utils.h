//
// Created by chenwenjing on 5/7/19.
//

#ifndef CRYPTO_TOOLS_CM_UTILS_H
#define CRYPTO_TOOLS_CM_UTILS_H

#include <stdint.h>
#include <stddef.h>

uint32_t cm_bin2hex(uint8_t *in, size_t len, char **out);
uint32_t cm_hex2bin(char *in, uint8_t **out, uint32_t *outlen);

#endif //CRYPTO_TOOLS_CM_UTILS_H
