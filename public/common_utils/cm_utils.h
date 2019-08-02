//
// Created by chenwenjing on 5/7/19.
//

#ifndef CRYPTO_TOOLS_CM_UTILS_H
#define CRYPTO_TOOLS_CM_UTILS_H

#include <stdint.h>
#include <stddef.h>

#define CM_SUCCESS             0X00000001

uint32_t cm_bin2hex(uint8_t *in, size_t len, char **out);
uint32_t cm_hex2bin(char *in, uint8_t **out, uint32_t *outlen);

int cm_read_bin_file(char *path, uint8_t **data, int *data_len);

int cm_read_str_file(char *path, uint8_t **data, int *data_len);

int cm_is_number(const char *str);

int cm_write_str_file(char *path, char *data);

#endif //CRYPTO_TOOLS_CM_UTILS_H
