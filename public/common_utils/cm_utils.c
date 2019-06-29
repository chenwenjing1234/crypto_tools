//
// Created by chenwenjing on 5/7/19.
//

#include "cm_utils.h"
#include <openssl/bn.h>

#include <stdio.h>

uint32_t cm_bin2hex(uint8_t *in, size_t len, char **out) {
    char *buf = NULL;

    buf = (char*)calloc(2 * len + 1, 1);
    if (buf == NULL) {
        return 1;
    }
    for (int i = 0; i < len; i++) {
        sprintf(buf + i * 2, "%02x", in[i]);
    }
    buf[2*len] = '\0';
    *out = buf;
    return 0;
}

uint32_t cm_hex2bin(char *in, uint8_t **out, uint32_t *outlen) {
    BIGNUM *bn = NULL;
    int len;
    uint32_t ret = 1;
    uint8_t *buf = NULL;

    len = BN_hex2bn(&bn, in);

    buf = (uint8_t*)calloc(len, 1);
    if (buf == NULL) {
        goto end;
    }
    len = BN_bn2bin(bn, buf);
    *out = buf;
    *outlen = (uint32_t)len;
    ret = 0;
end:
    BN_free(bn);
    if (ret != 0 && buf != NULL) {
        free(buf);
    }
    return ret;
}
