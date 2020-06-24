//
// Created by chenwenjing on 5/7/19.
//

#include "cm_utils.h"
#include <openssl/bn.h>

#include <stdio.h>
#include <memory.h>
#include <ctype.h>

uint32_t cm_bin2hex(uint8_t *in, size_t len, char **out) {
    char *buf = NULL;

    buf = (char*)calloc(2 * len + 1, 1);
    if (buf == NULL) {
        return 0;
    }
    for (int i = 0; i < len; i++) {
        sprintf(buf + i * 2, "%02x", in[i]);
    }
    buf[2*len] = '\0';
    *out = buf;
    return CM_SUCCESS;
}

uint32_t cm_hex2bin(char *in, uint8_t **out, uint32_t *outlen) {
    BIGNUM *bn = NULL;
    int len;
    uint32_t ret = 0;
    uint8_t *buf = NULL;

    len = BN_hex2bn(&bn, in);

    buf = (uint8_t*)calloc(len, 1);
    if (buf == NULL) {
        goto end;
    }
    len = BN_bn2bin(bn, buf);
    *out = buf;
    *outlen = (uint32_t)len;
    ret = CM_SUCCESS;
end:
    BN_free(bn);
    if (ret != CM_SUCCESS && buf != NULL) {
        free(buf);
    }
    return ret;
}

int cm_read_bin_file(char *path, uint8_t **data, int *data_len) {
    int ret = 0;
    FILE *fp = NULL;
    uint8_t *buf = NULL;
    long file_len = 0;

    if (path == NULL || data == NULL || data_len == NULL) {
        return 0;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buf = (uint8_t*)calloc((size_t)file_len, 1);
    if (buf == NULL) {
        goto end;
    }

    fread(buf, 1, (size_t)file_len, fp);

    *data = buf;
    *data_len = (int)file_len;

    ret = CM_SUCCESS;

end:
    if (ret != CM_SUCCESS && buf != NULL) {
        free(buf);
    }
    fclose(fp);
    return ret;
}

int cm_read_str_file(char *path, uint8_t **data, int *data_len) {

    int ret = 0;
    FILE *fp = NULL;
    uint8_t *buf = NULL;
    long file_len = 0;

    if (path == NULL || data == NULL || data_len == NULL) {
        return 0;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buf = (uint8_t*)calloc((size_t)file_len + 1, 1);
    if (buf == NULL) {
        goto end;
    }

    fread(buf, 1, (size_t)file_len, fp);
    if (buf[file_len-1] == '\n') {
        buf[file_len-1] = '\0';
    } else {
        buf[file_len] = '\0';
    }

    *data = buf;
    *data_len = (int)file_len;

    ret = CM_SUCCESS;

end:
    if (ret != CM_SUCCESS && buf != NULL) {
        free(buf);
    }
    fclose(fp);
    return ret;
}

int cm_is_number(const char *str)
{
    size_t i = 0;
    size_t len = 0;

    len = strlen(str);
    for (i = 0; i < len; ++i) {
        if (!isdigit(str[i])) {
            return 0;
        }
    }
    return CM_SUCCESS;
}


int cm_write_str_file(char *path, char *data) {
    int ret = 0;
    FILE *fp = NULL;

    if (path == NULL || data == NULL) {
        return 0;
    }

    fp = fopen(path, "w+");
    if (fp == NULL) {
        return 0;
    }

    fwrite(data, 1, strlen(data), fp);

    ret = CM_SUCCESS;

    fclose(fp);
    return ret;
}