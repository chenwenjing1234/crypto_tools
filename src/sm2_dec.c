//
// Created by chenwenjing on 6/11/19.
//
#include <stdio.h>
#include <cm_utils.h>
#include <string.h>
#include <cp_sm2.h>
#include <stdlib.h>
#include "ca_define.h"
#include "cp_defines.h"

//crypto_tools sm2_dec -prikey xx -cipher xx

int sm2_dec_main(int argc, char *argv[]) {
    int ret = 1;
    uint64_t ret_code;
    char *cipher_hex = NULL;
    char *prikey_hex = NULL;
    int index = 2;
    uint8_t *prikey_bin = NULL;
    uint32_t prikey_bin_len = 0;
    uint8_t *cipher_bin = NULL;
    uint32_t cipher_bin_len = 0;
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    char *plain_hex = NULL;

    if (argc < 6) {
        printf("input arguments invalid, example as flow:\n");
        printf("  crypto_tools sm2_dec -prikey xx -cipher xx\n");
        return 1;
    }

    while(index < 5){
        for(;;){
            if (strcmp(OPT_PRIKEY, argv[index]) == 0) {
                prikey_hex = argv[++index];
                break;
            }
            if (strcmp(OPT_CIPHER, argv[index]) == 0) {
                cipher_hex = argv[++index];
                break;
            }
            ++index;
            break;
        }
    }

    if (0x00 != cm_hex2bin(prikey_hex, &prikey_bin, &prikey_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }
    if (0x00 != cm_hex2bin(cipher_hex, &cipher_bin, &cipher_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }

    ret_code = cp_sm2_dec(prikey_bin, prikey_bin_len, cipher_bin, cipher_bin_len,
                          &plain, &plain_len);
    if (ret_code != CP_SUCCESS) {
        printf("sm2 decrypt failed, ret = %lx", ret_code);
        goto end;
    }

    if (0x00 != cm_bin2hex(plain, plain_len, &plain_hex)) {
        printf("convert bin to hex failed\n");
        goto end;
    }
    ret = 0;
    printf("plain: %s\n", plain_hex);
    end:
    if (prikey_bin != NULL) {
        free(prikey_bin);
    }
    if (cipher_bin != NULL) {
        free(cipher_bin);
    }
    if (plain != NULL) {
        free(plain);
    }
    if (plain_hex != NULL) {
        free(plain_hex);
    }
    return ret;
}



