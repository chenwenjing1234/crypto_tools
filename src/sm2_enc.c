//
// Created by chenwenjing on 6/3/19.
//

#include <stdio.h>
#include <cm_utils.h>
#include <string.h>
#include <cp_sm2.h>
#include <stdlib.h>
#include "ca_define.h"
#include "cp_defines.h"

//crypto_tools sm2_enc -pubkey xx -plain xx

int sm2_enc_main(int argc, char *argv[]) {
    int ret = 1;
    uint64_t ret_code;
    char *plain_hex = NULL;
    char *pubkey_hex = NULL;
    int index = 2;
    uint8_t *pubkey_bin = NULL;
    uint32_t pubkey_bin_len = 0;
    uint8_t *plain_bin = NULL;
    uint32_t plain_bin_len = 0;
    uint8_t *cipher = NULL;
    size_t cipher_len = 0;
    char *cipher_hex = NULL;

    if (argc < 6) {
        printf("input arguments invalid, example as flow:\n");
        printf("  crypto_tools sm2_enc -pubkey xx -plain xx\n");
        return 1;
    }

    while(index < 5){
        for(;;){
            if (strcmp(OPT_PUBKEY, argv[index]) == 0) {
                pubkey_hex = argv[++index];
                break;
            }
            if (strcmp(OPT_PLAIN, argv[index]) == 0) {
                plain_hex = argv[++index];
                break;
            }
            ++index;
            break;
        }
    }

    if (0x00 != cm_hex2bin(pubkey_hex, &pubkey_bin, &pubkey_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }
    if (0x00 != cm_hex2bin(plain_hex, &plain_bin, &plain_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }

    ret_code = cp_sm2_enc(pubkey_bin, pubkey_bin_len, plain_bin, plain_bin_len,
                     &cipher, &cipher_len);
    if (ret_code != CP_SUCCESS) {
        printf("sm2 encrypt failed, ret = %lx", ret_code);
        goto end;
    }

    if (0x00 != cm_bin2hex(cipher, cipher_len, &cipher_hex)) {
        printf("convert bin to hex failed\n");
        goto end;
    }
    ret = 0;
    printf("cipher: %s\n", cipher_hex);
end:
    if (pubkey_bin != NULL) {
        free(pubkey_bin);
    }
    if (plain_bin != NULL) {
        free(plain_bin);
    }
    if (cipher != NULL) {
        free(cipher);
    }
    if (cipher_hex != NULL) {
        free(cipher_hex);
    }
    return ret;
}

