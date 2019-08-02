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

//crypto_tools sm2_pubkey_encoding -pubkey xx
int sm2_pubkey_encoding_main(int argc, char **argv) {
    int ret = 1;
    uint64_t ret_code;
    char *pubkey_hex = NULL;
    int index = 2;
    uint8_t *pubkey_bin = NULL;
    uint32_t pubkey_bin_len = 0;

    uint8_t *pubkey_der = NULL;
    int pubkey_der_len = 0;
    char *pubkey_der_hex = NULL;

    if (argc < 4) {
        printf("input arguments invalid, example as flow:\n");
        printf("  crypto_tools sm2_pubkey_encoding_main -pubkey xx\n");
        return 1;
    }

    while(index < 4){
        for(;;){
            if (strcmp(OPT_PUBKEY, argv[index]) == 0) {
                pubkey_hex = argv[++index];
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

    ret_code = cp_sm2_pubkey_encoding(pubkey_bin, pubkey_bin_len,
                                      &pubkey_der, &pubkey_der_len);
    if (ret_code != CP_SUCCESS) {
        printf("cp_sm2_pubkey_encoding failed, ret = %lx", ret_code);
        goto end;
    }

    if (0x00 != cm_bin2hex(pubkey_der, (size_t)pubkey_der_len, &pubkey_der_hex)) {
        printf("convert bin to hex failed\n");
        goto end;
    }
    ret = 0;
    printf("pubkey DER: %s\n", pubkey_der_hex);
    end:
    if (pubkey_bin != NULL) {
        free(pubkey_bin);
    }
    if (pubkey_der != NULL) {
        free(pubkey_der);
    }

    if (pubkey_der_hex != NULL) {
        free(pubkey_der_hex);
    }
    return ret;
}
