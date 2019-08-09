//
// Created by root on 8/8/19.
//
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cm_utils.h"
#include "ca_define.h"
#include "cp_sm2.h"
#include "cp_defines.h"
#include "global.h"

//crypto_tools -sm2_kp_check -pubkey xx -prikey xx
int sm2_kp_check_main(int argc, char **argv) {
    int ret = 1;
    int index = 2;
    char *pubkey_hex = NULL;
    uint8_t *pubkey_bin = NULL;
    uint32_t pubkey_bin_len = 0;
    char *prikey_hex = NULL;
    uint8_t *prikey_bin = NULL;
    uint32_t prikey_bin_len = 0;

    if (argc < 6) {
        printf("input arguments invalid, example as flow:\n");
        printf("  crypto_tools -sm2_kp_check -pubkey xx -prikey xx\n");
        return 1;
    }

    while(index < 6){
        for(;;){
            if (strcmp(OPT_PUBKEY, argv[index]) == 0) {
                pubkey_hex = argv[++index];
                break;
            }
            if (strcmp(OPT_PRIKEY, argv[index]) == 0) {
                prikey_hex = argv[++index];
                break;
            }
            ++index;
            break;
        }
    }

    if (CM_SUCCESS != cm_hex2bin(pubkey_hex, &pubkey_bin, &pubkey_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }

    if (CM_SUCCESS != cm_hex2bin(prikey_hex, &prikey_bin, &prikey_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }

    ret = cp_sm2_kp_check(prikey_bin, prikey_bin_len, pubkey_bin, pubkey_bin_len);
    if (ret != CP_SUCCESS) {
        printf("cp_sm2_kp_check failed, ret = %d\n", ret);
        goto end;
    }

    ret = ERR_OK;
    printf("sm2 key pair check successful\n");
end:
    if (pubkey_bin != NULL) {
        free(pubkey_bin);
    }
    if (prikey_bin != NULL) {
        free(prikey_bin);
    }
    return ret;
}