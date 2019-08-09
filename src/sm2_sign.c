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

//crypto_tools -sm2_sign -prikey xx -pubkey xx -pre_process xx -msg xx
int sm2_sign_main(int argc, char **argv) {
    int ret = 1;
    uint64_t cp_ret;
    int index = 2;
    char *pubkey_hex = NULL;
    char *prikey_hex = NULL;
    char *pre_process = NULL;
    int type;
    char *msg_hex = NULL;
    uint8_t *msg_bin = NULL;
    uint32_t msg_bin_len = 0;
    EC_KEY *ec_key = NULL;
    uint8_t sig[72] = {0};
    uint32_t sig_len = 0;
    char *sig_hex = NULL;

    if (argc < 10) {
        printf("input arguments invalid, example as flow:\n");
        printf("  crypto_tools -sm2_sign -prikey xx -pubkey xx -pre_process xx -msg xx\n");
        return ret;
    }

    while(index < 10){
        for(;;){
            if (strcmp(OPT_PUBKEY, argv[index]) == 0) {
                pubkey_hex = argv[++index];
                break;
            }
            if (strcmp(OPT_PRIKEY, argv[index]) == 0) {
                prikey_hex = argv[++index];
                break;
            }
            if (strcmp(OPT_PREPROCESS, argv[index]) == 0) {
                pre_process = argv[++index];
                break;
            }
            if (strcmp(OPT_MSG, argv[index]) == 0) {
                msg_hex = argv[++index];
                break;
            }
            ++index;
            break;
        }
    }

    if (strcmp(pre_process, "1") == 0) {
        type = 1;
    } else if (strcmp(pre_process, "0") == 0) {
        type = 0;
    } else {
        printf("pre process type invalid, must 0 or 1\n");
        return ret;
    }

    cp_ret = cp_new_eckey_by_hex_pubkey_prikey(pubkey_hex, prikey_hex, &ec_key);
    if (cp_ret != CP_SUCCESS) {
        printf("cp_new_eckey_by_hex_pubkey_prikey failed\n");
        goto end;
    }

    if (CM_SUCCESS != cm_hex2bin(msg_hex, &msg_bin, &msg_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }

    cp_ret = cp_sm2_sign(ec_key, msg_bin, msg_bin_len, type, sig, &sig_len);
    if (cp_ret != CP_SUCCESS) {
        printf("cp_sm2_sign failed\n");
        goto end;
    }

    ret = cm_bin2hex(sig, sig_len, &sig_hex);
    if (ret != CM_SUCCESS) {
        printf("cm_bin2hex failed\n");
        goto end;
    }

    printf("signature result: %s\n", sig_hex);
    ret = ERR_OK;
end:
    if (msg_bin != NULL) {
        free(msg_bin);
    }
    EC_KEY_free(ec_key);
    if (sig_hex != NULL) {
        free(sig_hex);
    }
    return ret;
}