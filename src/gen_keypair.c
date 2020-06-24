//
// Created by root on 11/6/19.
//

#include "ca_define.h"
#include "cp_rsa.h"
#include "cp_defines.h"
#include "cm_utils.h"

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

//crypto_utils gen_rsa_kp -keybits xx -e xx
int gen_rsa_kp_main(int argc, char *argv[]) {
    int ret;
    unsigned char *pubkey = NULL;
    unsigned char *privkey = NULL;
    int pubkey_len = 0;
    int privkey_len = 0;
    char *pubkey_hex = NULL;
    char *privkey_hex = NULL;
    int bits, e;

    if (argc < 6 || strcmp(argv[2], "-keybits") != 0 || strcmp(argv[4], "-e") != 0) {
        printf("input arguments invalid, correct as follow:\n");
        printf("crypto_utils gen_rsa_kp -keybits xx -e xx\n");
        return 1;
    }

    if (cm_is_number(argv[3]) != CM_SUCCESS || cm_is_number(argv[5]) != CM_SUCCESS) {
        printf("input arguments invalid\n");
        return 1;
    }

    bits = atoi(argv[3]);
    e = atoi(argv[5]);

    ret = cp_gen_rsa_keypair(e, bits, &pubkey, &pubkey_len, &privkey, &privkey_len);
    if (ret != CP_SUCCESS) {
        printf("cp_gen_rsa_keypair failed");
        return 1;
    }

    if (cm_bin2hex(pubkey, (size_t)pubkey_len, &pubkey_hex) != CM_SUCCESS ||
        cm_bin2hex(privkey, (size_t)privkey_len, &privkey_hex) != CM_SUCCESS) {
        ret = 1;
        goto end;
    }

    printf("pubkey: %s\n", pubkey_hex);
    printf("privkey: %s\n", privkey_hex);
    ret = 0;

end:
    if (pubkey != NULL) {
        free(pubkey);
    }
    if (privkey != NULL) {
        free(privkey);
    }
    if (pubkey_hex != NULL) {
        free(pubkey_hex);
    }
    if (privkey_hex != NULL) {
        free(privkey_hex);
    }
    return ret;
}