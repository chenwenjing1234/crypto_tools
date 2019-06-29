//
// Created by chenwenjing on 6/3/19.
//

#include <stdio.h>
#include <cp_sm2.h>

int gen_sm2_kp_main(int argc, char *argv[]) {
    uint64_t ret;
    char pubkey_hex[131] = {0};
    char prikey_hex[65] = {0};

    ret = cp_gen_keypair(pubkey_hex, prikey_hex);
    if (ret != CP_SUCCESS) {
        printf("cp_gen_keypair failed, ret = %lx", ret);
        return 1;
    }
    printf("pubkey: %s\n", pubkey_hex);
    printf("prikey: %s\n", prikey_hex);
    return 0;
}

