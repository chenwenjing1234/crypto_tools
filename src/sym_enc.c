//
// Created by root on 11/7/19.
//

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>

#include "cm_utils.h"

static void print_aes_help_info();

//crypto_utils aes_enc -mode xx -keybits xx -padding xx -iv xx -key xx -plain xx
int aes_enc_main(int argc, char **argv) {

    char mode[8] = {0};
    int keybits = 0;
    int padding = 0;
    char *iv_hex = NULL;
    unsigned char *iv_bin = NULL;
    char *key_hex = NULL;
    unsigned char *key_bin = NULL;
    char *plain_hex = NULL;
    unsigned char *plain_bin = NULL;
    uint32_t iv_len, key_len, plain_len;
    int counter = 0;

    if (argc < 11 || strcmp("aes_enc", argv[1]) != 0 ||
        strcmp("-mode", argv[2]) != 0) {

    }


    for(int i = 2; i < argc - 2; i+=2) {
        for (;;) {
            if (strcmp("-mode", argv[i]) == 0) {
                strcpy(mode, argv[i+1]);
                counter++;
                break;
            }
            if (strcmp("-keybits", argv[i]) == 0) {
                keybits = atoi(argv[i+1]);
                counter++;
                break;
            }
            if (strcmp("-padding", argv[i]) == 0) {
                padding = atoi(argv[i+1]);
                counter++;
                break;
            }
            if (strcmp("-iv", argv[i]) == 0) {
                iv_hex = argv[i+1];
                counter++;
                break;
            }
            if (strcmp("-key", argv[i]) == 0) {
                key_hex = argv[i+1];
                counter++;
                break;
            }
            if (strcmp("-plain", argv[i]) == 0) {
                plain_hex = argv[i+1];
                counter++;
                break;
            }
        }
    }

    if (counter != argc - 2) {

    }


    cm_hex2bin(iv_hex, &iv_bin, &iv_len);
    cm_hex2bin(key_hex, &key_bin, &key_len);
    cm_hex2bin(plain_hex, &plain_bin, &plain_len);





}

static void print_aes_help_info() {

    printf("crypto_utils aes_enc -mode xx -keybits xx -padding xx -iv xx -key xx -plain xx\n");

}

