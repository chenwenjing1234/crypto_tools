//
// Created by chenwenjing on 11/24/18.
//

#include "test.h"
#include <string.h>
#include <openssl/cmac.h>

/*#define RLEFT(x) ((x) << 24) | \
                 (((x) << 8) & 0xff0000) | \
                 (((x) >> 8) & 0xff00) | \
                 ((x) >> 24)*/

int cmac_test() {

    CMAC_CTX *ctx = NULL;
    uint8_t key[] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    uint8_t data[32] = {0};
    uint8_t cmac[32] = {0};
    uint64_t cmac_len;


    memset(data, 0x68, sizeof(data));

    ctx = CMAC_CTX_new();

    CMAC_Init(ctx, key, sizeof(key), EVP_sm4_cbc(), NULL);

    CMAC_Update(ctx, data, sizeof(data));

    CMAC_Final(ctx, cmac, &cmac_len);

    CMAC_CTX_free(ctx);

    int i;
    for(i = 0; i < cmac_len; i++){
        printf("%02X", cmac[i]);
    }
    printf("\n");

}

int hex_to_bin(char *hex, unsigned char *bin, size_t *bin_len){
    size_t i,j;
    size_t str_len = strlen(hex);
    uint8_t t1, t2;
    size_t total_len = (str_len * 4) / 8;
        char buf[2] = {0};
    if (*bin_len < total_len) {
        return 0;
    }

    i = 0;
    for(j = 0; j < total_len; j++){
        memset(buf, 0, sizeof(buf));
        buf[0] = hex[i*2];
        t1 = (uint8_t)atoi(buf);
        memset(buf, 0, sizeof(buf));
        buf[0] = hex[1 + i*2];
        t2 = (uint8_t)atoi(buf);
        bin[j] = (t1 << 4) | t2;
        i++;
    }


//    for(i = 0; i < str_len; i++){
//        buf[0] = hex[i];
//        t1 = (uint8_t)atoi(buf);
//        buf[0] = hex[i+1];
//        t2 = (uint8_t)atoi(buf);
//        bin[i] = (t1 << 4) | t2;
//    }

    *bin_len = total_len;

    return 1;
}

void print_hex(int a){
    unsigned char *p = (unsigned char*)&a;
    int i;
    for(i = 0; i < sizeof(a); i++){
        printf("%02x", p[i]);
    }
    printf("\n");
}

void rleft_test(){
    int a = 0x06050403;
    //unsigned char *p = (unsigned char*)&a;

    print_hex(a);


/*    int b = RLEFT(a);


    print_hex(b);*/
}