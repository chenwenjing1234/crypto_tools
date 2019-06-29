//
// Created by chenwenjing on 5/24/19.
//

#include "bn_test.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>

unsigned char *BN_to_binary(BIGNUM *b, unsigned int *outsz) {
    unsigned char *ret;

    *outsz = BN_num_bytes(b);
    if (BN_is_negative(b)) {

        (*outsz)++;
        if (!(ret = (unsigned char *)malloc(*outsz))) return 0;
        BN_bn2bin(b, ret + 1);
        ret[0] = 0x80;
    } else {
        if (!(ret = (unsigned char *)malloc(*outsz))) return 0;
        BN_bn2bin(b, ret);
    }
    return ret;
}

int bn2bin_test() {
    BIGNUM *bn = BN_new();
    uint8_t buf[20] = {0};
    uint8_t buf2[20] = {0};
    int len = 0;
    BN_set_word(bn, 0x8001);

    int bytes = BN_num_bytes(bn);


    len = BN_bn2bin(bn, buf);
    for(int i = 0; i < len; i++){
        printf("%02x", buf[i]);
    }
    printf("\n");
    char *hex1 = BN_bn2hex(bn);
    printf("hex1 = %s\n", hex1);

    BN_set_negative(bn, 1);


    len = BN_bn2bin(bn, buf2);


    for(int i = 0; i < len; i++){
        printf("%02x", buf2[i]);
    }

    printf("\n");
    char *hex2 = BN_bn2hex(bn);
    printf("hex2 = %s\n", hex2);
    return 1;

}


int bin2bn_test() {
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();
    uint8_t buf[20] = {0x80, 0x01};
    uint8_t buf2[20] = {0x00, 0x80, 0x01};
    int len = 0;

    BN_bin2bn(buf, 2, bn1);

    BN_bin2bn(buf2, 3, bn2);

    int a = BN_is_negative(bn1);
    int b = BN_is_negative(bn2);

    printf("a = %d\n", a);
    printf("b = %d\n", b);

    return 1;

}

int bn_negative_test() {

    EC_KEY *ec_key = EC_KEY_new();
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_set_group(ec_key, ec_group);
    uint8_t *buf = NULL;
    BIGNUM *bn_x = BN_new();
    BIGNUM *bn_y = BN_new();
    uint8_t *pri_der_buf = NULL;
    uint8_t *pub_der_buf = NULL;
    uint8_t *p;

    int j;
    for(j = 0; j < 10; j++){

        EC_KEY_generate_key(ec_key);



        const BIGNUM *bn_pri = EC_KEY_get0_private_key(ec_key);
        int len = BN_num_bytes(bn_pri);
        buf = calloc(len, 1);

        BN_bn2bin(bn_pri, buf);

        int ne = BN_is_negative(bn_pri);

        printf("private key:\n");
        for(int i = 0; i < len; i++){
            printf("%02x", buf[i]);
        }
        printf("\n");
        free(buf);

        printf("private key der:\n");
        //pri_der_buf = p;
        len = i2d_ECPrivateKey(ec_key, &pri_der_buf);
        for(int i = 0; i < len; i++){
            printf("%02x", pri_der_buf[i]);
        }
        printf("\n");

        const EC_POINT *ec_point = EC_KEY_get0_public_key(ec_key);

        EC_POINT_get_affine_coordinates_GFp(ec_group, ec_point, bn_x, bn_y, NULL);

        len = BN_num_bytes(bn_x);
        buf = calloc(len, 1);

        ne = BN_is_negative(bn_x);
        BN_bn2bin(bn_x, buf);
        printf("X:\n");
        for(int i = 0; i < len; i++){
            printf("%02x", buf[i]);
        }
        printf("\n");
        free(buf);

        len = BN_num_bytes(bn_y);
        buf = calloc(len, 1);

        ne = BN_is_negative(bn_y);
        BN_bn2bin(bn_y, buf);
        printf("Y:\n");
        for(int i = 0; i < len; i++){
            printf("%02x", buf[i]);
        }
        printf("\n");
        free(buf);


        printf("public key der:\n");
        //p = pub_der_buf;
        len = i2d_EC_PUBKEY(ec_key, &pub_der_buf);
        for(int i = 0; i < len; i++){
            printf("%02x", pub_der_buf[i]);
        }
        printf("\n");

    }

    printf("j = %d\n", j);
    return 1;
}