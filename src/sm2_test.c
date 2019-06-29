//
// Created by chenwenjing on 11/25/18.
//

#include "sm2_test.h"
#include <openssl/sm2.h>
#include <openssl/gmapi.h>

void sm2_test() {
    int ret = 0;
    EC_KEY *ec_key = NULL;
    uint8_t digest[32] = {0};
    uint8_t sig[80] = {0};
    uint32_t sig_len = 0;
    uint8_t cipher[200] = {0};
    size_t cipher_len = 0;
    uint8_t plain[32] = {0};
    size_t plain_len = 0;
    ECDSA_SIG *ecdsa_sig = NULL;
    uint8_t *p = NULL;
    int i;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (ec_key == NULL) {
        printf("EC_KEY_new_by_curve_name failed\n");
        return;
    }

    EC_KEY_generate_key(ec_key);

    memset(digest, 0x62, sizeof(digest));
    ret = SM2_sign(NID_sm3, digest, sizeof(digest),
                   sig, &sig_len, ec_key);
    if (ret != 1) {
        printf("SM2_sign failed\n");
        return;
    }

//    for(i = 0; i < sig_len; i++) {
//        printf("%02X", sig[i]);
//    }
//    printf("\n");
    p = sig;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, (const unsigned char**)&p, sig_len);
    if (ecdsa_sig == NULL) {
        printf("d2i_ECDSA_SIG failed\n");
        return;
    }
    //ecdsa_sig->r;

    ret = SM2_verify(NID_sm3, digest, sizeof(digest),
               sig, sig_len, ec_key);
    if (ret != 1) {
        printf("SM2_verify failed\n");
        return;
    }

    ret = SM2_encrypt(NID_sm3, digest, sizeof(digest),
                cipher, &cipher_len, ec_key);
    if (ret != 1) {
        printf("SM2_encrypt failed\n");
        return;
    }

    ret = SM2_decrypt(NID_sm3, cipher, cipher_len, plain,
                      &plain_len, ec_key);
    if (ret != 1 || memcmp(digest, plain, sizeof(digest)) != 0) {
        printf("SM2_decrypt failed\n");
        return;
    }

    for(i = 0; i < cipher_len; i++) {
        printf("%02X", cipher[i]);
    }
    printf("\n");

    printf("sm2_test passed\n");

}

void print_ec_key(EC_KEY *ec_key) {
    const BIGNUM *bn_pri = EC_KEY_get0_private_key(ec_key);
    int len = BN_num_bytes(bn_pri);
    uint8_t  *buf = calloc(len, 1);
    const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
    BIGNUM *bn_x = BN_new();
    BIGNUM *bn_y = BN_new();

    BN_bn2bin(bn_pri, buf);

    int ne = BN_is_negative(bn_pri);

    printf("private key:\n");
    for(int i = 0; i < len; i++){
        printf("%02x", buf[i]);
    }
    printf("\n");
    free(buf);


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
}


void sm2_enc_test() {
    int ret = 0;
    EC_KEY *ec_key = NULL;
    uint8_t digest[32] = {0};
    uint8_t cipher[200] = {0};
    size_t cipher_len = 0;
    SM2CiphertextValue *ctx;
    ECCCipher ecc_cipher = {0};
    BIGNUM *bn;
    uint8_t *p;
    uint8_t buf[64] = {0};
    int len;
    int i, j;
    uint8_t cipher2[] = {0x30, 0x81, 0x89, 0x02, 0x20, 0x9f, 0x6d, 0x57,
                         0xe5, 0x13, 0x55, 0x8e, 0x76, 0xf3, 0x3c, 0x59, 0x82, 0xc8, 0x29, 0x29, 0x5e, 0xd9, 0xfb, 0xf7, 0x04, 0x2e, 0x83, 0xdc, 0x4f, 0x6d, 0x3f, 0x3c, 0xc1, 0xd1, 0xd0, 0xd7, 0x5c, 0x02, 0x21, 0x00, 0xf5, 0x53, 0x7d, 0x72, 0x9b, 0x7d, 0x91, 0xcb, 0x5e, 0xa3, 0xc4, 0xe7, 0xaf, 0xc2, 0x48, 0x6a, 0xa7, 0x8a, 0xc3, 0xb4, 0x36, 0x62, 0xe5, 0x62, 0xe4, 0x5b, 0x12, 0xb0, 0x73, 0xa5, 0x8e, 0x8d, 0x04, 0x20, 0xbf, 0x01, 0x8e, 0x22, 0x3b, 0xc9, 0x4e, 0x7b, 0x76, 0xb9, 0xf1, 0x0f, 0x37, 0x3e, 0xe1, 0x01, 0x8d, 0xa2, 0x1a, 0xc6, 0x66, 0x7b, 0x6d, 0xee, 0xad, 0x76, 0xdf, 0x8f, 0x1b, 0x9e, 0x63, 0x28, 0x04, 0x20, 0xaa, 0xfe, 0x1c, 0x2e, 0xb5, 0xfd, 0xb1, 0x14, 0x2f, 0x84, 0x24, 0xc4, 0x8e, 0xf1, 0x42, 0x8d, 0x72, 0xd7, 0x66, 0x8e, 0x17, 0x3c, 0x0b, 0xb5, 0xe2, 0x5b, 0x3a, 0xbf, 0x6b, 0x0c, 0x76};


    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (ec_key == NULL) {
        printf("EC_KEY_new_by_curve_name failed\n");
        return;
    }

    EC_KEY_generate_key(ec_key);

    print_ec_key(ec_key);
    memset(digest, 0x62, sizeof(digest));

    for(j = 0; j < 1000; j++){
        ret = SM2_encrypt(NID_sm3, digest, sizeof(digest),
                          cipher, &cipher_len, ec_key);
        if (ret != 1) {
            printf("SM2_encrypt failed\n");
            return;
        }

        printf("cipher:\n");
        for(i = 0; i < cipher_len; i++) {
            printf("%02X", cipher[i]);
        }
        printf("\n");

        p = cipher;
        p = cipher2;
        ctx = d2i_SM2CiphertextValue(NULL, (const unsigned char**)&p, cipher_len);
        if (ctx == NULL) {
            printf("d2i_SM2CiphertextValue failed\n");
            return;
        }

        SM2CiphertextValue_get_ECCCipher(ctx, &ecc_cipher);
        bn = BN_new();
        BN_bin2bn(ecc_cipher.x, sizeof(ecc_cipher.x), bn);
        len = BN_num_bytes(bn);
        printf("X len = %d ", len);
        BN_bn2bin(bn, buf);



        BN_bin2bn(ecc_cipher.y, sizeof(ecc_cipher.y), bn);
        len = BN_num_bytes(bn);
        printf("Y len = %d \n", len);
        BN_bn2bin(bn, buf);




//        for(i = 0; i < cipher_len; i++) {
//            printf("%02X", cipher[i]);
//        }
//        printf("\n");

        BN_free(bn);
    }

}

static void _print_sig_der(uint8_t *sig, uint32_t sig_len) {
    int i;
    for(i = 0; i < sig_len; i++){
        printf("%02X", sig[i]);
    }
    printf("\n");

}

void sm2_sign_test() {
    int ret = 0;
    EC_KEY *ec_key = NULL;
    uint8_t digest[32] = {0};
    uint8_t sig[80] = {0};
    uint32_t sig_len = 0;
    ECDSA_SIG *ecdsa_sig = NULL;
    uint8_t *p = NULL;
    int i, j;
    BIGNUM *r = NULL, *s = NULL;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (ec_key == NULL) {
        printf("EC_KEY_new_by_curve_name failed\n");
        return;
    }

    EC_KEY_generate_key(ec_key);


    memset(digest, 0x62, sizeof(digest));

    for(i = 0; i < 1000; i++){
        ret = SM2_sign(NID_sm3, digest, sizeof(digest),
                       sig, &sig_len, ec_key);
        if (ret != 1) {
            printf("SM2_sign failed\n");
            return;
        }

        p = sig;
        ecdsa_sig = d2i_ECDSA_SIG(NULL, (const unsigned char **) &p, sig_len);
        if (ecdsa_sig == NULL) {
            printf("d2i_ECDSA_SIG failed\n");
            return;
        }
        ECDSA_SIG_get0((const ECDSA_SIG*)ecdsa_sig, (const BIGNUM**)&r, (const BIGNUM**)&s);
        int r_len = BN_num_bytes(r);
        if (r_len == 31) {
            printf("r_len = 31, i = %d\n", i);
            _print_sig_der(sig, sig_len);
        }
        int s_len = BN_num_bytes(s);
        if (s_len == 31) {
            printf("s_len = 31, i = %d\n", i);
            _print_sig_der(sig, sig_len);
        }
        ECDSA_SIG_free(ecdsa_sig);

    }
}

void sm2_gen_key_test() {
    int ret = 0;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *bn_pri;
    BIGNUM *bn_x, *bn_y;
    const EC_POINT *pubkey;
    uint8_t buf[100] = {0};
    int i, j;
    int len;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (ec_key == NULL) {
        printf("EC_KEY_new_by_curve_name failed\n");
        return;
    }
    for(j = 0; j < 1000; j++){
        EC_KEY_generate_key(ec_key);

        bn_pri = EC_KEY_get0_private_key(ec_key);
        if (bn_pri == NULL){
            printf("EC_KEY_get0_private_key failed\n");
            return;
        }

        BN_bn2bin(bn_pri, buf);
        len = BN_num_bytes(bn_pri);
        if (len != 32) {
            printf("prikey len = %d\n", len);
            for(i = 0; i < len; i++){
                printf("%02X", buf[i]);
            }
            printf("\n");
        }


        pubkey = EC_KEY_get0_public_key(ec_key);
        if (pubkey == NULL) {
            printf("EC_KEY_get0_public_key failed\n");
            return;
        }
        group = EC_KEY_get0_group(ec_key);
        bn_x = BN_new();
        bn_y = BN_new();
        EC_POINT_get_affine_coordinates_GFp(group, pubkey, bn_x, bn_y, NULL);

        BN_bn2bin(bn_x, buf);
        len = BN_num_bytes(bn_x);
        if (len != 32) {
            printf("X len = %d\n", len);
            for(i = 0; i < len; i++){
                printf("%02X", buf[i]);
            }
            printf("\n");
        }


        BN_bn2bin(bn_y, buf);
        len = BN_num_bytes(bn_y);
        if (len != 32) {
            printf("Y len = %d\n", len);
            for(i = 0; i < len; i++){
                printf("%02X", buf[i]);
            }
            printf("\n");
        }
    }

}

void sm2_dec_test() {
    uint8_t prikey[32] = {
            0xFE, 0x9A, 0xBC, 0xF4, 0x31, 0x66, 0x24, 0xCE, 0x54, 0x67, 0x8C, 0x0C, 0xFE, 0x14, 0xFA, 0xCD,
            0x51, 0x97, 0x5F, 0x32, 0x6E, 0xBD, 0xAA, 0x06, 0x06, 0xA2, 0x72, 0x40, 0xD2, 0x90, 0xFB, 0xDE
    };
    uint8_t pubkey_x[32] = {
            0xBC, 0xA2, 0xA3, 0x87, 0x26, 0xC0, 0x25, 0x0C, 0x7B, 0xD1, 0xDD, 0xEF, 0xAE, 0x8D, 0x15, 0xC5,
            0x4C, 0xB4, 0x83, 0x51, 0xE1, 0x89, 0x8C, 0x78, 0x93, 0x06, 0x6F, 0xB1, 0x2F, 0x06, 0x7C, 0x2F
    };
    uint8_t pubkey_y[32] = {
            0xB8, 0x1F, 0xEA, 0x8D, 0x0C, 0x79, 0x5F, 0x38, 0x0C, 0x4A, 0x68, 0xE9, 0x95, 0xCB, 0x5E, 0x4F,
            0x18, 0x75, 0xC2, 0x2B, 0xA2, 0x80, 0x33, 0x10, 0x40, 0x5B, 0x5D, 0xBD, 0xA2, 0x61, 0xBA, 0x17
    };
    uint8_t cipher[141] = {
            0x30, 0x81, 0x8A, 0x02, 0x21, 0x00, 0xA9, 0xF7, 0xFF, 0xF1, 0xE6, 0x34, 0x8D, 0xFB, 0x25, 0x95,
            0xA6, 0xBA, 0xAF, 0x66, 0x9F, 0x5E, 0x9C, 0x3E, 0x0F, 0x66, 0x72, 0xFA, 0x96, 0xAF, 0x72, 0x8E,
            0x36, 0x6C, 0x34, 0xFD, 0xB8, 0x98, 0x02, 0x21, 0x00, 0xD1, 0x8D, 0x49, 0x69, 0x49, 0xC4, 0x3A,
            0x52, 0x87, 0xAD, 0xBF, 0x83, 0xA6, 0xEC, 0x45, 0xB8, 0xC6, 0xEA, 0x25, 0xB1, 0x33, 0x80, 0xAD,
            0x63, 0xB5, 0x04, 0x6C, 0xBB, 0xA3, 0x85, 0x04, 0x69, 0x04, 0x20, 0xCF, 0x65, 0x7B, 0xF9, 0xD7,
            0xDB, 0xFA, 0x56, 0xE1, 0x0A, 0xE1, 0xDA, 0x8D, 0x98, 0x53, 0xC3, 0xBD, 0x91, 0xAA, 0x61, 0x68,
            0x2D, 0xC2, 0xE8, 0xA3, 0xA0, 0xBA, 0x17, 0x5C, 0x70, 0x02, 0xDF, 0x04, 0x20, 0x07, 0x70, 0x05,
            0x82, 0x50, 0x25, 0x7A, 0x10, 0x3E, 0xBC, 0x11, 0xCB, 0x97, 0xBD, 0xA1, 0xE7, 0x25, 0x8C, 0xA6,
            0xC9, 0xE4, 0x57, 0xD2, 0x5F, 0x1B, 0xA7, 0x78, 0x4A, 0xF6, 0xC3, 0xF3, 0x6C
    };
    uint8_t cipher2[] = {
            0x30, 0x81, 0x88, 0x02, 0x20, 0xA9, 0xF7, 0xFF, 0xF1, 0xE6, 0x34, 0x8D, 0xFB, 0x25, 0x95,
            0xA6, 0xBA, 0xAF, 0x66, 0x9F, 0x5E, 0x9C, 0x3E, 0x0F, 0x66, 0x72, 0xFA, 0x96, 0xAF, 0x72, 0x8E,
            0x36, 0x6C, 0x34, 0xFD, 0xB8, 0x98, 0x02, 0x20, 0xD1, 0x8D, 0x49, 0x69, 0x49, 0xC4, 0x3A,
            0x52, 0x87, 0xAD, 0xBF, 0x83, 0xA6, 0xEC, 0x45, 0xB8, 0xC6, 0xEA, 0x25, 0xB1, 0x33, 0x80, 0xAD,
            0x63, 0xB5, 0x04, 0x6C, 0xBB, 0xA3, 0x85, 0x04, 0x69, 0x04, 0x20, 0xCF, 0x65, 0x7B, 0xF9, 0xD7,
            0xDB, 0xFA, 0x56, 0xE1, 0x0A, 0xE1, 0xDA, 0x8D, 0x98, 0x53, 0xC3, 0xBD, 0x91, 0xAA, 0x61, 0x68,
            0x2D, 0xC2, 0xE8, 0xA3, 0xA0, 0xBA, 0x17, 0x5C, 0x70, 0x02, 0xDF, 0x04, 0x20, 0x07, 0x70, 0x05,
            0x82, 0x50, 0x25, 0x7A, 0x10, 0x3E, 0xBC, 0x11, 0xCB, 0x97, 0xBD, 0xA1, 0xE7, 0x25, 0x8C, 0xA6,
            0xC9, 0xE4, 0x57, 0xD2, 0x5F, 0x1B, 0xA7, 0x78, 0x4A, 0xF6, 0xC3, 0xF3, 0x6C
    };

    uint8_t plain[32] = {0};
    memset(plain, 0x62, sizeof(plain));
    uint8_t out[32] = {0};
    size_t len = sizeof(out);


    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(ec_group);
    BIGNUM *bn_pri = BN_new();
    BIGNUM *bn_x = BN_new();
    BIGNUM *bn_y = BN_new();

    BN_bin2bn(prikey, sizeof(prikey), bn_pri);
    BN_bin2bn(pubkey_x, sizeof(pubkey_x), bn_x);
    BN_bin2bn(pubkey_y, sizeof(pubkey_y), bn_y);

    BN_set_negative(bn_pri, 1);

    EC_KEY_set_private_key(ec_key, bn_pri);
    //EC_POINT_set_affine_coordinates_GFp(ec_group, ec_point, bn_x, bn_y, NULL);
    //EC_KEY_set_public_key(ec_key, ec_point);

    SM2_decrypt(NID_sm3, cipher2, sizeof(cipher2),out, &len, ec_key);

    if (memcmp(plain, out, sizeof(plain)) != 0) {
        printf("dec failed\n");
    } else {
        printf("dec success\n");
    }


}