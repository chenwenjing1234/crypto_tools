//
// Created by chenwenjing on 12/22/18.
//

#include "bn_test.h"

#include <openssl/bn.h>

int bn_test(){
    BIGNUM *p = NULL, *q = NULL, *n = NULL;
    BN_CTX *ctx = NULL;
    int ret, bits;

    p = BN_new();
    q = BN_new();
    n = BN_new();

    ctx = BN_CTX_new();

    ret = BN_rand(p, 512, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD);
    if (ret != 1) {
        printf("BN_rand failed, ret = %d\n", ret);
        return ret;
    }
    ret = BN_rand(q, 512, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD);
    if (ret != 1) {
        printf("BN_rand failed, ret = %d\n", ret);
        return ret;
    }

    ret = BN_mul(n, p, q, ctx);
    if (ret != 1) {
        printf("BN_mul failed, ret = %d\n", ret);
        return ret;
    }

    bits = BN_num_bits(n);
    printf("bits = %d\n", bits);

    return 0;

}

int bn_gen_rsa_keypair(RSA *rsa, int bits, unsigned long e){
    BIGNUM *p = NULL, *q = NULL, *n = NULL, *bn_e = NULL, *d = NULL;
    BIGNUM *p1 = NULL, *q1 = NULL, *tmp = NULL, *pmq = NULL;
    BN_CTX *ctx = NULL;
    int ret;

    p = BN_new();
    q = BN_new();
    n = BN_new();
    bn_e = BN_new();
    p1 = BN_new();
    q1 = BN_new();
    tmp = BN_new();
    pmq = BN_new();

    ctx = BN_CTX_new();

    ret = BN_generate_prime_ex(p, bits/2, 0, NULL, NULL, NULL);
    if(ret != 1){
        printf("BN_generate_prime_ex failed, ret = %d\n", ret);
        return ret;
    }

    ret = BN_generate_prime_ex(q, bits/2, 0, NULL, NULL, NULL);
    if(ret != 1){
        printf("BN_generate_prime_ex failed, ret = %d\n", ret);
        return ret;
    }

    ret = BN_mul(n, p, q, ctx);
    if(ret != 1){
        printf("BN_mul failed, ret = %d\n", ret);
        return ret;
    }

    BN_one(tmp);
    ret = BN_sub(p1, p, tmp);
    if(ret != 1){
        printf("BN_sub failed, ret = %d\n", ret);
        return ret;
    }

    BN_zero_ex(tmp);
    BN_one(tmp);
    ret = BN_sub(q1, q, tmp);
    if(ret != 1){
        printf("BN_sub failed, ret = %d\n", ret);
        return ret;
    }

    ret = BN_mul(pmq, p1, q1, ctx);
    if(ret != 1){
        printf("BN_mul failed, ret = %d\n", ret);
        return ret;
    }

    ret = BN_set_word(bn_e, e);
    if(ret != 1){
        printf("BN_set_word failed, ret = %d\n", ret);
        return ret;
    }

    d = BN_mod_inverse(NULL, bn_e, pmq, ctx);
    if(d == NULL){
        printf("BN_mod_inverse failed\n");
        return -1;
    }

    ret = RSA_set0_key(rsa, n, bn_e, d);
    if(ret != 1){
        printf("RSA_set0_key failed, ret = %d\n", ret);
        return ret;
    }

    return 1;
}

int bn_gen_rsa_keypair_test(){
    RSA *rsa = NULL;

    rsa = RSA_new();

    int ret = bn_gen_rsa_keypair(rsa, 1024, RSA_F4);
    if (ret != 1) {
        printf("bn_gen_rsa_keypair failed, ret = %d\n", ret);
        return ret;
    }

    return 1;
}