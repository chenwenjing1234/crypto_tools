//
// Created by chenwenjing on 12/18/18.
//

#include "rsa_test.h"
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

#include "bn_test.h"

static RSA* _gen_rsa(){
    RSA *ret = NULL;
    BIGNUM *bn = NULL;

    ret = RSA_new();
    bn = BN_new();

    BN_set_word(bn, RSA_3);
    RSA_generate_key_ex(ret, 2048, bn, NULL);

    return ret;
}

static void _print_bin(uint8_t *data, uint32_t len) {
    int i;
    for(i = 0; i < len; i++){
        printf("%02x", data[i]);
    }
    printf("\n");
}

int rsa_enc_test() {
    RSA *rsa = NULL;
    uint8_t msg[2] = {0x10,0x20};
    uint8_t rlt[256] = {0};
    int i;

    rsa = _gen_rsa();

    for(i = 0; i < 3; i++){
        RSA_public_encrypt(sizeof(msg), msg, rlt, rsa, RSA_PKCS1_PADDING);
        _print_bin(rlt, sizeof(rlt));
    }
}

int rsa_sign_test() {
    RSA *rsa = NULL;
    uint8_t msg[2] = {0x10,0x20};
    uint8_t rlt[256] = {0};
    uint8_t hash[32] = {0};
    uint8_t out[256] = {0};
    unsigned int rlt_len = 0;
    int ret, i;

//    rsa = _gen_rsa();
    //RSA_set_flags(rsa, RSA_FLAG_NO_BLINDING);

    rsa = RSA_new();
    ret = bn_gen_rsa_keypair(rsa, 2048, RSA_F4);
    if(ret != 1){
        printf("bn_gen_rsa_keypair failed\n");
        return ret;
    }

    SHA256(msg, sizeof(msg), hash);
//    _print_bin(hash, sizeof(hash));

    for(i = 0; i < 3; i++){
        ret = RSA_sign(NID_sha256, hash, sizeof(hash), rlt, &rlt_len, rsa);
        if (ret != 1) {
            printf("RSA_sign failed\n");
            return -1;
        }
        _print_bin(rlt, sizeof(rlt));

        ret = RSA_public_decrypt(rlt_len, rlt, out, rsa, RSA_PKCS1_PADDING);
        if (ret < 11) {
            printf("RSA_public_decrypt failed\n");
            return -1;
        }
        _print_bin(out, sizeof(out));

        ret = RSA_verify(NID_sha256, hash, sizeof(hash), rlt, rlt_len, rsa);
        if (ret != 1) {
            printf("RSA_verify failed\n");
            return -1;
        }
    }



    return 1;
}
