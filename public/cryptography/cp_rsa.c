//
// Created by root on 11/6/19.
//

#include "cp_rsa.h"

#include <openssl/rsa.h>
#include <memory.h>

int cp_gen_rsa_keypair(int e, int bits, unsigned char **pubkey, int *pubkey_len,
                       unsigned char **privkey, int *privkey_len) {
    int ret= 0;
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    int buf1_len, buf2_len;

    rsa = RSA_new();
    bne = BN_new();

    if (rsa == NULL || bne == NULL) {
        goto end;
    }

    BN_set_word(bne, (unsigned long)e);

    ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
    if (ret != 1) {
        goto end;
    }

    buf1_len = i2d_RSAPublicKey(rsa, &buf1);
    buf2_len = i2d_RSAPrivateKey(rsa, &buf2);

    *pubkey = buf1;
    *privkey = buf2;

    *pubkey_len = buf1_len;
    *privkey_len = buf2_len;

    ret = 1;
end:
    RSA_free(rsa);
    BN_free(bne);

    return ret;
}
