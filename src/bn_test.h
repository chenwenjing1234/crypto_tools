//
// Created by chenwenjing on 12/22/18.
//

#ifndef CRYPTO_TOOLS_BN_TEST_H
#define CRYPTO_TOOLS_BN_TEST_H

#include <openssl/rsa.h>

int bn_test();
int bn_gen_rsa_keypair(RSA *rsa, int bits, unsigned long e);
int bn_gen_rsa_keypair_test();

#endif //CRYPTO_TOOLS_BN_TEST_H
