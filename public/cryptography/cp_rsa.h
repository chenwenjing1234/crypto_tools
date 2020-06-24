//
// Created by root on 11/6/19.
//

#ifndef CRYPTO_TOOLS_CP_RSA_H
#define CRYPTO_TOOLS_CP_RSA_H

int cp_gen_rsa_keypair(int e, int bits, unsigned char **pubkey, int *pubkey_len,
                       unsigned char **privkey, int *privkey_len);

#endif //CRYPTO_TOOLS_CP_RSA_H
