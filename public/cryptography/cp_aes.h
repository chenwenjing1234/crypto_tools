//
// Created by root on 11/7/19.
//

#ifndef CRYPTO_TOOLS_CP_AES_H
#define CRYPTO_TOOLS_CP_AES_H

int aes_cbc_enc_with_padding(int keybits, unsigned char *key, unsigned char *iv,
                             unsigned char *in, int in_len, unsigned char *out, int *out_len);

#endif //CRYPTO_TOOLS_CP_AES_H
