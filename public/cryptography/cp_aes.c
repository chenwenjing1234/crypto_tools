//
// Created by root on 11/7/19.
//

#include "cp_aes.h"

#include <memory.h>
#include <openssl/evp.h>

int aes_cbc_enc_with_padding(int keybits, unsigned char *key, unsigned char *iv,
                             unsigned char *in, int in_len, unsigned char *out, int *out_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    unsigned char *buf = NULL;
    int len1 = in_len + 16, len2, ret = 0;

    buf = (unsigned char*)calloc((size_t)len1, 1);
    if (buf == NULL) {
        goto end;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto end;
    }

    switch(keybits){
        case 128:
            cipher = EVP_aes_128_cbc();
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
            break;
        default:
            goto end;
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) ||
        !EVP_EncryptUpdate(ctx, buf, &len1, in, in_len) ||
        !EVP_EncryptFinal_ex(ctx, buf + len1, &len2)) {
        goto end;
    }

    len1 += len2;
    memcpy(out, buf, (size_t)len1);
    *out_len = len1;
    ret = 1;
end:
    if (buf != NULL) {
        free(buf);
    }
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}
