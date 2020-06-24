#include<stdio.h>
#include <string.h>
#include "test.h"
#include "sm2_test.h"
#include "sm3_test.h"
#include "rsa_test.h"
#include "bn_test.h"
#include "cp_sm2.h"
#include "cm_utils.h"
#include "global.h"
#include "cp_defines.h"

static int _sm2_pubkey_encoding(char *pubkey_hex, uint8_t **pubkey_der, int *pubkey_der_len) {
    uint32_t ret = 0;
    uint8_t *buf = NULL;
    uint32_t buf_len = 0;

    ret = cm_hex2bin(pubkey_hex, &buf, &buf_len);
    if (ret != 0) {
        return 0;
    }

    ret = (uint32_t)cp_sm2_pubkey_encoding(buf, buf_len,
                                           pubkey_der, pubkey_der_len);

    free(buf);
    return ret;
}

/*
 * 1. crypto_utils gen_sm2_kp OK
 * 2. crypto_utils gen_rsa_kp -coding DER/RAW
 * 3. crypto_utils sm2_enc -pubkey xx -plain xx OK
 * 4. crypto_utils sm2_dec -prikey xx -cipher xx OK
 * 5. crypto_utils sm2_pubkey_encoding_main -pubkey xx(04||x||y)
 * 6. crypto_utils sm2_pubkey_decoding -pubkey xx(der)
 * 6. crypto_utils sm2_prikey_encoding -prikey xx(bn)
 * 6. crypto_utils sm2_prikey_decoding -prikey xx(der)
 * 7. crypto_utils kp_check -pubkey xx -prikey xx
 * 8. crypto_utils sm2_cipher_decoding -cipher xx
 * 9. crypto_utils sm2_plain_encoding -plain c1||c2||c3
 * sm2 sign result encoding decoding
 * rsa ecc sm2 sign
 * verify
 * sign rst decoding
 * r s encoding
 * sm2 prepare
 * gen csr
 * create cert(SM2 | RSA | ECC)
 * cert chain verify(SM2 | RSA | ECC)
 * algo performance test (AES-ECB-CBC-CFB-OFB-OCT SM2-ENC-SIGN RSA-ENC-SIGN
 * HASH-SH1-SM3-SH2-SH3)
 * MAC-HMAC CMAC
 * GEN RANDOM -LENGTH
 * CERT PARSER(SM2 | RSA | ECC)
 * AES-ENC-DEC(ECB-CBC-CFB-OFB-OCT) -MODE -KEYLENGTH -PADDING -IV
 * SM4-ENC-DEC(ECB-CBC-CFB-OFB-OCT) -MODE -KEYLENGTH -PADDING -IV
 * HASH-SM3-MD5-SHA1-SHA256-SHA384-SHA512
 * */

int main(int argc, char *argv[]) {

    cp_sm2_init();

    return exec_func_by_option(argc, argv);
    sm2_dec_test();
    uint64_t ret = CP_SUCCESS;
    char pubkey_hex[131] = {0};
    char prikey_hex[65] = {0};
    uint8_t *pubkey_bin = NULL;
    uint32_t pubkey_bin_len = 0;
    uint8_t *prikey_bin = NULL;
    uint32_t prikey_bin_len = 0;
    uint8_t *plain_bin = NULL;
    uint32_t plain_bin_len = 0;
    uint8_t *cipher_bin = NULL;
    uint32_t len2 = 0;
    uint8_t *cipher = NULL;
    size_t cipher_len = 0;
    size_t plain_len = 0;
    char *cipher_hex = NULL;
    char *plain_hex = NULL;
    uint8_t *up = NULL;
    char *p1 = NULL;
    char *p2 = NULL;
    int len = 0;

    if ((strcmp(argv[1], "gen_sm2_kp") == 0)) {
        ret = cp_gen_sm2_keypair(pubkey_hex, prikey_hex);
        if (ret != CP_SUCCESS) {
            printf("gen keypair failed, ret = %lx", ret);
            return 1;
        }
        printf("pubkey: %s\n", pubkey_hex);
        printf("prikey: %s\n", prikey_hex);
    } else if ((strcmp(argv[1], "sm2_enc") == 0)) {
        plain_hex = argv[5];
        if (0x00 != cm_hex2bin(argv[3], &pubkey_bin, &pubkey_bin_len)) {
            printf("convert hex to bin failed\n");
            goto end;
        }
        if (0x00 != cm_hex2bin(plain_hex, &plain_bin, &plain_bin_len)) {
            printf("convert hex to bin failed\n");
            goto end;
        }

        ret = cp_sm2_enc(pubkey_bin, pubkey_bin_len, plain_bin, plain_bin_len,
                         &cipher, &cipher_len);
        if (ret != CP_SUCCESS) {
            printf("sm2 encrypt failed, ret = %lx", ret);
            return 1;
        }

        if (0x00 != cm_bin2hex(cipher, cipher_len, &cipher_hex)) {
            printf("convert bin to hex failed\n");
            return 1;
        }

        printf("plain: %s\n", plain_hex);
        printf("cipher: %s\n", cipher_hex);
    } else if ((strcmp(argv[1], "sm2_dec") == 0)) {
        cipher_hex = argv[5];
        if (0x00 != cm_hex2bin(argv[3], &prikey_bin, &prikey_bin_len)) {
            printf("convert hex to bin failed\n");
            goto end;
        }
        if (0x00 != cm_hex2bin(cipher_hex, &cipher, &len2)) {
            printf("convert hex to bin failed\n");
            goto end;
        }

        ret = cp_sm2_dec(prikey_bin, prikey_bin_len, cipher, len2,
                         &plain_bin, &plain_len);
        if (ret != CP_SUCCESS) {
            printf("sm2 decrypt failed, ret = %lx", ret);
            return 1;
        }

        if (0x00 != cm_bin2hex(plain_bin, plain_len, &plain_hex)) {
            printf("convert bin to hex failed\n");
            return 1;
        }

        printf("cipher: %s\n", cipher_hex);
        printf("plain: %s\n", plain_hex);
    } else if ((strcmp(argv[1], "sm2_pubkey_encoding_main") == 0)) {
        p1 = argv[5];
        if (0x01 != _sm2_pubkey_encoding(p1, &up, &len)) {
            printf("sm2 public key encoding failed\n");
            goto end;
        }

        cm_bin2hex(up, (size_t)len, &p2);

        printf("pubkey: %s\n", p2);
    }
end:
    if (pubkey_bin != NULL) {
        free(pubkey_bin);
    }
    return 0;
}
