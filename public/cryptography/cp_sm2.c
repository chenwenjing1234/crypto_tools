//
// Created by chenwenjing on 5/6/19.
//

#include "cp_sm2.h"

#include <openssl/sm2.h>

#include "cm_utils.h"

int test()
{
    return 1;
}

uint64_t cp_sm2_enc(uint8_t *pubkey, uint32_t pubkey_len,
                    uint8_t *plain, size_t plain_len,
                    uint8_t **cipher, size_t *cipher_len) {
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group = NULL;
    EC_POINT *ec_point = NULL;
    char *buf = NULL;
    uint8_t *p = NULL;
    size_t len = plain_len + 120;
    uint64_t ret = CP_SUCCESS;

    p = (uint8_t*)calloc(len, 1);
    if (p == NULL) {
        return 0;
    }

    ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    if (ec_group == NULL) {
        ret = ERR_peek_last_error();
        return ret;
    }

    ret = cm_bin2hex(pubkey, (size_t)pubkey_len, &buf);
    if (ret != 0) {
        return 0;
    }
    ec_point = EC_POINT_hex2point(ec_group, buf, NULL, NULL);
    if (ec_point == NULL) {
        ret = ERR_peek_last_error();
        EC_GROUP_free(ec_group);
        return ret;
    }

    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        ret = ERR_peek_last_error();
        EC_GROUP_free(ec_group);
        EC_POINT_free(ec_point);
        return ret;
    }

    EC_KEY_set_group(ec_key, ec_group);
    EC_KEY_set_public_key(ec_key, ec_point);

    ret = (uint64_t)SM2_encrypt(NID_sm3, plain, plain_len,
                                p, &len, ec_key);
    if (ret != CP_SUCCESS) {
        ret = ERR_peek_last_error();
        goto end;
    }
    *cipher = p;
    *cipher_len = len;
end:
    EC_KEY_free(ec_key);
    if (ret != CP_SUCCESS) {
        free(p);
    }
    if (buf != NULL) {
        free(buf);
    }
    return ret;
}


uint64_t cp_sm2_dec(uint8_t *prikey, uint32_t prikey_len,
                    uint8_t *cipher, size_t cipher_len,
                    uint8_t **plain, size_t *plain_len) {
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group = NULL;
    BIGNUM *bn_prikey = NULL;
    uint8_t *buf = NULL;
    uint64_t ret = CP_SUCCESS;

    ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    if (ec_group == NULL) {
        ret = ERR_peek_last_error();
        return ret;
    }

    bn_prikey = BN_bin2bn(prikey, prikey_len, NULL);
    if (bn_prikey == NULL) {
        ret = ERR_peek_last_error();
        EC_GROUP_free(ec_group);
        return ret;
    }

    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        ret = ERR_peek_last_error();
        EC_GROUP_free(ec_group);
        BN_free(bn_prikey);
        return ret;
    }

    EC_KEY_set_group(ec_key, ec_group);
    EC_KEY_set_private_key(ec_key, bn_prikey);

    buf = (uint8_t*)calloc(cipher_len, 1);
    if (buf == NULL) {
        return 0;
    }

    ret = (uint64_t)SM2_decrypt(NID_sm3, cipher, cipher_len,
                                buf, plain_len, ec_key);
    if (ret != CP_SUCCESS) {
        ret = ERR_peek_last_error();
        goto end;
    }

    *plain = buf;
end:
    if (ret != CP_SUCCESS && buf != NULL) {
        free(buf);
    }
    EC_KEY_free(ec_key);
    return ret;
}

uint64_t cp_gen_keypair(char *pubkey, char *prikey) {
    uint64_t ret = CP_SUCCESS;
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group = NULL;
    const BIGNUM *bn_prikey = NULL;
    const EC_POINT *ec_point = NULL;
    char *buf = NULL;

    ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    if (ec_group == NULL) {
        ret = ERR_peek_last_error();
        return ret;
    }

    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        ret = ERR_peek_last_error();
        EC_GROUP_free(ec_group);
        return ret;
    }

    EC_KEY_set_group(ec_key, ec_group);

    ret = (uint64_t)EC_KEY_generate_key(ec_key);
    if (ret != CP_SUCCESS) {
        ret = ERR_peek_last_error();
        goto end;
    }

    bn_prikey = EC_KEY_get0_private_key(ec_key);
    buf = BN_bn2hex(bn_prikey);
    strcpy(prikey, buf);
    OPENSSL_free(buf);

    ec_point = EC_KEY_get0_public_key(ec_key);
    buf = EC_POINT_point2hex(ec_group, ec_point, POINT_CONVERSION_UNCOMPRESSED, NULL);
    strcpy(pubkey, buf);
    OPENSSL_free(buf);

end:
    EC_KEY_free(ec_key);
    return ret;
}

uint64_t cp_sm2_pubkey_encoding(uint8_t *pubkey, size_t pubkey_len,
                             uint8_t **pubkey_der, int *pubkey_der_len) {
    uint64_t ret;
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group = NULL;
    EC_POINT *ec_point = NULL;
    uint8_t *buf = NULL;
    char *pubkey_hex = NULL;
    int len = 0;

    ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    if (ec_group == NULL) {
        ret = ERR_peek_last_error();
        return ret;
    }

    ret = cm_bin2hex(pubkey, pubkey_len, &pubkey_hex);
    if (ret != 0) {
        EC_GROUP_free(ec_group);
        return ret;
    }

    ec_point = EC_POINT_hex2point(ec_group, pubkey_hex, NULL, NULL);
    if (ec_point == NULL) {
        ret = ERR_peek_last_error();
        EC_GROUP_free(ec_group);
        return ret;
    }

    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        ret = ERR_peek_last_error();
        EC_GROUP_free(ec_group);
        EC_POINT_free(ec_point);
        return ret;
    }

    EC_KEY_set_group(ec_key, ec_group);
    EC_KEY_set_public_key(ec_key, ec_point);
    //TODO not right
    len = i2d_EC_PUBKEY(ec_key, &buf);

    *pubkey_der = buf;
    *pubkey_der_len = len;

    ret = CP_SUCCESS;
    free(pubkey_hex);
    EC_GROUP_free(ec_group);
    EC_POINT_free(ec_point);
    EC_KEY_free(ec_key);
    return ret;
}

uint64_t cp_new_eckey_by_hex_pubkey(char *hex_pubkey, EC_KEY **ec_key) {

    EC_KEY *key = NULL;
    EC_POINT *ec_point = NULL;
    key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    ec_point = EC_POINT_hex2point(EC_KEY_get0_group(key), hex_pubkey, NULL, NULL);
    EC_KEY_set_public_key(key, ec_point);

    *ec_key = key;

    return CP_SUCCESS;
}

uint64_t cp_new_eckey_by_hex_pubkey_prikey(char *hex_pubkey, char *hex_prikey,
                                           EC_KEY **ec_key) {

    EC_KEY *key = NULL;
    EC_POINT *ec_point = NULL;
    BIGNUM *bn_prikey = NULL;

    key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    ec_point = EC_POINT_hex2point(EC_KEY_get0_group(key), hex_pubkey, NULL, NULL);
    EC_KEY_set_public_key(key, ec_point);
    BN_hex2bn(&bn_prikey, hex_prikey);
    EC_KEY_set_private_key(key, bn_prikey);

    *ec_key = key;

    return CP_SUCCESS;
}

uint64_t cp_hex_pubkey_2_evpkey(char *hex_pubkey, EVP_PKEY **pkey) {
    EVP_PKEY *evp_pkey = NULL;
    EC_KEY *ec_key = NULL;

    cp_new_eckey_by_hex_pubkey(hex_pubkey, &ec_key);

    EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key);

    *pkey = evp_pkey;
    return CP_SUCCESS;
}

uint64_t cp_hex_pubkey_prikey_2_evpkey(char *hex_pubkey, char *hex_prikey,
                                       EVP_PKEY **pkey) {
    EVP_PKEY *evp_pkey = NULL;
    EC_KEY *ec_key = NULL;

    cp_new_eckey_by_hex_pubkey_prikey(hex_pubkey, hex_prikey, &ec_key);

    EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key);

    *pkey = evp_pkey;
    return CP_SUCCESS;
}

uint64_t cp_build_x509_req(X509_REQ **x509_req, char *c, char *cn, char *o,
                           char *ou, char *l, char *pubkey, char *prikey) {
    X509_REQ *req = NULL;
    X509_NAME *x509_name = NULL;
    EVP_PKEY *pkey = NULL;

    req = X509_REQ_new();
    x509_name = X509_REQ_get_subject_name(req);

    X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, ou, -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, l, -1, -1, 0);

    X509_REQ_set_version(req, 0L);

    cp_hex_pubkey_prikey_2_evpkey(pubkey, prikey, &pkey);
    X509_REQ_set_pubkey(req, pkey);

//    X509_ALGOR_set0(req, ASN1_OBJECT *aobj, int ptype,
//    void *pval);

    X509_REQ_sign(req, pkey, EVP_sm3());

}