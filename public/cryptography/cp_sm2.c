//
// Created by chenwenjing on 5/6/19.
//

#include "cp_sm2.h"

#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/ec.h>

#include "cm_utils.h"
#include "cp_defines.h"

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
    if (ret != CM_SUCCESS) {
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

uint64_t cp_gen_sm2_keypair(char *pubkey, char *prikey) {
    uint64_t ret = CP_SUCCESS;
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group = NULL;
    const BIGNUM *bn_prikey = NULL;
    const EC_POINT *ec_point = NULL;
    char *buf = NULL;
    uint8_t msg[32] = {0x11};
    uint8_t sig[72] = {0};
    uint32_t siglen = sizeof(sig);

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

    //verify key pair
    ret = cp_sm2_sign(ec_key, msg, sizeof(msg), 1, sig, &siglen);
    if (ret != CP_SUCCESS) {
        printf("cp_sm2_sign failed\n");
        goto end;
    }

    int t = cp_sm2_verify(ec_key, msg, sizeof(msg), 1, sig, siglen);
    if (t != CP_SUCCESS) {
        printf("cp_sm2_verify failed\n");
        goto end;
    }

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
    if (ret != CM_SUCCESS) {
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

    evp_pkey = EVP_PKEY_new();

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

//uint64_t cp_build_x509_req(X509_REQ **x509_req, char *c, char *cn, char *o,
//                           char *ou, char *l, char *pubkey, char *prikey) {
//    X509_REQ *req = NULL;
//    X509_NAME *x509_name = NULL;
//    EVP_PKEY *pkey = NULL;
//
//    req = X509_REQ_new();
//    x509_name = X509_REQ_get_subject_name(req);
//
//    X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, c, -1, -1, 0);
//    X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
//    X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, o, -1, -1, 0);
//    X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, ou, -1, -1, 0);
//    X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, l, -1, -1, 0);
//
//    X509_REQ_set_version(req, 0L);
//
//    cp_hex_pubkey_prikey_2_evpkey(pubkey, prikey, &pkey);
//    X509_REQ_set_pubkey(req, pkey);
//
////    X509_ALGOR_set0(req, ASN1_OBJECT *aobj, int ptype,
////    void *pval);
//
//    X509_REQ_sign(req, pkey, EVP_sm3());
//
//}

uint64_t cp_sm2_sign(EC_KEY *ec_key, uint8_t *msg, int msg_len, int pre_process,
                     uint8_t *signature, uint32_t *signature_len) {
    uint64_t rc = 0;
    int type = NID_undef;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstlen = sizeof(dgst);
    const EVP_MD *md = EVP_sm3();

    if(!msg || !signature || !ec_key) {
        return rc;
    }
    if(pre_process) {
        if(!SM2_compute_message_digest(md, md, (const unsigned char *)msg, (size_t)msg_len, SM2_DEFAULT_ID_GMT09, 16,
                                       dgst, &dgstlen, ec_key)){
            rc = ERR_get_error();
            goto end;
        }

        if (SM2_sign(type, dgst, (int)dgstlen, signature, signature_len, ec_key) != 1) {
            rc = ERR_peek_last_error();
            goto end;
        }
    } else {
        if (!SM2_sign(type, msg, msg_len, signature, signature_len, ec_key)) {
            rc = ERR_peek_last_error();
            goto end;
        }
    }
    rc = CP_SUCCESS;
    end:
    return rc;
}


int cp_sm2_verify(EC_KEY *ec_key, uint8_t *msg, int msg_len, int pre_process,
                     uint8_t *signature, int signature_len) {
    int rc = -1;
    uint64_t inner_ret;
    int type = NID_undef;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstlen = sizeof(dgst);
    const EVP_MD *md = EVP_sm3();

    if(!msg || !signature || !ec_key) {
        return rc;
    }
    if(pre_process) {
        if(!SM2_compute_message_digest(md, md, (const unsigned char *)msg, (size_t)msg_len, SM2_DEFAULT_ID_GMT09, 16,
                                       dgst, &dgstlen, ec_key)){
            inner_ret = ERR_peek_last_error();
            goto end;
        }

        if (SM2_verify(type, dgst, (int)dgstlen, signature, signature_len, ec_key) != 1) {
            inner_ret = ERR_peek_last_error();
            goto end;
        }
    } else {
        if (!SM2_verify(type, msg, msg_len, signature, signature_len, ec_key)) {
            inner_ret = ERR_peek_last_error();
            goto end;
        }
    }
    rc = CP_SUCCESS;
end:
    return rc;
}

uint64_t cp_get_ec_key_from_cert(uint8_t *cert, int cert_len, EC_KEY **ec_key) {
    uint64_t rc;
    uint8_t *p = cert;
    X509 *x509 = NULL;
    EVP_PKEY *evp_pkey = NULL;
    EC_KEY *key = NULL;

    x509 = d2i_X509(NULL, (const uint8_t**)&p, cert_len);
    if (x509 == NULL) {
        rc = ERR_peek_last_error();
        return rc;
    }

    evp_pkey = X509_get0_pubkey(x509);

    key = EVP_PKEY_get0_EC_KEY(evp_pkey);

    *ec_key = EC_KEY_dup(key);

    X509_free(x509);

    return CP_SUCCESS;
}

void cp_sm2_init() {

    ERR_load_ERR_strings();
    ERR_load_CRYPTO_strings();
}

int cp_sm2_kp_check(uint8_t *prikey, int prikey_len, uint8_t *pubkey, int pubkey_len) {
    int ret = 0;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *ec_group = NULL;
    EC_POINT *ec_point = NULL;
    BIGNUM *bn_pri = NULL;
    BIGNUM *bn_pub_x = NULL;
    BIGNUM *bn_pub_y = NULL;
    uint8_t buf[64] = {0};

    if (pubkey_len != 65) {
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (ec_key == NULL) {
        return ret;
    }

    ec_group = EC_KEY_get0_group(ec_key);

    ec_point = EC_POINT_new(ec_group);
    if (ec_point == NULL) {
        goto end;
    }

    bn_pri = BN_new();
    bn_pub_x = BN_new();
    bn_pub_y = BN_new();
    if (bn_pri == NULL || bn_pub_x == NULL || bn_pub_y == NULL) {
        goto end;
    }

    bn_pri = BN_bin2bn(prikey, prikey_len, NULL);
    if (bn_pri == NULL) {
        goto end;
    }

    ret = EC_POINT_mul(ec_group, ec_point, bn_pri, NULL, NULL, NULL);
    if (ret != 1) {
        goto end;
    }

    ret = EC_POINT_get_affine_coordinates_GFp(ec_group, ec_point, bn_pub_x, bn_pub_y, NULL);
    if (ret != 1) {
        goto end;
    }

    BN_bn2bin(bn_pub_x, buf);
    BN_bn2bin(bn_pub_y, buf+32);

    if (memcmp(pubkey + 1, buf, 32) != 0 || memcmp(pubkey + 33, buf + 32, 32) != 0) {
        ret = 0;
        goto end;
    }
    ret = CP_SUCCESS;
end:
    EC_KEY_free(ec_key);
    EC_POINT_free(ec_point);
    BN_free(bn_pri);
    BN_free(bn_pub_x);
    BN_free(bn_pub_y);
    return ret;
}