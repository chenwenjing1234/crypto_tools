//
// Created by chenwenjing on 5/6/19.
//

#ifndef CRYPTO_TOOLS_CP_SM2_H
#define CRYPTO_TOOLS_CP_SM2_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/x509.h>

int test();

/**
 *
 * @param pubkey        compress type | data
 * @param pubkey_len
 * @param plain
 * @param plain_len
 * @param cipher
 * @param cipher_len
 * @return
 */
uint64_t cp_sm2_enc(uint8_t *pubkey, uint32_t pubkey_len,
                    uint8_t *plain, size_t plain_len,
                    uint8_t **cipher, size_t *cipher_len);

/**
 *
 * @param prikey        32 bytes
 * @param prikey_len
 * @param cipher
 * @param cipher_len
 * @param plain
 * @param plain_len
 * @return
 */
uint64_t cp_sm2_dec(uint8_t *prikey, uint32_t prikey_len,
                    uint8_t *cipher, size_t cipher_len,
                    uint8_t **plain, size_t *plain_len);

uint64_t cp_gen_sm2_keypair(char *pubkey, char *prikey);

uint64_t cp_sm2_pubkey_encoding(uint8_t *pubkey, size_t pubkey_len,
                             uint8_t **pubkey_der, int *pubkey_der_len);

//uint64_t cp_build_x509_req(X509_REQ **x509_req, char *c, char *cn, char *o,
//                           char *ou, char *l, char *pubkey, char *prikey);

uint64_t cp_new_eckey_by_hex_pubkey(char *hex_pubkey, EC_KEY **ec_key);

uint64_t cp_hex_pubkey_2_evpkey(char *hex_pubkey, EVP_PKEY **pkey);

uint64_t cp_hex_pubkey_prikey_2_evpkey(char *hex_pubkey, char *hex_prikey, EVP_PKEY **pkey);

uint64_t cp_hex_pubkey_prikey_2_eckey(char *hex_pubkey, char *hex_prikey, EC_KEY **ec_key);

uint64_t cp_new_eckey_by_hex_pubkey_prikey(char *hex_pubkey, char *hex_prikey, EC_KEY **ec_key);

uint64_t cp_sm2_sign(EC_KEY *ec_key, uint8_t *msg, int msg_len, int pre_process,
                     uint8_t *signature, uint32_t *signature_len);

int cp_sm2_verify(EC_KEY *ec_key, uint8_t *msg, int msg_len, int pre_process,
                     uint8_t *signature, int signature_len);

uint64_t cp_get_ec_key_from_cert(uint8_t *cert, int cert_len, EC_KEY **ec_key);

void cp_sm2_init();

int cp_sm2_kp_check(uint8_t *prikey, int prikey_len, uint8_t *pubkey, int pubkey_len);

#endif //CRYPTO_TOOLS_CP_SM2_H
