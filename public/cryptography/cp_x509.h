//
// Created by root on 8/1/19.
//

#ifndef CRYPTO_TOOLS_CP_X509_H
#define CRYPTO_TOOLS_CP_X509_H

#include "openssl/ec.h"



int cp_build_x509_req(EVP_PKEY *pubkey, X509_NAME *subject, int is_ca, unsigned char *reqinfo, int *reqinfol);

int cp_create_sm2_csr(uint8_t *req_info, int req_info_len, uint8_t *sig, int sig_len, uint8_t *csr, int *csr_len);

int cp_get_x509_subject_from_csr(uint8_t *csr, int csr_len, X509_NAME **subject);

int cp_get_x509_pkey_from_csr(uint8_t *csr, int csr_len, EVP_PKEY **pEVP_pkey);

int cp_get_x509_subject_from_cer(uint8_t *cert, int cert_len, X509_NAME **subject);

int cp_set_cert_validity(X509 *x, const char *start_date, const char *end_date, int days);

int cp_copy_extensions(X509 *x, uint8_t *csr, int csr_len, int copy_type);

void cp_set_x509_signature_alg(X509 *x509);

int cp_get_x509_cert_info_der(X509 *x509, uint8_t **cert_info, int *len);

void cp_set_x509_signature(X509 *x509, uint8_t *sig, int sig_len);


#endif //CRYPTO_TOOLS_CP_X509_H
