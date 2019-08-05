//
// Created by root on 8/2/19.
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ca_define.h"
#include "global.h"
#include "cp_x509.h"
#include "cp_defines.h"
#include "cm_utils.h"
#include "cp_sm2.h"

#include "openssl/x509.h"


static int _gen_sm2_cert(uint8_t *csr, int csr_len, char *cert_type, char *ca_path, char *cert_path);
static int _set_cert_subject(X509 *x509, X509_NAME *subject, char *path);
static int _get_cert_sn(char *path, long *sn);
static int _set_cert_validity(char *path, X509 *x509);
static int _do_x509_sign(X509 *x509, char *cert_path, char *cert_type);
static int _set_cert_sn(long sn, char *ca_path);
static int _save_cert(X509 *x509, char *cert_path);

static int _gen_sm2_cert(uint8_t *csr, int csr_len, char *cert_type, char *ca_path, char *cert_path) {
    int ret;
    X509_NAME *subject = NULL;
    EVP_PKEY *evp_pkey = NULL;
    X509 *x509 = NULL;
    char path_buf[256] = {0};
    long cert_sn = 0;

    x509 = X509_new();

    ret = cp_get_x509_subject_from_csr(csr, csr_len, &subject);
    if (ret != CP_SUCCESS) {
        printf("cp_get_x509_subject_from_csr failed\n");
        goto end;
    }

    ret = cp_get_x509_pkey_from_csr(csr, csr_len, &evp_pkey);
    if (ret != CP_SUCCESS) {
        printf("cp_get_x509_pkey_from_csr failed\n");
        goto end;
    }

    strcpy(path_buf, ca_path);
    strcat(path_buf, "/");

    if (strcmp(cert_type, CERT_TYPE_ROOT) == 0) {
        if (X509_set_subject_name(x509, subject) != 1) {
            printf("set subject name failed\n");
            goto end;
        }

        if (X509_set_issuer_name(x509, subject) != 1) {
            printf("set issuer name failed\n");
            goto end;
        }

    } else if (strcmp(cert_type, CERT_TYPE_SUB) == 0) {
        strcat(path_buf, CERT_NAME_ROOT);
        ret = _set_cert_subject(x509, subject, path_buf);
        if (ret != ERR_OK) {
            printf("_set_cert_subject failed\n");
            goto end;
        }
    } else {
        strcat(path_buf, CERT_NAME_SUB);
        ret = _set_cert_subject(x509, subject, path_buf);
        if (ret != ERR_OK) {
            printf("_set_cert_subject failed\n");
            goto end;
        }
    }

    ret = _get_cert_sn(ca_path, &cert_sn);
    if (ret != ERR_OK) {
        printf("_get_cert_sn failed\n");
        goto end;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), cert_sn);

    if (!X509_set_version(x509, 2)) {
        printf("X509_set_version failed\n");
        goto end;
    }

    X509_set_pubkey(x509, evp_pkey);

    ret = _set_cert_validity(ca_path, x509);
    if (ret != ERR_OK) {
        printf("_set_cert_validity failed\n");
        goto end;
    }

    ret = cp_copy_extensions(x509, csr, csr_len, EXT_COPY_ADD);
    if (ret != CP_SUCCESS) {
        printf("cp_copy_extensions failed\n");
        goto end;
    }

    ret = _do_x509_sign(x509, ca_path, cert_type);
    if (ret != ERR_OK) {
        printf("_do_x509_sign failed\n");
        goto end;
    }

    ret = _set_cert_sn(cert_sn+1, ca_path);
    if (ret != ERR_OK) {
        printf("_set_cert_sn failed\n");
        goto end;
    }

    ret = _save_cert(x509, cert_path);
    if (ret != ERR_OK) {
        printf("_save_cert failed\n");
        goto end;
    }

end:
    return ret;
}

static int _set_cert_subject(X509 *x509, X509_NAME *subject, char *path) {
    int ret;
    uint8_t *cert = NULL;
    int cert_len = 0;
    X509_NAME *issuer = NULL;

    cm_read_bin_file(path, &cert, &cert_len);

    ret = cp_get_x509_subject_from_cer(cert, cert_len, &issuer);
    if (ret != CP_SUCCESS) {
        printf("cp_get_x509_subject_from_cer failed\n");
        goto end;
    }

    if (X509_set_subject_name(x509, subject) != 1) {
        printf("X509_set_subject_name failed\n");
        goto end;
    }

    if (X509_set_issuer_name(x509, issuer) != 1) {
        printf("X509_set_issuer_name failed\n");
        goto end;
    }
    ret = ERR_OK;
end:
    if (cert != NULL) {
        free(cert);
    }
    return ret;
}

static int _get_cert_sn(char *path, long *sn)
{
    int ret = 0;
    char sn_path[256] = {0};
    char *str_sn = NULL;
    int str_sn_len = 0;

    strcpy(sn_path, path);
    strncat(sn_path, "/", sizeof(sn_path) - strlen(sn_path));
    strncat(sn_path, SN_FILE_NAME, sizeof(sn_path) - strlen(sn_path));

    ret = cm_read_str_file(sn_path, (uint8_t**)&str_sn, &str_sn_len);
    if (ret != CM_SUCCESS) {
        printf("cm_read_str_file failed, path: %s\n", sn_path);
        return ret;
    }

    if (str_sn[strlen(str_sn)-1] == '\n') {
        str_sn[strlen(str_sn)-1] = '\0';
    }

    if (cm_is_number(str_sn) != CM_SUCCESS) {
        printf("SN is not number, sn: %s\n", str_sn);
        goto end;
    }
    *sn = atol(str_sn);

    ret = ERR_OK;

    end:
    if (NULL != str_sn) {
        free(str_sn);
    }
    return ret;
}

static int _set_cert_validity(char *path, X509 *x509) {
    int ret;
    char conf_path[256] = {0};
    int str_len;
    int validity;
    char *str_validity = NULL;

    strcpy(conf_path, path);
    strncat(conf_path, "/", sizeof(conf_path) - strlen(conf_path));
    strncat(conf_path, VALIDITY_FILE_NAME, sizeof(conf_path) - strlen(conf_path));

    ret = cm_read_str_file(conf_path, (uint8_t**)&str_validity, &str_len);
    if (ret != CM_SUCCESS) {
        printf("read_file [%s] failed\n", conf_path);
        return 0;
    }

    if (str_validity[strlen(str_validity)-1] == '\n') {
        str_validity[strlen(str_validity)-1] = '\0';
    }

    if (cm_is_number(str_validity) != CM_SUCCESS) {
        printf("validity is not number\n");
        goto end;
    }
    validity = (int)atol(str_validity);

    ret = cp_set_cert_validity(x509, NULL, NULL, validity);
    if (ret != CP_SUCCESS) {
        printf("cp_set_cert_validity failed\n");
        goto end;
    }
    ret = ERR_OK;
end:
    if (str_validity != NULL) {
        free(str_validity);
    }

    return ret;
}

static int _do_x509_sign(X509 *x509, char *cert_path, char *cert_type) {
    int ret = 0;
    uint64_t cp_ret;
    uint8_t *cert_info = NULL;
    int cert_info_len = 0;
    char pubkey_path_buf[256] = {0};
    char prikey_path_buf[256] = {0};
    char *pubkey = NULL;
    int pubkey_len = 0;
    char *prikey = NULL;
    int prikey_len = 0;
    EC_KEY *ec_key = NULL;
    uint8_t sig[72] = {0};
    uint32_t sig_len = sizeof(sig);

    cp_set_x509_signature_alg(x509);

    ret = cp_get_x509_cert_info_der(x509, &cert_info, &cert_info_len);
    if (ret != CP_SUCCESS) {
        printf("cp_get_x509_cert_info_der, 0x%08X\n", ret);
        return ret;
    }

    strcpy(pubkey_path_buf, cert_path);
    strcpy(prikey_path_buf, cert_path);

    strncat(pubkey_path_buf, "/", sizeof(pubkey_path_buf) - strlen(pubkey_path_buf));
    strncat(prikey_path_buf, "/", sizeof(prikey_path_buf) - strlen(prikey_path_buf));

    if (strcmp(cert_type, CERT_TYPE_ROOT) == 0 || strcmp(cert_type, CERT_TYPE_SUB) == 0) {
        strcat(pubkey_path_buf, ROOT_PUBKEY_NAME);
        strcat(prikey_path_buf, ROOT_PRIKEY_NAME);
    } else if (strcmp(cert_type, CERT_TYPE_LEAF) == 0){
        strcat(pubkey_path_buf, SUB_PUBKEY_NAME);
        strcat(prikey_path_buf, SUB_PRIKEY_NAME);
    }

    ret = cm_read_str_file(pubkey_path_buf, (uint8_t**)&pubkey, &pubkey_len);
    if (ret != CM_SUCCESS) {
        printf("cm_read_str_file failed, path: %s\n", pubkey_path_buf);
        goto end;
    }

    ret = cm_read_str_file(prikey_path_buf, (uint8_t**)&prikey, &prikey_len);
    if (ret != CM_SUCCESS) {
        printf("cm_read_str_file failed, path: %s\n", prikey_path_buf);
        goto end;
    }

    cp_ret = cp_new_eckey_by_hex_pubkey_prikey(pubkey, prikey, &ec_key);
    if (cp_ret != CP_SUCCESS) {
        printf("cp_hex_pubkey_prikey_2_eckey failed\n");
        ret = (int)cp_ret;
        goto end;
    }

    cp_ret = cp_sm2_sign(ec_key, cert_info, cert_info_len, 1, sig, &sig_len);
    if (cp_ret != CP_SUCCESS) {
        printf("cp_sm2_sign failed\n");
        ret = (int)cp_ret;
        goto end;
    }

    cp_set_x509_signature(x509, sig, sig_len);

    ret = ERR_OK;
end:
    if (cert_info != NULL) {
        free(cert_info);
    }
    if (pubkey != NULL) {
        free(pubkey);
    }
    if (prikey != NULL) {
        free(prikey);
    }
    EC_KEY_free(ec_key);
    return ret;
}

static int _set_cert_sn(long sn, char *ca_path) {
    char sn_path[256] = {0};
    char sn_str[16] = {0};

    strcpy(sn_path, ca_path);
    strncat(sn_path, "/", sizeof(sn_path) - strlen(sn_path));
    strncat(sn_path, SN_FILE_NAME, sizeof(sn_path) - strlen(sn_path));

    sprintf(sn_str, "%lu", sn);

    if(cm_write_str_file(sn_path, sn_str) != CM_SUCCESS) {
        printf("cm_write_str_file failed, sn_path: %s\n", sn_path);
        return 1;
    }
    return ERR_OK;
}

static int _save_cert(X509 *x509, char *cert_path) {
    FILE *fp = NULL;

    fp = fopen(cert_path, "wb");
    if (fp == NULL) {
        printf("open cert output file failed, path: %s\n", cert_path);
        return 0;
    }

    i2d_X509_fp(fp, x509);

    fclose(fp);

    return ERR_OK;
}

//crypto_tools gen_sm2_cert -csr xx.csr -type root/sub/leaf -ca_path xxx -cert_path xxx.cer
int gen_sm2_cert_main(int argc, char **argv) {
    int ret = 1;
    char *csr_path = NULL;
    char *cert_path = NULL;
    char *cert_type = NULL;
    char *ca_path = NULL;
    int index = 2;
    uint8_t *csr = NULL;
    int csr_len = 0;
    FILE *fp = NULL;

    if (argc < 10) {
        printf("input arguments invalid, example as flow:\n");
        printf("  crypto_tools gen_sm2_cert -csr xxx.csr -type root/sub/leaf -ca_path xxx -cert_path xxx\n");
        return 1;
    }

    while(index < 10){
        for(;;){
            if (strcmp(OPT_CSR, argv[index]) == 0) {
                csr_path = argv[++index];
                break;
            }
            if (strcmp(OPT_TYPE, argv[index]) == 0) {
                cert_type = argv[++index];
                break;
            }
            if (strcmp(OPT_CA_PATH, argv[index]) == 0) {
                ca_path = argv[++index];
                break;
            }
            if (strcmp(OPT_CERT_PATH, argv[index]) == 0) {
                cert_path = argv[++index];
                break;
            }
            ++index;
            break;
        }
    }

    if (strcmp(cert_type, CERT_TYPE_ROOT) != 0 &&
        strcmp(cert_type, CERT_TYPE_SUB) != 0 &&
        strcmp(cert_type, CERT_TYPE_LEAF) != 0) {
        printf("cert type invalid, must root or sub or leaf\n");
        return ret;
    }

    fp = fopen(csr_path, "rb");
    if (fp == NULL) {
        printf("open csr file failed, path: %s\n", csr_path);
        return ret;
    }

    ret = cm_read_bin_file(csr_path, &csr, &csr_len);
    if (ret != CM_SUCCESS) {
        printf("cm_read_bin_file failed\n");
        goto end;
    }

    ret = _gen_sm2_cert(csr, csr_len, cert_type, ca_path, cert_path);
    if (ret != ERR_OK) {
        printf("_gen_sm2_cert failed\n");
        goto end;
    }

    printf("generate sm2 certificate successful, path: %s\n", cert_path);
end:
    if (csr != NULL) {
        free(csr);
    }
    fclose(fp);
    return ret;
}