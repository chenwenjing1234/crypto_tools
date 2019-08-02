//
// Created by chenwenjing on 6/12/19.
//
#include <stdio.h>
#include <cm_utils.h>
#include <string.h>
#include <cp_sm2.h>
#include <stdlib.h>
#include "ca_define.h"
#include "cp_x509.h"
#include "global.h"
#include "cp_defines.h"

//crypto_utils gen_sm2_csr -pubkey xx [-prikey xx] -csr_out_path xxxx

static int _build_x509_req(char *pubkey_hex, uint8_t *req_info, int *req_info_len);
static int _build_x509_name(X509_NAME **x509_name, char *sn);
static int _get_cert_sn(char *sn);
static int _gen_csr(uint8_t *req_info, int req_info_len, char *pubkey_hex, char *prikey_hex,
                    uint8_t *csr, int *csr_len);
static int _save_csr(uint8_t *csr, size_t csr_len, char *csr_path);


static int _build_x509_req(char *pubkey_hex, uint8_t *req_info, int *req_info_len) {
    int ret = 0;
    uint64_t cp_ret;
    X509_NAME *x509_name = NULL;
    EVP_PKEY *pkey = NULL;
    char sn[8] = {0};

    ret = _get_cert_sn(sn);
    if (ret != ERR_OK) {
        printf("_get_cert_sn failed\n");
        return ret;
    }

    ret = _build_x509_name(&x509_name, sn);
    if (ret != ERR_OK) {
        return ret;
    }

    cp_ret = cp_hex_pubkey_2_evpkey(pubkey_hex, &pkey);
    if (cp_ret != CP_SUCCESS) {
        ret = (int)cp_ret;
        goto end;
    }

    ret = cp_build_x509_req(pkey, x509_name, 1, req_info, req_info_len);
    if (ret != CP_SUCCESS) {
        goto end;
    }
    ret = ERR_OK;
end:
    X509_NAME_free(x509_name);
    EVP_PKEY_free(pkey);
    return ret;
}

static int _build_x509_name(X509_NAME **x509_name, char *sn) {
    X509_NAME *name = NULL;

    char C[8] = {0};
    char CN[60] = {0};
    char O[60] = {0};
    char OU[60] = {0};
    char L[60] = {0};
    char S[60] = {0};

    name = X509_NAME_new();
    if (name == NULL) {
        return 1;
    }

    printf("country code (C):");
    fgets(C, sizeof(C), stdin);
    C[strlen(C)-1] = '\0';

    printf("common name (CN):");
    fgets(CN, sizeof(CN), stdin);
    CN[strlen(CN)-1] = '\0';

    printf("organization (O):");
    fgets(O, sizeof(O), stdin);
    O[strlen(O)-1] = '\0';

    printf("organizational unit name (OU):");
    fgets(OU, sizeof(OU), stdin);
    OU[strlen(OU)-1] = '\0';

    printf("locality name (L):");
    fgets(L, sizeof(L), stdin);
    L[strlen(L)-1] = '\0';

    printf("state, or province name (S):");
    fgets(S, sizeof(S), stdin);
    S[strlen(S)-1] = '\0';

    X509_NAME_add_entry_by_txt(name, "serialNumber", MBSTRING_ASC, sn, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, CN, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, C, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, OU, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, O, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, S, -1, -1, 0);

    *x509_name = name;

    return ERR_OK;
}

static int _get_cert_sn(char *sn) {
    char *p = "123";

    strcpy(sn, p);
    return ERR_OK;
}

static int _gen_csr(uint8_t *req_info, int req_info_len, char *pubkey_hex, char *prikey_hex,
                    uint8_t *csr, int *csr_len) {
    int ret;
    uint64_t cp_ret;
    EC_KEY *ec_key = NULL;
    uint8_t sig[72] = {0};
    uint32_t sig_len = sizeof(sig);

    cp_ret = cp_new_eckey_by_hex_pubkey_prikey(pubkey_hex, prikey_hex, &ec_key);
    if (cp_ret != CP_SUCCESS) {
        ret = (int)cp_ret;
        return ret;
    }

    cp_ret = cp_sm2_sign(ec_key, req_info, req_info_len, 1, sig, &sig_len);
    if (cp_ret != CP_SUCCESS) {
        ret = (int)cp_ret;
        goto end;
    }

    ret = cp_create_sm2_csr(req_info, req_info_len, sig, sig_len, csr, csr_len);
    if (ret != CP_SUCCESS) {
        goto end;
    }

    ret = ERR_OK;
end:
    EC_KEY_free(ec_key);
    return ret;
}

static int _save_csr(uint8_t *csr, size_t csr_len, char *csr_path) {
    FILE *fp = NULL;

    fp = fopen(csr_path, "wb+");
    if (fp == NULL) {
        printf("open file failed, path: %s\n", csr_path);
        return 1;
    }

    fwrite(csr, 1, csr_len, fp);

    fclose(fp);

    return ERR_OK;
}

int gen_sm2_csr_main(int argc, char **argv) {
    int ret = ERR_OK;
    int index = 2;
    char *pubkey_hex = NULL;
    char *prikey_hex = NULL;
    char *csr_path = NULL;
    uint8_t req_info[512] = {0};
    int req_info_len = sizeof(req_info);
    uint8_t csr[512] = {0};
    int csr_len = sizeof(csr);

    if (argc < 8) {
        printf("input arguments invalid, example as flow:\n");
        printf("  crypto_tools gen_sm2_csr -pubkey xx -prikey xx -csr_out_path xx\n");
        return 1;
    }

    while(index < 7){
        for(;;){
            if (strcmp(OPT_PUBKEY, argv[index]) == 0) {
                pubkey_hex = argv[++index];
                break;
            }
            if (strcmp(OPT_PRIKEY, argv[index]) == 0) {
                prikey_hex = argv[++index];
                break;
            }
            if (strcmp(OPT_PATH, argv[index]) == 0) {
                csr_path = argv[++index];
                break;
            }
            ++index;
            break;
        }
    }

    ret = _build_x509_req(pubkey_hex, req_info, &req_info_len);
    if (ret != ERR_OK) {
        printf("_build_x509_req failed\n");
        goto end;
    }

    ret = _gen_csr(req_info, req_info_len, pubkey_hex, prikey_hex, csr, &csr_len);
    if (ret != ERR_OK) {
        printf("_gen_csr failed\n");
        goto end;
    }

    ret = save_bin_file(csr, (size_t)csr_len, csr_path);
    if (ret != ERR_OK) {
        printf("save_bin_file failed\n");
        goto end;
    }

    printf("generate csr success\n");

end:
    return ret;
}
