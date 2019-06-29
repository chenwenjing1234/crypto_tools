//
// Created by chenwenjing on 6/12/19.
//
#include <stdio.h>
#include <cm_utils.h>
#include <string.h>
#include <cp_sm2.h>
#include <stdlib.h>
#include "ca_define.h"

//crypto_utils gen_sm2_csr -pubkey xx [-prikey xx] -csr_out_path xxxx

static int _build_x509_req(X509_REQ **x509_req, char *pubkey_hex) {
    int ret = 0;
    X509_REQ *req = NULL;
    X509_NAME *x509_name = NULL;

    char C[8] = {0};
    char CN[60] = {0};
    char U[60] = {0};
    char OU[60] = {0};
    char L[60] = {0};

    printf("C:");
    fgets(C, sizeof(C), stdin);

    printf("CN:");
    fgets(CN, sizeof(CN), stdin);

    printf("U:");
    fgets(U, sizeof(U), stdin);

    printf("OU:");
    fgets(OU, sizeof(OU), stdin);

    printf("L:");
    fgets(L, sizeof(L), stdin);

    req = X509_REQ_new();
//    x509_name = X509_REQ_get_subject_name();
//
//    X509_NAME_add_entry_by_txt()
//
//    X509_REQ_set_subject_name();
//    X509_REQ_set_version();
//    X509_REQ_set_pubkey();

}



int gen_csr_main(int argc, char **argv) {
    int ret = 1;
    uint64_t ret_code;
    int index = 2;
    char *pubkey_hex = NULL;
    uint8_t *pubkey_bin = NULL;
    uint32_t pubkey_bin_len = 0;
    char *prikey_hex = NULL;
    uint8_t *prikey_bin = NULL;
    uint32_t prikey_bin_len = 0;
    char *csr_path = NULL;
    X509_REQ *x509_req = NULL;

    uint8_t *csr = NULL;
    int csr_len = 0;

    if (argc < 6) {
        printf("input arguments invalid, example as flow:\n");
        printf("  crypto_tools gen_sm2_csr -pubkey xx [-prikey xx] -csr_out_path xx\n");
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
            if (strcmp(OPT_CSR_OUT_PATH, argv[index]) == 0) {
                csr_path = argv[++index];
                break;
            }
            ++index;
            break;
        }
    }

    ret = _build_x509_req(&x509_req, pubkey_hex);
    if (ret != 1) {
        printf("_build_x509_req failed\n");
        goto end;
    }


    if (0x00 != cm_hex2bin(pubkey_hex, &pubkey_bin, &pubkey_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }

    if (0x00 != cm_hex2bin(prikey_hex, &prikey_bin, &prikey_bin_len)) {
        printf("convert hex to bin failed\n");
        goto end;
    }




//
//    ret_code = cp_sm2_pubkey_encoding(pubkey_bin, pubkey_bin_len,
//                                      &pubkey_der, &pubkey_der_len);
//    if (ret_code != CP_SUCCESS) {
//        printf("cp_sm2_pubkey_encoding failed, ret = %lx", ret_code);
//        goto end;
//    }
//
//    if (0x00 != cm_bin2hex(pubkey_der, (size_t)pubkey_der_len, &pubkey_der_hex)) {
//        printf("convert bin to hex failed\n");
//        goto end;
//    }
//    ret = 0;
//    printf("pubkey DER: %s\n", pubkey_der_hex);
    end:
//    if (pubkey_bin != NULL) {
//        free(pubkey_bin);
//    }
//    if (pubkey_der != NULL) {
//        free(pubkey_der);
//    }
//
//    if (pubkey_der_hex != NULL) {
//        free(pubkey_der_hex);
//    }
    return ret;

}
