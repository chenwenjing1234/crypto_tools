//
// Created by chenwenjing on 6/3/19.
//

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "global.h"
#include "ca_define.h"

func_table_st g_func_table[] = {
        {HELP, print_help_info, "use --help get help information"},
        {GEN_SM2_KP, gen_sm2_kp_main, "generate sm2 key pair"},
        {SM2_ENC, sm2_enc_main, "sm2 encrypt message"},
        {SM2_DEC, sm2_dec_main, "sm2 decrypt message"},
        {SM2_PUBKEY_ENCODING, sm2_pubkey_encoding_main, "sm2 public key encoding with DER"},
        {GEN_SM2_CSR, gen_sm2_csr_main, "generate certificate singing request"},
        {GEN_SM2_CERT, gen_sm2_cert_main, "generate sm2 certificate"},
        {SM2_CERT_VERIFY, sm2_cert_verify_main, "sm2 certificate verify"}
};

int print_help_info(int argc, char *argv[]) {
    int counts = sizeof(g_func_table) / sizeof(func_table_st);

    for(int i = 1; i < counts; i++){
        printf("%s %s: %s\n", PROGRAM_NAME, g_func_table[i].option, g_func_table[i].help_info);
    }
}

int exec_func_by_option(int argc, char *argv[]) {

    int counts = sizeof(g_func_table) / sizeof(func_table_st);

    if (argc == 1) {
        return g_func_table[0].func(argc, argv);
    }

    for(int i = 0; i < counts; i++){
        if (strcmp(argv[1], g_func_table[i].option) == 0) {
            return g_func_table[i].func(argc, argv);
        }
    }

}

int save_bin_file(uint8_t *data, size_t data_len, char *path) {
    FILE *fp = NULL;

    fp = fopen(path, "wb+");
    if (fp == NULL) {
        printf("open file failed, path: %s\n", path);
        return 1;
    }

    fwrite(data, 1, data_len, fp);

    fclose(fp);

    return ERR_OK;
}
