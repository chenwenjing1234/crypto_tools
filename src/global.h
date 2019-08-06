//
// Created by chenwenjing on 6/3/19.
//

#ifndef CRYPTO_TOOLS_GLOBAL_H
#define CRYPTO_TOOLS_GLOBAL_H


typedef struct {
    char *option;
    int (*func) (int, char *argv[]);
    char *help_info;
} func_table_st;

typedef struct _cert_parse_ctx_st{
    uint8_t *begin_addr;
    int header_len;
    int payload_len;
} cert_parse_ctx_st;

#define ERR_OK                   0X00000000


int exec_func_by_option(int argc, char *argv[]);

int print_help_info(int, char *argv[]);

int save_bin_file(uint8_t *data, size_t data_len, char *path);

#endif //CRYPTO_TOOLS_GLOBAL_H
