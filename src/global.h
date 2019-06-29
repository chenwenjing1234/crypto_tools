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




int exec_func_by_option(int argc, char *argv[]);

int print_help_info(int, char *argv[]);

#endif //CRYPTO_TOOLS_GLOBAL_H
