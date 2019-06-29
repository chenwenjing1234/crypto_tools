//
// Created by chenwenjing on 11/24/18.
//

#ifndef CRYPTO_TOOLS_TEST_H
#define CRYPTO_TOOLS_TEST_H

#include <stdlib.h>

int cmac_test();

int hex_to_bin(char *hex, unsigned char *bin, size_t *bin_len);

void rleft_test();
#endif //CRYPTO_TOOLS_TEST_H
