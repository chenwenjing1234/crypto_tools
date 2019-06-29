//
// Created by chenwenjing on 12/3/18.
//

#include "sm3_test.h"
#include <string.h>
#include <stdio.h>

#define T0    0x79cc4519
#define T1    0x7a879d8a

#define FF0(x, y, z)  ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z) ))

#define GG0(x, y, z)  ((x) ^ (y) ^ (z))
#define GG1(x, y, z)  (((x) & (y)) | ((~x) & (z)))

#define RLEFT(x, n)  (((x) << (n)) | (((x) >> (32-n))))

#define P0(x) ((x) ^ (RLEFT((x),9)) ^ (RLEFT((x),17)))
#define P1(x) ((x) ^ (RLEFT((x),15)) ^ (RLEFT((x),23)))

#define CPUTOBE32(x) ((x) << 24) | \
                 (((x) << 8) & 0xff0000) | \
                 (((x) >> 8) & 0xff00) | \
                 ((x) >> 24)

/*
 * ABCDEFGH   V (i)
FOR j=0 TO 63
SS1   ((A≪12) + E + (Tj ≪j))≪7
SS2   SS1  (A≪12)
TT1   FFj(A;B;C) + D + SS2 +W′j
TT2   GGj(E; F;G) + H + SS1 +Wj
D   C
C   B≪9
B   A
A   TT1
H   G
G   F ≪19
F   E
E   P0(TT2)
ENDFOR
V (i+1)   ABCDEFGH  V (i)
 *
 * */

static void _qinn_sm3_compress(uint32_t *digest, uint8_t *data) {
    unsigned int j;
    uint32_t A,B,C,D,E,F,G,H;
    uint32_t SS1,SS2,TT1,TT2;
    uint32_t W1[68], W2[64];
    uint32_t *p = (uint32_t*)data;
    for(j = 0; j < 68; j++){
        if (j < 16) {
            W1[j] = CPUTOBE32(p[j]);
//            print_hex_1(W1[j]);
        } else{
            W1[j] = (P1(W1[j-16] ^ W1[j-9] ^ (RLEFT(W1[j-3],15))) ^ (RLEFT(W1[j-13], 7)) ^ W1[j-6]);
//            print_hex_1(W1[j]);
        }
    }
//    printf("\n");

    for(j = 0; j < 64; j++){
        W2[j] = W1[j] ^ W1[j+4];
//        print_hex_1(W2[j]);
    }
//    printf("\n");

    A = (digest[0]);
    B = (digest[1]);
    C = (digest[2]);
    D = (digest[3]);
    E = (digest[4]);
    F = (digest[5]);
    G = (digest[6]);
    H = (digest[7]);

    /*print_hex_1(A);
    print_hex_1(B);
    print_hex_1(C);
    print_hex_1(D);
    print_hex_1(E);
    print_hex_1(F);
    print_hex_1(G);
    print_hex_1(H);*/

    for(j = 0; j < 64; j++){
        if (j < 16) {
            SS1  = RLEFT(((RLEFT(A,12)) + E + (RLEFT(T0,j))), 7);
            SS2 = SS1 ^ RLEFT(A,12);
            TT1 = FF0(A,B,C) + D + SS2 + W2[j];
            TT2 = GG0(E,F,G) + H + SS1 + W1[j];
            D = C;
            C = RLEFT(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = RLEFT(F, 19);
            F = E;
            E = P0(TT2);
            /*print_hex_1(A);
            print_hex_1(B);
            print_hex_1(C);
            print_hex_1(D);
            print_hex_1(E);
            print_hex_1(F);
            print_hex_1(G);
            print_hex_1(H);*/
        } else {
            SS1  = RLEFT((RLEFT(A,12) + E + (RLEFT(T1,j))), 7);
            SS2 = SS1 ^ RLEFT(A,12);
            TT1 = FF1(A,B,C) + D + SS2 + W2[j];
            TT2 = GG1(E,F,G) + H + SS1 + W1[j];
            D = C;
            C = RLEFT(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = RLEFT(F, 19);
            F = E;
            E = P0(TT2);
            /*print_hex_1(A);
            print_hex_1(B);
            print_hex_1(C);
            print_hex_1(D);
            print_hex_1(E);
            print_hex_1(F);
            print_hex_1(G);
            print_hex_1(H);*/
        }
    }

    digest[0] ^= A;
    digest[1] ^= B;
    digest[2] ^= C;
    digest[3] ^= D;
    digest[4] ^= E;
    digest[5] ^= F;
    digest[6] ^= G;
    digest[7] ^= H;

    print_hex_1(digest[0]);
    print_hex_1(digest[1]);
    print_hex_1(digest[2]);
    print_hex_1(digest[3]);
    print_hex_1(digest[4]);
    print_hex_1(digest[5]);
    print_hex_1(digest[6]);
    print_hex_1(digest[7]);



}

//7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e
int qinn_sm3_init(qinn_sm3_ctx *ctx) {
    ctx->digest[0] = 0x7380166f;
    ctx->digest[1] = 0x4914b2b9;
    ctx->digest[2] = 0x172442d7;
    ctx->digest[3] = 0xda8a0600;
    ctx->digest[4] = 0xa96f30bc;
    ctx->digest[5] = 0x163138aa;
    ctx->digest[6] = 0xe38dee4d;
    ctx->digest[7] = 0xb0fb0e4e;

    ctx->num = 0;
    ctx->nblocks = 0;

}



int qinn_sm3_update(qinn_sm3_ctx *ctx, uint8_t *data, uint32_t data_len) {


    while (data_len >= 64) {
        _qinn_sm3_compress(ctx->digest, data);
        data_len -= 64;
        data += 64;
        ctx->nblocks ++;
    }

    memcpy(ctx->block + ctx->num, data, data_len);
    ctx->num += data_len;

    if (ctx->num >= 64) {
        _qinn_sm3_compress(ctx->digest, ctx->block);
        ctx->num -= 64;
        ctx->nblocks ++;
    }

    return 1;
}

int qinn_sm3_final(qinn_sm3_ctx *ctx, uint8_t digest[32]) {
    int  i;
    long bits = 0;
    uint32_t *p = (uint32_t*)digest;
    //TODO 8bytes
//    int *q = (int*)(ctx->block + 64 - 8);
    int *q = (int*)(ctx->block + 64 - 4);
    ctx->block[ctx->num] = 0x80;
    memset(ctx->block + ctx->num + 1, 0, 64 - 9);
    bits = (ctx->nblocks * 64 + ctx->num) * 8;
//    memcpy(ctx->block + 64 - 8, &bits, sizeof(bits));
    *q |= CPUTOBE32(bits);
    _qinn_sm3_compress(ctx->digest, ctx->block);

    for(i = 0; i < 8; i++){
        p[i] = CPUTOBE32(ctx->digest[i]);
    }
}
int g_count = 0;
void print_hex_1(uint32_t a){
    g_count ++;
    unsigned char *p = (unsigned char*)&a;
    int i;
    for(i = 0; i < sizeof(a); i++){
        printf("%02x", p[i]);
    }
    if (g_count % 8 == 0) {
        g_count = 0;
        printf("\n");
    } else {
        printf(" ");
    }

}

void qinn_sm3_test() {
    uint32_t a = 0x61626380;
    uint32_t b = RLEFT(a, 15);
    uint32_t c = RLEFT(a, 23);
    uint32_t d = a ^ b ^ c;
    uint32_t f = P1(a);

/*    print_hex_1(b);
    print_hex_1(c);
    print_hex_1(d);
    print_hex_1(f);*/


    qinn_sm3_ctx ctx;
    uint8_t data[] = {0x61,0x62,0x63};
    uint8_t result[32] = {
            0x66, 0xC7, 0xF0, 0xF4, 0x62, 0xEE, 0xED, 0xD9, 0xD1, 0xF2, 0xD4, 0x6B, 0xDC, 0x10, 0xE4, 0xE2,
            0x41, 0x67, 0xC4, 0x87, 0x5C, 0xF2, 0xF7, 0xA2, 0x29, 0x7D, 0xA0, 0x2B, 0x8F, 0x4B, 0xA8, 0xE0
    };
    uint8_t digest[32] = {0};

    qinn_sm3_init(&ctx);
    qinn_sm3_update(&ctx, data, sizeof(data));
    qinn_sm3_final(&ctx, digest);

    int i;
    for(i = 0; i < 32; i++){
        printf("%02x", digest[i]);
    }
    printf("\n");

}
