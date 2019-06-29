//
// Created by chenwenjing on 6/3/19.
//

#ifndef CRYPTO_TOOLS_CA_DEFINE_H
#define CRYPTO_TOOLS_CA_DEFINE_H


#define PROGRAM_NAME            "crypto_tools"

#define HELP                    "--help"
#define GEN_SM2_KP              "-gen_sm2_kp"
#define SM2_ENC                 "-sm2_enc"
#define SM2_DEC                 "-sm2_dec"
#define SM2_PUBKEY_ENCODING     "-sm2_pubkey_encoding"
#define GEN_CSR                 "-gen_sm2_csr"


#define OPT_PUBKEY              "-pubkey"
#define OPT_PLAIN               "-plain"
#define OPT_PRIKEY              "-prikey"
#define OPT_CIPHER              "-cipher"
#define OPT_CSR_OUT_PATH        "-csr_out_path"

typedef struct options_st {
    const char *name;
    int retval;
    /*
     * value type: - no value (also the value zero), n number, p positive
     * number, u unsigned, l long, s string, < input file, > output file,
     * f any format, F der/pem format , E der/pem/engine format identifier.
     * l, n and u include zero; p does not.
     */
    int valtype;
    const char *helpstr;
} OPTIONS;

int gen_sm2_kp_main(int argc, char *argv[]);

int sm2_enc_main(int argc, char *argv[]);

int sm2_dec_main(int argc, char *argv[]);

int sm2_pubkey_encoding_main(int argc, char **argv);

int gen_csr_main(int argc, char **argv);

#endif //CRYPTO_TOOLS_CA_DEFINE_H
