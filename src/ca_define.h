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
#define GEN_SM2_CSR             "-gen_sm2_csr"
#define GEN_SM2_CERT            "-gen_sm2_cert"
#define SM2_CERT_VERIFY         "-sm2_cert_verify"


#define OPT_PUBKEY              "-pubkey"
#define OPT_PLAIN               "-plain"
#define OPT_PRIKEY              "-prikey"
#define OPT_CIPHER              "-cipher"
#define OPT_PATH                "-path"
#define OPT_CSR                 "-csr"
#define OPT_TYPE                "-type"
#define OPT_CSR_OUT_PATH        "-csr_out_path"
#define OPT_CA_PATH             "-ca_path"
#define OPT_CERT_PATH           "-cert_path"
#define OPT_ROOT_CERT           "-root_cert"
#define OPT_LEAF_CERT           "-leaf_cert"


#define CERT_TYPE_ROOT          "root"
#define CERT_TYPE_SUB           "sub"
#define CERT_TYPE_LEAF          "leaf"

#define CERT_NAME_ROOT          "root.cer"
#define CERT_NAME_SUB           "sub_root.cer"

#define SN_FILE_NAME            "cert.sn"
#define VALIDITY_FILE_NAME      "cert.validity"

#define ROOT_PUBKEY_NAME        "root.pubkey"
#define ROOT_PRIKEY_NAME        "root.prikey"
#define SUB_PUBKEY_NAME         "sub_root.pubkey"
#define SUB_PRIKEY_NAME         "sub_root.prikey"


#define EXT_COPY_ADD            1
#define OID_SM3_WITH_SM2        "\x2a\x81\x1c\xcf\x55\x01\x83\x75"
#define OID_SM3_WITH_SM2_LEN    8

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

int gen_sm2_csr_main(int argc, char **argv);

int gen_sm2_cert_main(int argc, char **argv);

int sm2_cert_verify_main(int argc, char **argv);

#endif //CRYPTO_TOOLS_CA_DEFINE_H
