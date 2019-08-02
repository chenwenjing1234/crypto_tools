//
// Created by root on 8/1/19.
//

#include "cp_x509.h"

#include <memory.h>

#include "openssl/objects.h"
#include "openssl/asn1t.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include "cp_defines.h"

#define EXT_COPY_NONE            0
# define EXT_COPY_ADD            1

static int ext_nid_list[] = { NID_ext_req, NID_ms_ext_req, NID_undef };
static int *ext_nids = ext_nid_list;

typedef struct _sx509_req_info {
    ASN1_ENCODING enc;          /* cached encoding of signed part */
    ASN1_INTEGER *version;      /* version, defaults to v1(0) so can be NULL */
    X509_NAME *subject;         /* certificate request DN */
    X509_PUBKEY *pubkey;        /* public key of request */
    /*
     * Zero or more attributes.
     * NB: although attributes is a mandatory field some broken
     * encodings omit it so this may be NULL in that case.
     */
    STACK_OF(X509_ATTRIBUTE) *attributes;
} sx509_req_info;
static int rinf_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
    sx509_req_info *rinf = (sx509_req_info *)*pval;

    if (operation == ASN1_OP_NEW_POST) {
        rinf->attributes = sk_X509_ATTRIBUTE_new_null();
        if (!rinf->attributes)
            return 0;
    }
    return 1;
}
ASN1_SEQUENCE_enc(sx509_req_info, enc, rinf_cb) = {
ASN1_SIMPLE(sx509_req_info, version, ASN1_INTEGER),
ASN1_SIMPLE(sx509_req_info, subject, X509_NAME),
ASN1_SIMPLE(sx509_req_info, pubkey, X509_PUBKEY),
/* This isn't really OPTIONAL but it gets round invalid
 * encodings
 */
ASN1_IMP_SET_OF_OPT(sx509_req_info, attributes, X509_ATTRIBUTE, 0)
} ASN1_SEQUENCE_END_enc(sx509_req_info, sx509_req_info)
IMPLEMENT_ASN1_FUNCTIONS(sx509_req_info)

typedef struct _sx509_req {
    sx509_req_info req_info;     /* signed certificate request data */
    X509_ALGOR sig_alg;         /* signature algorithm */
    ASN1_BIT_STRING *signature; /* signature */
    int references;
    CRYPTO_RWLOCK *lock;
} sx509_req;
ASN1_SEQUENCE_ref(sx509_req, 0) = {
ASN1_EMBED(sx509_req, req_info, sx509_req_info),
ASN1_EMBED(sx509_req, sig_alg, X509_ALGOR),
ASN1_SIMPLE(sx509_req, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(sx509_req, sx509_req)
IMPLEMENT_ASN1_FUNCTIONS(sx509_req)
IMPLEMENT_ASN1_DUP_FUNCTION(sx509_req)


typedef struct _sx509_cinf {
    ASN1_INTEGER *version;      /* [ 0 ] default of v1 */
    ASN1_INTEGER serialNumber;
    X509_ALGOR signature;
    X509_NAME *issuer;
    X509_VAL validity;
    X509_NAME *subject;
    X509_PUBKEY *key;
    ASN1_BIT_STRING *issuerUID; /* [ 1 ] optional in v2 */
    ASN1_BIT_STRING *subjectUID; /* [ 2 ] optional in v2 */
    STACK_OF(X509_EXTENSION) *extensions; /* [ 3 ] optional in v3 */
    ASN1_ENCODING enc;
} sx509_cinf;

typedef struct _sx509 {
    sx509_cinf cert_info;
    X509_ALGOR sig_alg;
    ASN1_BIT_STRING signature;
    int references;
    CRYPTO_EX_DATA ex_data;
    /* These contain copies of various extension values */
    long ex_pathlen;
    long ex_pcpathlen;
    uint32_t ex_flags;
    uint32_t ex_kusage;
    uint32_t ex_xkusage;
    uint32_t ex_nscert;
    ASN1_OCTET_STRING *skid;
    AUTHORITY_KEYID *akid;
    STACK_OF(DIST_POINT) *crldp;
    STACK_OF(GENERAL_NAME) *altname;
    NAME_CONSTRAINTS *nc;
#ifndef OPENSSL_NO_RFC3779
    STACK_OF(IPAddressFamily) *rfc3779_addr;
    struct ASIdentifiers_st *rfc3779_asid;
# endif
    unsigned char sha1_hash[32 /*SHA_DIGEST_LENGTH*/];
    X509_CERT_AUX *aux;
    CRYPTO_RWLOCK *lock;
} sx509;

ASN1_SEQUENCE_enc(sx509_cinf, enc, 0) = {
        ASN1_EXP_OPT(sx509_cinf, version, ASN1_INTEGER, 0),
        ASN1_EMBED(sx509_cinf, serialNumber, ASN1_INTEGER),
        ASN1_EMBED(sx509_cinf, signature, X509_ALGOR),
        ASN1_SIMPLE(sx509_cinf, issuer, X509_NAME),
        ASN1_EMBED(sx509_cinf, validity, X509_VAL),
        ASN1_SIMPLE(sx509_cinf, subject, X509_NAME),
        ASN1_SIMPLE(sx509_cinf, key, X509_PUBKEY),
        ASN1_IMP_OPT(sx509_cinf, issuerUID, ASN1_BIT_STRING, 1),
        ASN1_IMP_OPT(sx509_cinf, subjectUID, ASN1_BIT_STRING, 2),
        ASN1_EXP_SEQUENCE_OF_OPT(sx509_cinf, extensions, X509_EXTENSION, 3)
} ASN1_SEQUENCE_END_enc(sx509_cinf, sx509_cinf)
IMPLEMENT_ASN1_FUNCTIONS(sx509_cinf)

static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
    sx509 *ret = (sx509 *)*pval;

    switch (operation) {

        case ASN1_OP_NEW_POST:
            ret->ex_flags = 0;
            ret->ex_pathlen = -1;
            ret->ex_pcpathlen = -1;
            ret->skid = NULL;
            ret->akid = NULL;
#ifndef OPENSSL_NO_RFC3779
            ret->rfc3779_addr = NULL;
            ret->rfc3779_asid = NULL;
#endif
            ret->aux = NULL;
            ret->crldp = NULL;
            if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data))
                return 0;
            break;

        case ASN1_OP_FREE_POST:
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
            X509_CERT_AUX_free(ret->aux);
            ASN1_OCTET_STRING_free(ret->skid);
            AUTHORITY_KEYID_free(ret->akid);
            CRL_DIST_POINTS_free(ret->crldp);
//        policy_cache_free(ret->policy_cache);
            GENERAL_NAMES_free(ret->altname);
            NAME_CONSTRAINTS_free(ret->nc);
#ifndef OPENSSL_NO_RFC3779
            sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
            ASIdentifiers_free(ret->rfc3779_asid);
#endif
            break;

    }

    return 1;

}

ASN1_SEQUENCE_ref(sx509, x509_cb) = {
        ASN1_EMBED(sx509, cert_info, sx509_cinf),
        ASN1_EMBED(sx509, sig_alg, X509_ALGOR),
        ASN1_EMBED(sx509, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(sx509, sx509)
IMPLEMENT_ASN1_FUNCTIONS(sx509)
IMPLEMENT_ASN1_DUP_FUNCTION(sx509)

static int _add_ext_exts(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
    X509_EXTENSION *ex = NULL;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (NULL == ex) {
        return 0;
    }
    sk_X509_EXTENSION_push(sk, ex);
    return 1;
}

int cp_build_x509_req(EVP_PKEY *pubkey, X509_NAME *subject, int is_ca, unsigned char *req_info, int *req_info_len)
{
    int ret_code = 0;
    sx509_req_info *x509_req_info = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    unsigned char *extbytes = NULL;
    int extbytesl = 0;
    unsigned char *tmp = NULL;
    int tmpl = 0;
    X509_NAME *subject_dup = NULL;

    x509_req_info = sx509_req_info_new();
    if (NULL == x509_req_info) {
        return 0;
    }

    ASN1_INTEGER_set(x509_req_info->version, 0);
    if (NULL != x509_req_info->subject) {
        X509_NAME_free(x509_req_info->subject);
    }
    subject_dup = X509_NAME_dup(subject);
    x509_req_info->subject = subject_dup;

    X509_PUBKEY_set(&x509_req_info->pubkey, pubkey);

    exts = sk_X509_EXTENSION_new_null();
    if (NULL == exts) {
        goto end;
    }
    if(is_ca) {
        if (_add_ext_exts(exts, NID_basic_constraints, "critical,CA:TRUE") != 1) {
            goto end;
        }
    }
    extbytesl = ASN1_item_i2d((ASN1_VALUE *)exts, &extbytes, ASN1_ITEM_rptr(X509_EXTENSIONS));
    X509at_add1_attr_by_NID(&x509_req_info->attributes, NID_ext_req, V_ASN1_SEQUENCE, extbytes, extbytesl);

    tmpl = i2d_sx509_req_info(x509_req_info, &tmp);
    if (tmpl > *req_info_len) {
        goto end;
    }
    memcpy(req_info, tmp, (size_t) tmpl);
    *req_info_len = tmpl;

    ret_code = CP_SUCCESS;
    end:
    if (NULL != tmp) {
        OPENSSL_free(tmp);
    }
    if(NULL != exts) {
        sk_X509_EXTENSION_free(exts);
    }
    if (NULL != x509_req_info) {
        sx509_req_info_free(x509_req_info);
    }
    return ret_code;
}

int cp_create_sm2_csr(uint8_t *req_info, int req_info_len, uint8_t *sig, int sig_len, uint8_t *csr, int *csr_len)
{
    int ret_code = 0;
    sx509_req *req = NULL;
    sx509_req_info *x509_req_info = NULL;//free by sx509_req_free
    unsigned char *tmp_reqinfo = req_info;
    unsigned char *tmp_sig = NULL;
    unsigned char *tmp_csr = NULL;
    int tmp_csrl = 0;

    x509_req_info = d2i_sx509_req_info(NULL, (const uint8_t **) &tmp_reqinfo, req_info_len);
    if (NULL == x509_req_info) {
        return ret_code;
    }

    req = sx509_req_new();
    if (NULL == req) {
        goto end;
    }
    req->req_info = *x509_req_info;
    X509_ALGOR_set0(&req->sig_alg, OBJ_nid2obj(NID_sm2sign_with_sm3), V_ASN1_UNDEF, NULL);

    tmp_sig = (uint8_t *)calloc(1, (size_t) sig_len);
    if (NULL == tmp_sig) {
        goto end;
    }

    memcpy(tmp_sig, sig, (size_t) sig_len);
    OPENSSL_free(req->signature->data);
    req->signature->data = tmp_sig;
    req->signature->length = sig_len;

    tmp_csrl = i2d_sx509_req(req, &tmp_csr);
    if (tmp_csrl > *csr_len) {
        goto end;
    }
    memcpy(csr, tmp_csr, (size_t) tmp_csrl);
    *csr_len = tmp_csrl;

    ret_code = CP_SUCCESS;

    end:
    if (NULL != tmp_csr) {
        OPENSSL_free(tmp_csr);
    }
    if (NULL != req) {
        sx509_req_free(req);
    }
    return ret_code;
}

int cp_get_x509_subject_from_csr(uint8_t *csr, int csr_len, X509_NAME **subject)
{
    int ret_code = CP_SUCCESS;
    const uint8_t *tmp_csr = csr;
    X509_REQ *x509req = NULL;
    x509req = d2i_X509_REQ(NULL, &tmp_csr, csr_len);
    if (NULL == x509req) {
        return 0;
    }
    *subject = X509_NAME_dup(X509_REQ_get_subject_name(x509req));

    X509_REQ_free(x509req);
    return ret_code;
}

int cp_get_x509_pkey_from_csr(uint8_t *csr, int csr_len, EVP_PKEY **pEVP_pkey)
{
    int ret_code = CP_SUCCESS;
    const uint8_t *tmp_csr = csr;
    X509_REQ *x509req = NULL;
    EVP_PKEY *evp_pkey_src = NULL;
    EVP_PKEY *evp_pkey_dst = NULL;
    EC_KEY *ec_key = NULL;
    x509req = d2i_X509_REQ(NULL, &tmp_csr, csr_len);
    if (NULL == x509req) {
        return 0;
    }

    evp_pkey_dst = EVP_PKEY_new();

    /**
     * 不能使用X509_REQ_get_pubkey，否则会增加一次evp_pkey_src的引用次数
     * 导致evp_pkey_src不能在X509_REQ_free里面被释放，引发内存泄露
     */
    evp_pkey_src = X509_REQ_get0_pubkey(x509req);
    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey_src);

    //ec_key在外层释放evp_pkey_dst的时候被释放
    EVP_PKEY_set1_EC_KEY(evp_pkey_dst, ec_key);
    *pEVP_pkey = evp_pkey_dst;
    X509_REQ_free(x509req);

    return ret_code;
}

int cp_get_x509_subject_from_cer(uint8_t *cert, int cert_len, X509_NAME **subject)
{
    int ret_code = CP_SUCCESS;
    const uint8_t *tmp_cer = cert;
    X509 *x509cer = NULL;

    x509cer = d2i_X509(NULL, &tmp_cer, cert_len);
    if (NULL == x509cer) {
        return 0;
    }

    *subject = X509_NAME_dup(X509_get_subject_name(x509cer));
    X509_free(x509cer);
    return ret_code;
}

int cp_set_cert_validity(X509 *x, const char *start_date, const char *end_date, int days)
{
    if (start_date == NULL || strcmp(start_date, "today") == 0) {
        if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL)
            return 0;
    } else {
        if (!ASN1_TIME_set_string(X509_getm_notBefore(x), start_date))
            return 0;
    }
    if (end_date == NULL) {
        if (X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL) == NULL)
            return 0;
    } else if (!ASN1_TIME_set_string(X509_getm_notAfter(x), end_date)) {
        return 0;
    }
    return CP_SUCCESS;
}

int cp_copy_extensions(X509 *x, uint8_t *csr, int csr_len, int copy_type)
{
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509_EXTENSION *ext, *tmpext;
    ASN1_OBJECT *obj;
    X509_REQ *x509req = NULL;
    int i, idx, ret = 0;
    const uint8_t *tmp_csr = csr;

    if (!x || !csr || (copy_type == EXT_COPY_NONE))
        return 0;

    x509req = d2i_X509_REQ(NULL, &tmp_csr, csr_len);
    if (NULL == x509req) {
        return 0;
    }

    exts = X509_REQ_get_extensions(x509req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        idx = X509_get_ext_by_OBJ(x, obj, -1);
        /* Does extension exist? */
        if (idx != -1) {
            /* If normal copy don't override existing extension */
            if (copy_type == EXT_COPY_ADD)
                continue;
            /* Delete all extensions of same type */
            do {
                tmpext = X509_get_ext(x, idx);
                X509_delete_ext(x, idx);
                X509_EXTENSION_free(tmpext);
                idx = X509_get_ext_by_OBJ(x, obj, -1);
            } while (idx != -1);
        }
        if (!X509_add_ext(x, ext, -1))
            goto end;
    }

    ret = CP_SUCCESS;

    end:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(x509req);
    return ret;
}

void cp_set_x509_signature_alg(X509 *x509) {

    int signid = NID_sm2sign_with_sm3;
    int paramtype = V_ASN1_UNDEF;//V_ASN1_NULL
    sx509 *psx509 = (sx509*)x509;

    if (&psx509->cert_info.signature)
        X509_ALGOR_set0(&psx509->cert_info.signature, OBJ_nid2obj(signid), paramtype, NULL);
    if (&psx509->sig_alg)
        X509_ALGOR_set0(&psx509->sig_alg, OBJ_nid2obj(signid), paramtype, NULL);
}

int cp_get_x509_cert_info_der(X509 *x509, uint8_t **cert_info, int *len) {
    int ret_code = CP_SUCCESS;
    uint8_t *buf = NULL;
    int buflen;
    sx509 *psx509 = (sx509*)x509;

    if (x509 == NULL || cert_info == NULL || len == NULL) {
        return 0;
    }

    buflen = ASN1_item_i2d((ASN1_VALUE*)&psx509->cert_info, &buf, ASN1_ITEM_rptr(X509_CINF));
    if (buflen <= 0) {
        return 0;
    }

    *cert_info = buf;
    *len = buflen;

    return ret_code;
}

void cp_set_x509_signature(X509 *x509, uint8_t *sig, int sig_len) {
    sx509 *psx509 = (sx509*)x509;

    (&psx509->signature)->data = sig;
    (&psx509->signature)->length = sig_len;
}