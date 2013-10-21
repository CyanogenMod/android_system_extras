/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* HACK: we need the RSAPublicKey struct
 * but RSA_verify conflits with openssl */
#define RSA_verify RSA_verify_mincrypt
#include "mincrypt/rsa.h"
#undef RSA_verify

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

// Convert OpenSSL RSA private key to android pre-computed RSAPublicKey format.
// Lifted from secure adb's mincrypt key generation.
static int convert_to_mincrypt_format(RSA *rsa, RSAPublicKey *pkey)
{
    int ret = -1;
    unsigned int i;

    if (RSA_size(rsa) != RSANUMBYTES)
        goto out;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* r32 = BN_new();
    BIGNUM* rr = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* rem = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* n0inv = BN_new();

    BN_set_bit(r32, 32);
    BN_copy(n, rsa->n);
    BN_set_bit(r, RSANUMWORDS * 32);
    BN_mod_sqr(rr, r, n, ctx);
    BN_div(NULL, rem, n, r32, ctx);
    BN_mod_inverse(n0inv, rem, r32, ctx);

    pkey->len = RSANUMWORDS;
    pkey->n0inv = 0 - BN_get_word(n0inv);
    for (i = 0; i < RSANUMWORDS; i++) {
        BN_div(rr, rem, rr, r32, ctx);
        pkey->rr[i] = BN_get_word(rem);
        BN_div(n, rem, n, r32, ctx);
        pkey->n[i] = BN_get_word(rem);
    }
    pkey->exponent = BN_get_word(rsa->e);

    ret = 0;

    BN_free(n0inv);
    BN_free(n);
    BN_free(rem);
    BN_free(r);
    BN_free(rr);
    BN_free(r32);
    BN_CTX_free(ctx);

out:
    return ret;
}

static int write_public_keyfile(RSA *private_key, const char *private_key_path)
{
    RSAPublicKey pkey;
    BIO *bfile = NULL;
    char *path = NULL;
    int ret = -1;

    if (asprintf(&path, "%s.pub", private_key_path) < 0)
        goto out;

    if (convert_to_mincrypt_format(private_key, &pkey) < 0)
        goto out;

    bfile = BIO_new_file(path, "w");
    if (!bfile)
        goto out;

    BIO_write(bfile, &pkey, sizeof(pkey));
    BIO_flush(bfile);

    ret = 0;
out:
    BIO_free_all(bfile);
    free(path);
    return ret;
}

static int generate_key(const char *file)
{
    int ret = -1;
    FILE *f = NULL;
    RSA* rsa = RSA_new();
    BIGNUM* exponent = BN_new();
    EVP_PKEY* pkey = EVP_PKEY_new();

    if (!pkey || !exponent || !rsa) {
        printf("Failed to allocate key\n");
        goto out;
    }

    BN_set_word(exponent, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, exponent, NULL);
    EVP_PKEY_set1_RSA(pkey, rsa);

    f = fopen(file, "w");
    if (!f) {
        printf("Failed to open '%s'\n", file);
        goto out;
    }

    if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
        printf("Failed to write key\n");
        goto out;
    }

    if (write_public_keyfile(rsa, file) < 0) {
        printf("Failed to write public key\n");
        goto out;
    }

    ret = 0;

out:
    if (f)
        fclose(f);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BN_free(exponent);
    return ret;
}

static void usage(){
    printf("Usage: generate_verity_key <path-to-key>");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage();
        exit(-1);
    }
    return generate_key(argv[1]);
}