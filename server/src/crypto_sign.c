#include "crypto_sign.h"

#include <errno.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mdm_signer_load(mdm_signer_t *signer, const char *private_key_path) {
    FILE *f = fopen(private_key_path, "r");
    if (f == NULL) {
        fprintf(stderr, "crypto_sign: failed to open %s: %s\n", private_key_path, strerror(errno));
        return -1;
    }

    signer->pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (signer->pkey == NULL) {
        fprintf(stderr, "crypto_sign: failed to parse private key %s\n", private_key_path);
        return -1;
    }
    return 0;
}

static char *base64_encode(const unsigned char *data, size_t len) {
    /* EVP_EncodeBlock pads to a multiple of 4 output chars per 3 input
     * bytes; this formula covers worst case plus the NUL terminator. */
    size_t out_cap = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_cap);
    if (out == NULL) return NULL;

    int out_len = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
    out[out_len] = '\0';
    return out;
}

char *mdm_signer_sign_b64(mdm_signer_t *signer, const char *payload, size_t len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "crypto_sign: EVP_MD_CTX_new failed\n");
        return NULL;
    }

    /* Ed25519 is used in its "pure" one-shot mode: no digest algorithm is
     * selected (NULL), and the whole message is passed to EVP_DigestSign
     * in a single call rather than streamed via *Update. */
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, signer->pkey) <= 0) {
        fprintf(stderr, "crypto_sign: EVP_DigestSignInit failed\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    unsigned char sig[128]; /* Ed25519 signatures are 64 bytes */
    size_t sig_len = sizeof(sig);
    if (EVP_DigestSign(ctx, sig, &sig_len, (const unsigned char *)payload, len) <= 0) {
        fprintf(stderr, "crypto_sign: EVP_DigestSign failed\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);

    return base64_encode(sig, sig_len);
}

void mdm_signer_free(mdm_signer_t *signer) {
    if (signer->pkey != NULL) {
        EVP_PKEY_free(signer->pkey);
        signer->pkey = NULL;
    }
}
