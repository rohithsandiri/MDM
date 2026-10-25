#include "crypto_verify.h"

#include <errno.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mdm_verifier_load(mdm_verifier_t *verifier, const char *public_key_path) {
    FILE *f = fopen(public_key_path, "r");
    if (f == NULL) {
        fprintf(stderr, "crypto_verify: failed to open %s: %s\n", public_key_path, strerror(errno));
        return -1;
    }

    verifier->pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

    if (verifier->pkey == NULL) {
        fprintf(stderr, "crypto_verify: failed to parse public key %s\n", public_key_path);
        return -1;
    }
    return 0;
}

static int base64_decode(const char *b64, unsigned char **out, size_t *out_len) {
    size_t in_len = strlen(b64);
    if (in_len == 0 || in_len % 4 != 0) return -1;

    size_t decoded_cap = (in_len / 4) * 3;
    unsigned char *buf = malloc(decoded_cap > 0 ? decoded_cap : 1);
    if (buf == NULL) return -1;

    int n = EVP_DecodeBlock(buf, (const unsigned char *)b64, (int)in_len);
    if (n < 0) {
        free(buf);
        return -1;
    }

    size_t pad = 0;
    if (in_len >= 1 && b64[in_len - 1] == '=') pad++;
    if (in_len >= 2 && b64[in_len - 2] == '=') pad++;
    if ((size_t)n < pad) {
        free(buf);
        return -1;
    }

    *out = buf;
    *out_len = (size_t)n - pad;
    return 0;
}

int mdm_verifier_verify(mdm_verifier_t *verifier, const char *payload, size_t len,
                         const char *signature_b64) {
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    if (base64_decode(signature_b64, &sig, &sig_len) != 0) {
        fprintf(stderr, "crypto_verify: malformed base64 signature\n");
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        free(sig);
        return -1;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, verifier->pkey) <= 0) {
        fprintf(stderr, "crypto_verify: EVP_DigestVerifyInit failed\n");
        EVP_MD_CTX_free(ctx);
        free(sig);
        return -1;
    }

    /* Verifies over the exact bytes the caller passed in — the raw,
     * received payload bytes, never a re-serialized/re-parsed form. */
    int rc = EVP_DigestVerify(ctx, sig, sig_len, (const unsigned char *)payload, len);
    EVP_MD_CTX_free(ctx);
    free(sig);

    if (rc == 1) return 1;
    if (rc == 0) return 0;
    fprintf(stderr, "crypto_verify: EVP_DigestVerify internal error\n");
    return -1;
}

void mdm_verifier_free(mdm_verifier_t *verifier) {
    if (verifier->pkey != NULL) {
        EVP_PKEY_free(verifier->pkey);
        verifier->pkey = NULL;
    }
}
