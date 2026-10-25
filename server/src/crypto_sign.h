#ifndef MDM_SERVER_CRYPTO_SIGN_H
#define MDM_SERVER_CRYPTO_SIGN_H

#include <openssl/evp.h>
#include <stddef.h>

typedef struct {
    EVP_PKEY *pkey; /* Ed25519 private key, loaded from signing_key.pem */
} mdm_signer_t;

/* Loads the server's Ed25519 command-signing private key. This key never
 * leaves the server — agents only ever receive the corresponding public
 * key (see crypto_verify.h on the agent side). Returns 0 on success, -1
 * on error. */
int mdm_signer_load(mdm_signer_t *signer, const char *private_key_path);

/* Signs the exact bytes [payload, payload+len) and returns a malloc'd,
 * NUL-terminated base64 string (caller frees), or NULL on error. Callers
 * must sign the precise bytes that will be transmitted — never a
 * re-serialized form of a parsed structure. */
char *mdm_signer_sign_b64(mdm_signer_t *signer, const char *payload, size_t len);

void mdm_signer_free(mdm_signer_t *signer);

#endif /* MDM_SERVER_CRYPTO_SIGN_H */
