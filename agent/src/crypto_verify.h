#ifndef MDM_AGENT_CRYPTO_VERIFY_H
#define MDM_AGENT_CRYPTO_VERIFY_H

#include <openssl/evp.h>
#include <stddef.h>

typedef struct {
    EVP_PKEY *pkey; /* Ed25519 public key only — never a private key */
} mdm_verifier_t;

/* Loads the trusted Ed25519 public key used to verify signed commands.
 * This is the one piece of key material an agent ever holds for command
 * signing — if the agent's filesystem or binary leaks, there is nothing
 * here that lets an attacker forge a command. Returns 0 on success, -1
 * on error. */
int mdm_verifier_load(mdm_verifier_t *verifier, const char *public_key_path);

/* Verifies `signature_b64` (base64) against the exact bytes
 * [payload, payload+len). Returns 1 if valid, 0 if invalid, -1 on error
 * (malformed base64, etc). Callers must verify over the raw bytes as
 * received, before parsing them as JSON — never re-serialize first. */
int mdm_verifier_verify(mdm_verifier_t *verifier, const char *payload, size_t len,
                         const char *signature_b64);

void mdm_verifier_free(mdm_verifier_t *verifier);

#endif /* MDM_AGENT_CRYPTO_VERIFY_H */
