#!/usr/bin/env bash
# Generate the Ed25519 keypair used to sign commands/policies, deliberately
# separate from the TLS CA/server key (make-ca.sh). Only mdm-server ever
# touches signing_key.pem; agents only ever receive signing_pub.pem. If an
# agent binary or its filesystem leaks, that must not hand an attacker
# anything that lets them forge a signed command.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../server/certs"

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

if [[ -f signing_key.pem ]]; then
    echo "Signing key already exists at ${CERT_DIR}/signing_key.pem. Remove it first if you want to regenerate (note: doing so invalidates every agent's trusted public key)." >&2
    exit 1
fi

echo "== Generating Ed25519 command-signing keypair =="
openssl genpkey -algorithm Ed25519 -out signing_key.pem
chmod 600 signing_key.pem
openssl pkey -in signing_key.pem -pubout -out signing_pub.pem

echo
echo "Done. Files in ${CERT_DIR}:"
ls -1 signing_key.pem signing_pub.pem
echo
echo "Keep signing_key.pem on the server only. Copy signing_pub.pem to every"
echo "enrolled device for mdm-agent's --signing-pubkey argument."
