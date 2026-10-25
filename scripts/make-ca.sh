#!/usr/bin/env bash
# Create a root CA and a server certificate signed by it, for mTLS between
# mdm-server and enrolled mdm-agent devices. Output lands in server/certs/
# (gitignored) and is local-dev/lab material only — do not reuse in production
# without reviewing key sizes, validity periods, and storage of the CA key.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../server/certs"
DAYS_CA=3650
DAYS_SERVER=825
SERVER_CN="${1:-mdm-server}"

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

if [[ -f ca.key || -f ca.crt ]]; then
    echo "CA already exists in ${CERT_DIR} (ca.key/ca.crt). Remove them first if you want to regenerate." >&2
    exit 1
fi

echo "== Generating CA key + self-signed CA cert =="
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ca.key
chmod 600 ca.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days "${DAYS_CA}" \
    -out ca.crt \
    -subj "/O=MDM Lab/CN=MDM Root CA"

echo "== Generating server key + CSR =="
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server.key
chmod 600 server.key
openssl req -new -key server.key -out server.csr \
    -subj "/O=MDM Lab/CN=${SERVER_CN}"

echo "== Signing server cert with CA =="
cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_CN},DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days "${DAYS_SERVER}" -sha256 -extfile server.ext

rm -f server.csr server.ext
echo
echo "Done. Files in ${CERT_DIR}:"
ls -1 ca.key ca.crt server.key server.crt
echo
echo "Next: scripts/enroll-device.sh <device-id> to issue a client cert."
