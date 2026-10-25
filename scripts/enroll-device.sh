#!/usr/bin/env bash
# Issue a unique client certificate for one device, signed by the lab CA
# created by make-ca.sh. In Phase 3 this is what the server does internally
# in response to a device presenting a valid one-time enrollment token; this
# script is the operator-side equivalent for manual/offline enrollment and
# for generating fixtures the agent can use in the test VM.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../server/certs"
DEVICE_DIR="${SCRIPT_DIR}/../server/certs/devices"
DAYS_CLIENT=365

usage() {
    echo "usage: $0 <device-id>" >&2
    exit 1
}

[[ $# -eq 1 ]] || usage
DEVICE_ID="$1"

if [[ ! -f "${CERT_DIR}/ca.key" || ! -f "${CERT_DIR}/ca.crt" ]]; then
    echo "No CA found in ${CERT_DIR}. Run scripts/make-ca.sh first." >&2
    exit 1
fi

mkdir -p "${DEVICE_DIR}"
cd "${DEVICE_DIR}"

if [[ -f "${DEVICE_ID}.crt" ]]; then
    echo "Device '${DEVICE_ID}' already has a certificate in ${DEVICE_DIR}." >&2
    exit 1
fi

echo "== Generating client key + CSR for device '${DEVICE_ID}' =="
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${DEVICE_ID}.key"
chmod 600 "${DEVICE_ID}.key"
openssl req -new -key "${DEVICE_ID}.key" -out "${DEVICE_ID}.csr" \
    -subj "/O=MDM Lab/OU=device/CN=${DEVICE_ID}"

cat > "${DEVICE_ID}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

echo "== Signing client cert with CA =="
openssl x509 -req -in "${DEVICE_ID}.csr" \
    -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
    -out "${DEVICE_ID}.crt" -days "${DAYS_CLIENT}" -sha256 -extfile "${DEVICE_ID}.ext"

rm -f "${DEVICE_ID}.csr" "${DEVICE_ID}.ext"

echo
echo "Issued certificate for device '${DEVICE_ID}':"
ls -1 "${DEVICE_DIR}/${DEVICE_ID}.key" "${DEVICE_DIR}/${DEVICE_ID}.crt"
echo
echo "Copy ${DEVICE_ID}.key, ${DEVICE_ID}.crt, and ${CERT_DIR}/ca.crt onto the device for mdm-agent."
