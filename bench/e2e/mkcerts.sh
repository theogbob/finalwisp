#!/bin/bash
# 80.04 L8: a throwaway CA + a P-256 leaf for 127.0.0.1 / localhost (webpki rejects a self-signed leaf)
set -e
D=${1:?dir}; mkdir -p "$D"; cd "$D"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 60 -subj "/CN=e2e-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out leaf.csr -subj "/CN=127.0.0.1" 2>/dev/null
printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n" > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cert.pem -days 60 -extfile leaf.ext 2>/dev/null
rm -f leaf.csr leaf.ext ca.srl
echo certs-ok
