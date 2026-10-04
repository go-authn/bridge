#!/usr/bin/env bash
# Runs the OpenID Foundation's oidcc-basic-certification-test-plan against
# the bridge built from this tree. Needs Go, Docker (compose) and openssl.
set -euo pipefail
cd "$(dirname "$0")"
W=work
rm -rf "$W" && mkdir -p "$W"

# Binaries: the bridge and the IdP for the containers, the driver for here.
(cd .. && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o conformance/$W/bridge .)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $W/testidp ./testidp
go build -o $W/driver ./driver

# Keys: throwaway, made for this run.
for k in idp fed sp; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$k" \
    -keyout $W/$k.key -out $W/$k.crt 2>/dev/null
done
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=bridge" \
  -addext "subjectAltName=DNS:bridge" -keyout $W/tls.key -out $W/tls.crt 2>/dev/null
# keygen runs where the containers do: this script is for linux/amd64 (CI).
$W/bridge keygen --key $W/oidc.key --salt $W/salt
fp=$(openssl x509 -in $W/fed.crt -outform der | openssl dgst -sha256 -r | cut -d' ' -f1 | tr a-f A-F)
for c in 1 2; do openssl rand -hex 24 > $W/client$c.secret; done
cb="https://localhost.emobix.co.uk:8443/test/a/bridge/callback"

cat > $W/bridge.hcl <<HCL
issuer            = "https://bridge:8443"
listen            = "0.0.0.0:8443"
cert_file         = "/work/tls.crt"
key_file          = "/work/tls.key"
signing_key_file  = "/work/oidc.key"
subject_salt_file = "/work/salt"

saml {
  key_file             = "/work/sp.key"
  cert_file            = "/work/sp.crt"
  metadata_url         = "http://idp:8080/federation.xml"
  metadata_cert_file   = "/work/fed.crt"
  metadata_fingerprint = "$fp"
  idps                 = ["http://idp:8080/metadata"]
  names                = { en = "Bridge" }
  technical_contact    = "noc@example.org"
}

client "conformance1" {
  secret_file      = "/work/client1.secret"
  redirect_uris    = ["$cb"]
  pkce             = "or_nonce"
  refresh_lifetime = "1h"
}

client "conformance2" {
  secret_file      = "/work/client2.secret"
  redirect_uris    = ["$cb"]
  pkce             = "or_nonce"
  refresh_lifetime = "1h"
}
HCL

cat > $W/plan.json <<JSON
{
  "alias": "bridge",
  "description": "go-authn/bridge",
  "server": { "discoveryUrl": "https://bridge:8443/.well-known/openid-configuration" },
  "client":  { "client_id": "conformance1", "client_secret": "$(cat $W/client1.secret)" },
  "client2": { "client_id": "conformance2", "client_secret": "$(cat $W/client2.secret)" },
  "browser": [
    {
      "match": "https://bridge:8443/authorize*",
      "tasks": [
        { "task": "Post the IdP's answer", "optional": true, "match": "http://idp:8080/sso*",
          "commands": [ [ "click", "id", "SAMLSubmitButton", "optional" ] ] },
        { "task": "Verify Complete", "match": "*/test/*/callback*",
          "commands": [ [ "wait", "id", "submission_complete", 10 ] ] }
      ]
    }
  ]
}
JSON

docker compose up -d
trap 'docker compose logs --no-color bridge idp > $W/containers.log 2>&1 || true; docker compose down -v >/dev/null 2>&1 || true' EXIT
$W/driver -config $W/plan.json -expected expected.txt
