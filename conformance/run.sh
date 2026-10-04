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
# TLS: a CA for this run signs the bridge's and the IdP's certificates.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=conformance run CA" \
  -keyout $W/ca.key -out $W/ca.crt 2>/dev/null
for h in bridge idp; do
  out=$W/$h-tls; [ $h = bridge ] && out=$W/tls
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$h" -keyout $out.key -out $out.csr 2>/dev/null
  printf "subjectAltName=DNS:%s\n" $h > $out.ext
  openssl x509 -req -in $out.csr -CA $W/ca.crt -CAkey $W/ca.key -CAcreateserial -days 2 \
    -extfile $out.ext -out $out.crt 2>/dev/null
done
# keygen runs where the containers do: this script is for linux/amd64 (CI).
$W/bridge keygen --key $W/oidc.key --salt $W/salt
fp=$(openssl x509 -in $W/fed.crt -outform der | openssl dgst -sha256 -r | cut -d' ' -f1 | tr a-f A-F)
# The two clients' credentials: throwaway, made here and kept in variables,
# written once for the bridge and never read back.
c1=$(openssl rand -hex 24)
c2=$(openssl rand -hex 24)
c3=$(openssl rand -hex 24)
printf '%s' "$c1" > $W/client1.secret
printf '%s' "$c2" > $W/client2.secret
printf '%s' "$c3" > $W/client3.secret
printf 'file:/data/state.db' > $W/state.dsn
cb="https://localhost.emobix.co.uk:8443/test/a/bridge/callback"

# The browser, as the suite drives it: through the IdP's login page when it
# shows one (with "shot", its screenshot is what prompt=login and max_age=1
# ask a person to upload), its auto-posted answer, back to the suite.
login_entry() {
  local first='[ "click", "id", "testidp-login", "optional" ]'
  if [ "${1:-}" = shot ]; then
    first='[ "wait", "xpath", "//*", 10, "Sign in to the test IdP", "update-image-placeholder-optional" ], [ "click", "id", "testidp-login", "optional" ]'
  fi
  cat <<E
    { "match": "https://bridge:8443/authorize*", "tasks": [
        { "task": "Sign in at the IdP", "optional": true, "match": "https://idp:8443/sso*", "commands": [ $first ] },
        { "task": "Post the IdP's answer", "optional": true, "match": "https://idp:8443/sso*",
          "commands": [ [ "click", "id", "SAMLSubmitButton", "optional" ] ] },
        { "task": "Verify Complete", "match": "*/test/*/callback*",
          "commands": [ [ "wait", "id", "submission_complete", 10 ] ] } ] }
E
}
# A redirect URI the client did not register: the bridge answers with a page
# of its own, never a redirect, and the suite wants it shown.
error_entry() {
  cat <<E
    { "match": "https://bridge:8443/authorize*", "tasks": [
        { "task": "Expect the redirect URI error page", "match": "https://bridge:8443/authorize*",
          "commands": [ [ "wait", "xpath", "//*", 10, "did not register", "update-image-placeholder" ] ] } ] }
E
}

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
  metadata_url         = "https://idp:8443/federation.xml"
  metadata_cert_file   = "/work/fed.crt"
  metadata_fingerprint = "$fp"
  idps                 = ["https://idp:8443/metadata"]
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

# The Shared Signals transmitter, and the suite's receiver as its client.
disabled_file = "/data/disabled.json"
state {
  driver   = "sqlite"
  dsn_file = "/work/state.dsn"
}
admin {
  listen     = "unix:///data/admin.sock"
  reflection = true
}
ssf {}
client "ssf-receiver" {
  secret_file  = "/work/client3.secret"
  ssf_receiver = true
}
HCL

cat > $W/ssf.json <<JSON
{
  "alias": "bridge-ssf",
  "description": "go-authn/bridge, Shared Signals transmitter",
  "server": { "discoveryUrl": "https://bridge:8443/.well-known/openid-configuration" },
  "client": { "client_id": "ssf-receiver", "client_secret": "$c3", "scope": "ssf" },
  "ssf": {
    "subjects": {
      "valid":   { "format": "email", "email": "alice@univ-example.fr" },
      "invalid": { "format": "email", "email": "nobody@nowhere.invalid" }
    },
    "transmitter": { "issuer": "https://bridge:8443", "metadata_suffix": "" }
  }
}
JSON

cat > $W/plan.json <<JSON
{
  "alias": "bridge",
  "description": "go-authn/bridge",
  "server": { "discoveryUrl": "https://bridge:8443/.well-known/openid-configuration" },
  "client":  { "client_id": "conformance1", "client_secret": "$c1" },
  "client2": { "client_id": "conformance2", "client_secret": "$c2" },
  "client_secret_post": { "client_id": "conformance1", "client_secret": "$c1" },
  "browser": [
$(login_entry)
  ],
  "override": {
    "oidcc-prompt-login": { "browser": [ $(login_entry shot) ] },
    "oidcc-max-age-1": { "browser": [ $(login_entry shot) ] },
    "oidcc-ensure-registered-redirect-uri": { "browser": [ $(error_entry) ] },
    "oidcc-ensure-request-object-with-redirect-uri": { "browser": [ $(error_entry) ] }
  }
}
JSON

docker compose up -d
# The operator's tool, ready before a module waits for it.
docker compose --profile tools pull --quiet admin
trap 'docker compose logs --no-color bridge idp > $W/containers.log 2>&1 || true; docker compose down -v >/dev/null 2>&1 || true' EXIT
# The plan only means something against a bridge that answers.
for i in $(seq 1 60); do
  curl -skf https://localhost:9443/.well-known/openid-configuration >/dev/null && break
  [ $i = 60 ] && { echo "the bridge never answered discovery"; exit 1; }
  sleep 2
done
echo "the bridge answers discovery"
# Both plans run, whatever the first one says; the script fails if either did.
status=0
$W/driver -config $W/plan.json -expected expected.txt || status=1
echo
echo "== openid-ssf-transmitter-caep-test-plan (poll)"
$W/driver -config $W/ssf.json -expected expected-ssf.txt \
  -plan openid-ssf-transmitter-caep-test-plan \
  -trigger "docker compose run --rm -T admin -plaintext -d '{\"username\":\"alice@univ-example.fr\"}' unix:///data/admin.sock bridge.admin.v1.AdminService/RevokePerson" \
  -variant '{"ssf_delivery_mode":"poll","client_registration":"static_client","server_metadata":"discovery","client_auth_type":"client_secret_basic","ssf_server_metadata":"discovery","ssf_auth_mode":"dynamic"}' || status=1
exit $status
