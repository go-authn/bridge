# bridge

[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/bridge/actions/workflows/ci.yml)

**An OpenID Connect provider in front of a SAML federation.** People log in at
their own university, through RENATER's Fédération Éducation-Recherche or
eduGAIN, and applications get an OpenID Connect token. Pure Go,
`CGO_ENABLED=0`, one binary.

```sh
go install github.com/go-authn/bridge@latest

bridge keygen   --key /var/lib/bridge/oidc.key --salt /var/lib/bridge/salt
bridge metadata --config /etc/bridge.d > sp.xml     # register this with the federation
bridge check    --config /etc/bridge.d
bridge          --config /etc/bridge.d
```

It does what SATOSA does for RENATER, which RENATER's technical framework names
as the gateway a bilateral-trust product such as Keycloak needs. The SAML half
is [go-authn/saml](https://github.com/go-authn/saml).

## The configuration

```hcl
issuer            = "https://login.example.org"
signing_key_file  = "/var/lib/bridge/oidc.key"   # bridge keygen --key
subject_salt_file = "/var/lib/bridge/salt"       # bridge keygen --salt; NEVER change it
listen            = "127.0.0.1:8080"             # the public listener: loopback by default, behind a TLS proxy

saml {
  key_file  = "/etc/bridge/saml.key"             # IdPs encrypt assertions to this
  cert_file = "/etc/bridge/saml.crt"

  metadata_url         = "https://pub.federation.renater.fr/metadata/fer/idps.xml"
  metadata_cert_file   = "/etc/bridge/metadata-signature-2026.pem"
  metadata_fingerprint = "68:2F:20:58:41:9E:D0:79:EB:FE:3C:27:D6:A4:A4:09:39:6F:AE:3F:10:5F:22:EA:04:0F:04:F3:78:2D:5C:C0"

  discovery = "https://discovery.renater.fr/renater"   # or leave it out for this provider's own list
  # idps    = ["https://idp.univ-example.fr/idp/shibboleth"]   # restrict; one entry skips the choice

  names             = { fr = "Passerelle OIDC de l'IRHC", en = "IRHC OIDC gateway" }
  technical_contact = "admin@example.org"
}

claims {
  username = "eppn"            # becomes preferred_username: eppn, subject_id, uid or mail
  groups   = ["entitlement"]   # becomes groups: entitlement, scoped_affiliation, affiliation, is_member_of
}

client "fileshare-web" {
  secret_file   = "/etc/bridge/fileshare-web.secret"   # absent: a public client
  redirect_uris = ["https://files.example.org/callback"]
  audience      = ["fileshare"]                         # what the access token is for
}
```

The metadata signing certificate is **pinned by its fingerprint**, which is
checked at every start: a key that arrives over the same channel as the
document it vouches for vouches for nothing. RENATER publishes the fingerprint
on its metadata page; the one above is the 2026 certificate's.

## What an application gets

| | |
|---|---|
| **flow** | authorization code, with **PKCE S256 required for every client** |
| **ID token** | RS256, `aud` = the client, `nonce`, `auth_time`, `acr` (the IdP's authentication context), `at_hash` |
| **access token** | RS256, `typ: at+jwt` (RFC 9068), `aud` = the client's `audience`, with `preferred_username`, `groups` and `idp` (the entity ID of the IdP that vouched) so that a resource server can decide without asking anybody. A token carrying `ssh`, `nfs` or `app_password` is addressed to **this provider alone** (`aud` = the issuer), and those endpoints refuse any other: a token a resource server received cannot be replayed here |
| **`sub`** | an HMAC of the institution's identifier under the salt: stable, not reversible, not an address. `public` (the same for every client) or `pairwise` per client (OIDC Core 8.1) |
| **scopes** | `profile` (name, given_name, family_name, preferred_username), `email`, `eduperson` (AARC-G056 names: `eduperson_principal_name`, `eduperson_scoped_affiliation`, `eduperson_entitlement`, `entitlements`, `schac_home_organization`, `voperson_id`...), `groups` |

The identifier behind `sub` is chosen in RENATER's order of preference:
`subject-id`, then `pairwise-id`, then `eduPersonPrincipalName`, then the
deprecated `eduPersonTargetedID`, then a persistent NameID. **Mail is never an
identifier**, and there is **no `email_verified`**: the IdP asserted an
address, which is not the same as anybody having verified that the person reads
it.

`prompt=none` becomes `IsPassive`, and an IdP with no session answers
`login_required`. `prompt=login` and `max_age=0` become `ForceAuthn`; any other
`max_age` goes without it, and when the IdP's `AuthnInstant` is older than
`max_age` the person is sent back to it with `ForceAuthn` (OIDC Core 3.1.2.1:
re-authenticate only "if the elapsed time is greater").
`acr_values` becomes `RequestedAuthnContext` -- and an IdP that ignores the
request (they may) is **refused**, so a client that asked for REFEDS MFA is
never told it got a second factor when it did not.

**Groups are held to the IdP that asserted them.** A federation has hundreds
of IdPs, and groups decide what a person may do -- at every resource server,
in the SSH and X.509 certificates. With more than one IdP allowed to log in,
an `eduPersonEntitlement` or `isMemberOf` value is kept only if its namespace
is one of that IdP's shibmd scopes or under one: `urn:mace:<domain>:...`,
`urn:geant:<domain>:...` (AARC-G002), `https://<host>/...`. Any other value
is dropped, in `groups` and in `entitlements` alike. `affiliation`, which names
no institution, needs `saml { idps }` to list exactly one IdP. A community
proxy asserting groups for people of many institutions is named explicitly:

```hcl
claims {
  trusted_groups = {
    "https://proxy.eduteams.org/saml2/idp/metadata.php" = ["urn:geant:eduteams.org:"]
  }
}
```

With exactly one IdP, that IdP is trusted for every value, as before.

## What it refuses

| | why |
|---|---|
| an authorization request **without PKCE S256** | RFC 7636 makes `plain` the default when no method is given, so a missing method is refused rather than read as S256. A **confidential** client configured `pkce = "or_nonce"` may send an OpenID `nonce` instead, as RFC 9700 2.1.1 allows; then a `code_verifier` for that code is refused, which is the RFC's downgrade check. A public client cannot be so configured. |
| a **redirect URI** not registered exactly | shown on the page, never sent to the URI: an error sent anywhere a request names is an open redirector. Loopback URIs may change port (RFC 8252) |
| a parameter **twice** | RFC 6749 3.1 |
| a **code used twice** | refused, and the token the first use bought stops working (RFC 6749 4.1.2) |
| a code exchanged by **another client**, with **another redirect URI**, or the **wrong verifier** | a code is bound to all three |
| a **public client that sends a secret** | it is configured as something it is not |
| an IdP response delivered **into another browser** | the login is found through a cookie, not through the RelayState the response carries -- otherwise anybody could log somebody else in as themselves |
| an IdP that releases **no persistent identifier** | nobody could be recognised twice |
| a **username with a comma, a space, a quote or a control character**, for an SSH or X.509 certificate | sshd reads `principals="a,b"` and AuthorizedPrincipalsFile entries as lists: one such name is two |
| everything [go-authn/saml](https://github.com/go-authn/saml#what-it-refuses) refuses | unsigned or SHA-1 assertions, several assertions, replay, foreign scopes, unauthenticated CBC... |

And at configuration time: an issuer that is not https, a salt under 32 bytes,
an RSA key under 2048 bits, a code lifetime over ten minutes, a client secret
somebody can guess, a redirect over cleartext http, a restricted IdP list
together with RENATER's discovery service (which cannot be restricted).

## Verified against things this repository did not write

- The **federation and the IdP are xmlsec1**: it signs the federation's
  metadata and signs and encrypts every response (AES-128-GCM, RSA-OAEP,
  Response signed -- a Shibboleth IdP v5's defaults).
- The **relying party is golang.org/x/oauth2 and coreos/go-oidc**: they
  discover the provider, build the request with PKCE, exchange the code,
  verify the ID token with its nonce and `at_hash`, and ask `/userinfo`.
- The **access token is checked by go-authn/oidc** with audience `fileshare`,
  exactly as [go-fileshare](https://github.com/go-fileshare/fileshare) checks
  the tokens WebDAV clients bring it; and the ID token is refused there.
- **go-fileshare itself**, the released binary: an X.509 certificate issued here
  opens a share over NFS with TLS, an SSH certificate over SFTP, and once the
  person is disabled here the next NFS call, the SFTP session already open and
  a new SFTP login are all refused within seconds -- through the CRL and the
  KRL go-fileshare fetches from this provider.
- The **[OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)**,
  the one OpenID Provider certification runs, executes its
  `oidcc-basic-certification-test-plan` (static clients, discovery) against
  the bridge built from every pull request, logging in through a SAML IdP on
  the way (`conformance/`). Every module passes or is listed, with why, in
  `conformance/expected.txt` -- the two deliberate refusals: a request with
  neither PKCE nor a nonce, and `acr_values` an IdP did not honour. The
  workflow fails on any other, and on a listed one that starts passing.
  The same run executes its `openid-ssf-transmitter-caep-test-plan` (poll
  delivery) against the Shared Signals transmitter, the CAEP event triggered
  through the admin API as an operator would; every module passes.
- The **relying party is also [openid-client](https://github.com/panva/openid-client)**,
  an OpenID Certified one, over TLS: discovery's issuer, the RFC 9207 `iss`
  parameter, the ID token, userinfo against its `sub`, the access token as an
  RFC 9068 resource server checks it (`validateJwtAccessToken`), refresh
  rotation and reuse, and the device grant (`openidclient_test.go`).
- The **ACME CA is [Pebble](https://github.com/letsencrypt/pebble)**, Let's
  Encrypt's test CA, with External Account Binding required: it refuses a
  wrong MAC key, validates tls-alpn-01 against the listener itself, and the
  certificate served chains to its root.
- The refusals were **sabotage-checked**: PKCE made optional, redirect URIs
  matched by prefix, the login found through RelayState, the replay revocation,
  the code's binding to its client, verifier and redirect URI, the scopes, the
  token type, `email_verified`, and a public client's secret each turn a test
  red.

## Without a browser: the device grant, and `bridge token`

A WebDAV client, a script, a terminal has no browser to send to a university.
It asks for a code instead (RFC 8628), and the person logs in on any other
device:

```hcl
client "rclone" {
  device           = true
  audience         = ["fileshare"]
  refresh_lifetime = "720h"     # refresh tokens, off unless set
  name             = "rclone (WebDAV)"
}
```

```sh
bridge token --issuer https://login.example.org --client rclone
```

prints an access token, logging in the first time and refreshing quietly after
that -- which is exactly rclone's `bearer_token_command` for
[go-fileshare](https://github.com/go-fileshare/fileshare) over WebDAV. It is
golang.org/x/oauth2's device client, not one written here.

| | |
|---|---|
| **user codes** | eight letters from RFC 8628's alphabet (no vowels, no digits), ten tries per address per ten minutes |
| **the confirmation page** | names the application and says to refuse a code somebody else sent: RFC 8628 5.4's remote phishing, where the ATTACKER's device gets the token |
| **polling** | `slow_down` adds five seconds for good; a device code buys one set of tokens |
| **refresh tokens** | rotate (RFC 9700 4.14.2) inside a family whose end is fixed at the login; a retired one used again revokes the family and the access tokens it bought |

## SSH certificates, for SFTP

```hcl
certificates_file = "/var/lib/bridge/certificates.json"   # every certificate issued, and the revoked
ssh_ca {
  key_file = "/var/lib/bridge/ssh-ca"   # bridge keygen --ssh-ca
  validity = "12h"
}
client "sftp" {
  device           = true
  ssh_certificates = true
}
```

`bridge ssh-cert --issuer ... --client sftp` logs in with a code and writes
`~/.ssh/id_ed25519-cert.pub`, where ssh and sftp find it. The certificate has
**exactly one principal**, the `preferred_username` -- PROTOCOL.certkeys makes
an empty list valid for ANY user, so there is never one -- no `permit-*`
extension, the person's groups in `groups@go-authn.org`, and it ends with the
IdP's session when that is sooner. go-fileshare trusts it with `oidc {
ssh_ca_file }`.

## X.509 certificates, for NFS over TLS

NFS over TLS (RFC 9289) can name the client by its certificate. This
provider issues one to a person who logged in, for a key made on their machine:

```hcl
certificates_file = "/var/lib/bridge/certificates.json"
x509_ca {
  key_file  = "/var/lib/bridge/nfs-ca/ca.key"    # bridge keygen --x509-ca /var/lib/bridge/nfs-ca
  cert_file = "/var/lib/bridge/nfs-ca/ca.crt"    # what go-fileshare trusts
  validity  = "12h"
}
client "nfs" {
  device            = true
  x509_certificates = true
}
```

`bridge nfs-cert --issuer ... --client nfs` makes a P-256 key, sends a
certificate request with the "nfs" scope, and writes the certificate and key
in PEM, and in the DER the kernel keyring takes, with the mount command.

- The person is a subjectAltName **otherName 1.3.6.1.4.1.2238.1.1.1**, a
  UTF8String `user@domain`, exactly one: what FreeBSD's `rpc.tlsservd -u`
  reads (draft-cel-nfsv4-rpc-tls-othername). FreeBSD maps it only when
  `domain` is its own NFSv4 domain and `user` is in its passwd; go-fileshare
  maps the whole name.
- The groups are URI names beside it,
  `tag:go-authn.github.io,2026:group:<group, percent-encoded>` (RFC 4151). Not
  an extension of the UUID arc: `x509.ParseCertificate` refuses a whole
  certificate whose extension OID has an arc larger than an `int` (measured),
  so every Go server would.
- Client authentication only, the CN the username (empty, and the SAN
  critical, past 64 characters), a CRL distribution point, and no longer than
  `validity`, the IdP's session or the CA's own certificate.
- **`GET /x509/crl`**: DER, signed by the CA that signs the certificates,
  `NextUpdate` an hour on and issued again every half hour, its number rising
  at every issue (RFC 5280 5.2.3: two CRLs whose thisUpdate differ have
  different numbers), its `ETag` the content's. An issue is never dated
  before the one it replaces, even if the clock steps back. Disabling or revoking a person lists their certificates there until
  they expire; enabling them again takes nothing off. openssl verifies the
  certificates and says `revoked` once they are listed.

⛔ **A certificate names the machine, not the user of it.** RFC 9289: the
server 'cannot utilize the remote TLS peer identity to authenticate RPC
users'. Linux sets the client certificate per mount (`cert_serial`,
`privkey_serial`), so everybody using that mount is the person it names:
this is for a machine one person uses, and `bridge nfs-cert` says so.

On the Linux client (measured by go-fileshare against Linux 6.17 and
ktls-utils 0.9): tlshd verifies the SERVER's certificate against the system
trust store only, ignoring `x509.truststore`; certificate files named in
`/etc/tlshd.conf` must be root's, the key mode 600 -- either mistake shows
only as `gnutls: Error in the certificate (-43)`; and MOUNT's MNT goes in the
clear, so a refused person sees "access denied" at the first access, not at
mount. `bridge nfs-cert` prints all three.

Every certificate, SSH and X.509, is recorded in `certificates_file` before it
is handed out: one that cannot be recorded is not issued, since it could
never be revoked. The file is required with `ssh_ca` or `x509_ca`.

## Application passwords, for SMB and S3

NTLMv2 and SigV4 prove a secret the server must already hold, so no token will
do. `bridge app-password --issuer ... --client files` sets one, generated,
shown once, into a database go-fileshare reads with a `users "sql"` block:

```hcl
client "files" {
  device        = true
  app_passwords = true         # its tokens, with the app_password scope, may set one
}

app_passwords {
  driver   = "sqlite"          # or postgres, mysql
  dsn_file = "/etc/bridge/apppw.dsn"
  store    = ["nt_hash"]       # SMB only: the default. Add "password" for S3.
  lifetime = "2160h"
}
```

What is stored is what the protocols need: the NT hash for SMB, the password
itself only when S3 is asked for.

The table is `login, password, nt_hash, expires, idp` (`idp`, the institution
that vouched, since v0.4.0). Name the columns in go-fileshare's query, never
`*`: go-authn/directory's sqldir reads them by position and refuses more than
it knows, so a `*` breaks at the first restart after a column is added:

```sql
-- sqlite; PostgreSQL: expires > extract(epoch from now())
select login, password, nt_hash from app_passwords where expires > strftime('%s','now')
```

(This is the query the tests run through sqldir.)

## OpenPubkey and opkssh

[OpenPubkey](https://github.com/openpubkey/openpubkey) commits the user's key in
the ID token's nonce, and opkssh turns that into SSH logins with no CA at all.
This provider does what that needs: the nonce comes back verbatim in the code
flow and in the device flow (where the openpubkey client sends it on the
device authorization request), RS256 so that GQ signatures work, and

```hcl
retired_signing_key_files = ["/var/lib/bridge/oidc-2026-03.key"]
```

because a PK Token outlives the ID token inside it and the openpubkey verifier
only fetches the keys published now: a retired key stays in the JWKS,
verifying and never signing, for at least the longest PK Token lifetime any
verifier allows (opkssh: a day by default, up to a week). Give opkssh a client
of its own -- `http://localhost:3000/login-callback` and its two siblings as
redirect URIs -- because its ID token travels to every server it logs into.

Judged by the openpubkey library itself: its client makes PK Tokens through
the device flow, with GQ signatures, and through the loopback code flow; its
verifier accepts them, and refuses one signed by a key no longer published.

## TLS: from files, or from an ACME CA

Both are [go-authn/servercert](https://github.com/go-authn/servercert)'s,
shared with go-fileshare. The public listener serves TLS itself when told to, or plain HTTP behind a
reverse proxy. From files -- certbot's, a Kubernetes secret -- which are
**read again when they change** (compared by content at most every 10 seconds;
a pair that does not load yet, the certificate renewed before its key, keeps
the one that did):

```hcl
cert_file = "/etc/letsencrypt/live/login.example.org/fullchain.pem"
key_file  = "/etc/letsencrypt/live/login.example.org/privkey.pem"
```

Or from an ACME CA, for the issuer's host and no other:

```hcl
acme {
  accept_terms_of_service = true             # the operator's agreement; no default
  cache_dir = "/var/lib/bridge/acme"        # account key and certificates
  email     = "noc@example.org"
  # Let's Encrypt by default: tls-alpn-01 on the listener itself, which then
  # has to be the one on port 443; or http-01 with
  # http_listen = ":80"                      # which also redirects to https
}
```

**GÉANT TCS** -- what French institutions get through RENATER, issued by
HARICA since 2025 -- is ACME with External Account Binding. With an
*Enterprise Admin* ACME account the domains are validated in HARICA's
portal beforehand, so no challenge is asked and nothing has to reach the
provider from outside:

```hcl
acme {
  accept_terms_of_service = true
  directory_url     = "<the ACME directory URL cm.harica.gr shows for the account>"
  eab_key_id        = "<key id from cm.harica.gr>"
  eab_hmac_key_file = "/etc/bridge/harica-eab.key"   # the HMAC key, base64url
  email             = "noc@example.org"             # HARICA requires one
  cache_dir         = "/var/lib/bridge/acme"
}
```

`directory_ca_file` trusts a private ACME CA (step-ca) for the directory's own
TLS.

`cache_dir` holds private keys, so the provider refuses to start on one that
anybody else could reach or re-point. That means a symbolic link, mode beyond
`0700`, or an owner other than the provider's user. **Every directory above
it** is held to sshd's StrictModes rule: owned by root or that user, and not
writable by group or others unless sticky. A missing `cache_dir` is created
`0700`. Since bridge v0.16.5 (go-authn/servercert v0.3.0) the directories
above are checked too, not only the last one. A `/var/lib/bridge` that a
group can write now stops the provider at startup, naming the path.

⛔ golang.org/x/crypto/acme (v0.57.0) polls a finalized order at the URL in
the finalize response's `Location` header, which RFC 8555 does not put there
([golang/go#77704](https://github.com/golang/go/issues/77704)): Let's
Encrypt sends one, Pebble and Buypass do not, and a CA that does not gets its
certificate never fetched. servercert learns each order's URL from the
new-order response, where RFC 8555 does require it, and supplies it. Whether
HARICA sends the header is not known here; with this, it does not matter.

⛔ The SAML key and certificate (`saml { key_file cert_file }`) are not this
certificate and never change with it: they are in the federation's metadata,
and every IdP encrypts to them.

## ssh-oidc (KIT: oidc-agent, mccli, motley-cue, pam-ssh-oidc)

[ssh-oidc](https://ssh-oidc-doc.data.kit.edu/) logs people into SSH with an
access token: oidc-agent gets it, mccli sends it, motley-cue on the server
checks it at this provider's `/userinfo` and maps the person to a local account.
It needs nothing this provider lacks -- no dynamic registration, no
introspection, no token exchange -- only a client for oidc-agent:

```hcl
client "oidc-agent" {
  # public: oidc-gen --pub --client-id oidc-agent
  redirect_uris    = ["http://localhost:8080", "http://localhost:4242", "http://localhost:43985"]
  device           = true
  refresh_lifetime = "720h"   # oidc-agent refuses a provider that gives no refresh token
  audience         = ["ssh"]  # what motley-cue's audience says
}
```

and on the server, in `motley_cue.conf`:

```ini
[authorisation.bridge]
op_url = https://login.example.org
scopes = ["openid", "profile", "email", "eduperson"]
vo_claim = eduperson_entitlement   # or groups
audience = ssh
```

What to know, read in their sources (not yet run end to end):

- **`sub` must be public** (the default): motley-cue keys an account on
  `sub`, and a pairwise `sub` is one per client -- the same person through
  two clients would get two accounts.
- **Tokens and the 1023 characters** OpenSSH reads as a keyboard-interactive
  answer: an RS256 access token with a 3072-bit key is about 1150 characters
  before any group. Sign access tokens with a P-256 key instead -- ID tokens
  stay RS256 --

  ```hcl
  access_token_key_file = "/var/lib/bridge/access-token.key"   # bridge keygen --access-token-key
  ```

  and one with a long eppn and three AARC entitlements is 953 (measured). Past
  that, mccli asks motley-cue for a one-time password instead, which
  motley-cue allows by default; a token pasted into plain `ssh` has to fit.
  go-authn/oidc (go-fileshare), coreos/go-oidc and flaat (motley-cue) all
  verify ES256.
- **`/userinfo` is how motley-cue checks every token.** Give the provider a
  `state` block (below) so that a restart does not refuse every token handed
  out before it.

## State: what a restart must not forget

```hcl
state {
  driver   = "postgres"                  # or sqlite, mysql
  dsn_file = "/etc/bridge/state.dsn"
}
```

Refresh token families, the refresh tokens and the retired ones (so that one
used again after a restart still revokes its family), and the access tokens
honoured at `/userinfo` and for certificates, written through to one table,
`bridge_state`, and read at start. Without it they live in memory, and a
restart logs everybody out.

A login in progress is not among them: it travels in its own cookie, sealed
(AES-256-GCM, under a key derived from the subject salt) so that the browser
can neither read nor change it -- the way SATOSA, the SAML-OIDC proxy of the
R&E federations, carries its state. Starting one costs this provider nothing
it keeps, a restart between the application and the IdP's answer costs the
person nothing, and an authorization request too large to carry (state,
nonce, redirect URI together past what a cookie holds) is refused at the
start. Once an IdP has answered for a login, its handle is remembered until
the login would have expired, so it is answered once; with a `state` block,
that and the IDs of the assertions accepted are written there too, so that a
restart, or another instance, does not accept the same answer twice. A login
ends against the configuration in force then: a redirect URI or an IdP removed
meanwhile is not honoured.

- A refresh token is kept as its **SHA-256**, never as itself: whoever reads
  the database cannot use what is in it (Ory Hydra's fosite keeps a signature
  for the same reason). Access tokens are kept by their `jti`, not a secret.
- A revocation the database did not take would come back at the next start: a
  delete that fails is retried at every later write, and until it succeeds
  the provider is **not ready** (`/readyz`, the gRPC health).
- Tested across restarts on SQLite and PostgreSQL: tokens still work, revoked
  ones stay revoked, a retired refresh token used again still revokes its
  family; with no `state` block the same restart forgets, which is the control.

## Shared Signals: telling the services that verify on their own

An access token, an opkssh certificate, are checked where they are used,
against keys, and nothing brings them back here: a person disabled here keeps
them until they expire. So this provider is an [OpenID Shared
Signals](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
transmitter: on `DisablePerson`, `RevokePerson` and `DisableIdP` it queues a
[CAEP](https://openid.net/specs/openid-caep-1_0-final.html) **session-revoked**
event -- everything issued to this subject before `event_timestamp` is void --
for every receiver that asked, go-fileshare among them.

```hcl
state { ... }            # required: a queue a restart empties loses revocations
ssf {}                   # event_retention = "192h" by default
client "fileshare-ssf" { # a receiver: client credentials, scope ssf
  secret_file  = "/etc/bridge/fileshare-ssf.secret"
  ssf_receiver = true
  audience     = ["fileshare"]
}
```

- **Poll delivery only** (RFC 8936): the receiver asks; nothing here dials
  out. `/.well-known/ssf-configuration` names the endpoints, under `/ssf/`.
- A receiver authenticates with an access token from the **client credentials**
  grant (RFC 6749 4.4, `ssf_receiver` clients only, scope `ssf`), and sees its
  own streams only.
- Events are SETs (RFC 8417) signed with the ID token key, `typ
  secevent+jwt`, no `exp`, no `sub`. The subject is `aliases` with the
  **account**, `acct:<username>`, by default -- a `sub` may be pairwise, one
  per client. A receiver configured `ssf_subject_format = "iss_sub"` gets
  instead the issuer and the **public** `sub` of each identity known under
  that person, one event each, which is what the CAEP Interoperability
  Profile (2.5) has transmitters send; a person nobody knows a `sub` for still
  reaches it, by account, since a revocation that does not arrive fails open.
  `session-revoked` always carries `reason_admin` (CAEP Interop 3.1). An
  institution disabled is one event per person
  this provider has a trace of there, and one whose subject is the **tenant**,
  with the institution's scopes: its people this provider has forgotten are
  covered by their domain.
- Streams and undelivered events are in the state database, until
  acknowledged or `event_retention`.
- A stream that is **paused or disabled answers a poll with an error**, not an
  empty 200 a receiver would read as "up to date"; paused, its events wait for
  it (SSF 1.0 8.1.1), disabled, none are kept. An event a receiver reports in
  error (`setErrs`) is **handed out again**, not dropped -- a key rotated inside
  its refresh window, a full disk -- until 10 reports or `event_retention`.
- HTTP, wire types and handlers are
  [go-ssf](https://github.com/hstern/go-ssf)'s. Judged by its client and
  its `Poller`, by go-jose against the published key set, and by go-fileshare
  itself, the release, over WebDAV: a token it verifies on its own is refused
  within seconds of the person -- or, for somebody forgotten here, their
  institution -- being disabled.

## Running it: the admin API, health and metrics

Both are off unless the configuration asks for them, and neither is ever on
the public listener:

```hcl
admin {
  listen = "unix:///run/bridge/admin.sock"      # mode 0600
  # or, over the network, mutual TLS and nothing less (loopback included):
  # listen         = "10.0.0.5:9443"
  # tls_cert_file  = "/etc/bridge/admin.crt"
  # tls_key_file   = "/etc/bridge/admin.key"
  # client_ca_file = "/etc/bridge/operators-ca.crt"
  # reflection     = true                       # for grpcurl; off by default
}

metrics { listen = "127.0.0.1:9101" }           # /healthz /readyz /metrics
```

**The admin API** is gRPC, `bridge.admin.v1.AdminService`
([`proto/bridge/admin/v1/admin.proto`](proto/bridge/admin/v1/admin.proto)),
with `grpc.health.v1` beside it:

| | |
|---|---|
| `Status` | version, the federation's metadata (IdPs, valid until, last refresh, last error), what is held in memory |
| `RefreshMetadata` | fetch the federation's metadata now |
| `ListIdPs`, `ListClients` | what the institution list shows, and the configured relying parties |
| `RevokePerson` | end somebody's refresh token families, the access tokens they bought, their device grants in progress and their application password |
| `DisablePerson`, `EnablePerson` | refuse somebody here -- at login and at every token, whatever their institution says -- and revoke what they hold; optionally until a given time |
| `DisableIdP`, `EnableIdP` | the same for everybody one institution vouches for: when its IdP is compromised, say. A metadata refresh does not lift it |
| `ListDisabled` | who is disabled, why, by whom, until when |

A person is disabled as who they are: usernames compare without case (eppn,
uid, mail and subject-id all compare so), the entry records the stable
identity of everybody known under that name, so another spelling from their
IdP does not let them back in, and a person whose IdP releases no username
is disabled by the `sub` a relying party knows them by -- public or pairwise,
matched at every login, whether or not anything of theirs is still live here.
Their application password and their SSF events reach every spelling of their
name the provider handed out.

Disabling is kept in a file, and refused without one -- somebody disabled
until the next restart would be let back in by the next deployment:

```hcl
disabled_file = "/var/lib/bridge/disabled.json"   # written whole, mode 0600
```

A file that cannot be read stops the provider from starting, for the same
reason. Disabling an institution also removes its people's application
passwords: those set from this version on carry the IdP that vouched for
them, and older ones are found by their scope when the username is scoped
(eppn, subject-id).

⛔ A removed application password stops working in go-fileshare when it next
reads its directory: at its `reload` interval, on SIGHUP, or when asked
(`fileshare.admin.v1.AdminService/ReloadDirectory`, since fileshare v0.10.0),
which also closes that person's open SMB, WebDAV and S3 sessions. Call it
after `DisablePerson` for the effect to be immediate. Everything that comes
back to this provider is refused at once.

SSH and X.509 certificates already issued are revoked with their person or
institution: they are listed in **`GET /ssh/krl`** (an OpenSSH KRL, what
`sshd`'s `RevokedKeys` and `ssh-keygen -Q` read) and `GET /x509/crl` until
they expire, and go-fileshare refuses them at login -- failing closed when it
cannot fetch a list recent enough.

Both lists are issued as [go-authn/revocation](https://github.com/go-authn/revocation)'s
protocol says, so that they can travel through anything -- a mirror, plain
HTTP, a file -- and still be checked:

- **The KRL is signed:** `GET /ssh/krl.sig` is a detached SSHSIG signature by
  the SSH CA key, namespace `krl@go-authn.github.io`, what OpenSSH recommends
  since it stopped verifying the KRL's own signature section.
  `ssh-keygen -Y verify` checks it. Fetch it with `If-Match: <the list's ETag>`;
  a list issued again in between answers 412.
- **Both say when they stop being current:** the CRL's `nextUpdate`, and the
  KRL's `expires@go-authn.github.io` extension, which sshd ignores. Each is an
  hour after issue, and a list is issued again every half hour, or at once
  when something is revoked.
- **The ETag is the content's.** It used to be the revocation counter while
  the body changed at every request, so a reader polling with
  `If-None-Match` kept a copy whose expiry passed: a reader that enforces the
  expiry then failed closed for good against a healthy provider.
  `TestAPollingReaderStaysCurrent` polls for two hours of clock.

For a plain `sshd`, or nginx and other TLS servers, **`revokd`**
(go-authn/revocation) fetches the lists, keeps only those that verify, and
writes them where they are read. When a list lapses it fails closed for sshd,
and with `listen` it serves the verified lists to other servers as a mirror.
The KRL is written by [go-authn/krl](https://github.com/go-authn/krl) and
checked here with `ssh-keygen -Q`.

**There are no users or groups to add or delete here.** People exist
because their institution vouches for them, and their groups are what it
asserts; the closest provider to this one, Dex, has no call to change them
either. Who may use what is decided by the service they reach -- a share in
go-fileshare names the groups it admits -- and a local list of people and
groups is [go-authn/directory](https://github.com/go-authn/directory)'s.

Every call that changes something is logged with who made it: the client
certificate's `cn=` over TLS, the peer's `uid=` on the socket. The listener is
[grpc-transports/control](https://github.com/grpc-transports/control), shared
with go-fileshare: the socket is never reachable by another user, not even
between bind and chmod, and never taken from an instance still running.

⛔ **What `RevokePerson` cannot end**: an access token already handed out is a
signed statement a resource server checks on its own, valid there until it
expires (an hour by default). Everything that comes back to this provider --
a refresh, `/userinfo`, an SSH certificate or an application password asked
with that token -- is refused at once; an SSH certificate already issued lasts
its validity, which is why that is short.

**Health and metrics** are
[go-net-health/endpoint](https://github.com/go-net-health/endpoint)'s, as in
go-fileshare: `/healthz` is up while the process answers; `/readyz` is ready
while the federation's metadata is loaded and still valid (a provider past
its `validUntil` knows no IdP); `/metrics` is Prometheus text 0.0.4 with
`bridge_*` families -- logins by outcome, tokens by grant, SSH certificates,
application passwords, metadata validity and refreshes, what is held in
memory. **No label names a person or an institution**: which universities'
people use the service, and when, is not this provider's to publish.

`-tags nogrpc` leaves gRPC out (4.1 MB of the binary) and refuses a
configuration with an `admin` block, rather than starting without it.

## Behind a reverse proxy, and under load

```hcl
trusted_proxies     = ["10.0.0.0/8"]   # whose X-Forwarded-For is believed
requests_per_minute = 120             # per address; 0 turns the limit off
```

Starting a login, a device grant and posting to the ACS cost memory or an RSA
operation before anybody is authenticated, so each address gets so many a
minute (429 past it). An address is an IPv4 address or an IPv6 /64 -- one host
holds a whole /64 -- and each IPv4 /24 and IPv6 /48 shares ten times that, so
a flood needs many networks rather than many addresses. A login in progress is
kept by its browser, not here (see State). The device grants waiting for
their person are capped at 20,000; past that, the oldest is pushed out rather
than everybody being refused. Behind a proxy, name it in `trusted_proxies`, or every
request is the proxy's: one address for the whole internet, and the wrong
device codes of one person lock out everybody. Every request is bounded: 1 MiB,
30 s to read, 60 s to answer, 2 min idle.

`claims { username = "uid" }` or `"mail"` needs `saml { idps }` to list exactly
one IdP: neither is held to an IdP's scopes, so with two, one names the
other's people.

## What it is not, yet

- **One process.** With a `state` block, refresh tokens and the access tokens
  honoured at `/userinfo` survive a restart; logins in progress, codes and
  device grants (minutes) do not. It is written through and read at start, so
  two instances on one database would each miss what the other wrote since:
  one instance still.
- No dynamic registration, no front- or back-channel logout.

## Licence

BSD-3-Clause.
