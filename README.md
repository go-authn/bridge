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
| **access token** | RS256, `typ: at+jwt` (RFC 9068), `aud` = the client's `audience`, with `preferred_username` and `groups` so that a resource server can decide without asking anybody |
| **`sub`** | an HMAC of the institution's identifier under the salt: stable, not reversible, not an address. `public` (the same for every client) or `pairwise` per client (OIDC Core 8.1) |
| **scopes** | `profile` (name, given_name, family_name, preferred_username), `email`, `eduperson` (AARC-G056 names: `eduperson_principal_name`, `eduperson_scoped_affiliation`, `eduperson_entitlement`, `entitlements`, `schac_home_organization`, `voperson_id`...), `groups` |

The identifier behind `sub` is chosen in RENATER's order of preference:
`subject-id`, then `pairwise-id`, then `eduPersonPrincipalName`, then the
deprecated `eduPersonTargetedID`, then a persistent NameID. **Mail is never an
identifier**, and there is **no `email_verified`**: the IdP asserted an
address, which is not the same as anybody having verified that the person reads
it.

`prompt=none` becomes `IsPassive`, and an IdP with no session answers
`login_required`. `prompt=login` and `max_age` become `ForceAuthn`.
`acr_values` becomes `RequestedAuthnContext` -- and an IdP that ignores the
request (they may) is **refused**, so a client that asked for REFEDS MFA is
never told it got a second factor when it did not.

## What it refuses

| | why |
|---|---|
| an authorization request **without PKCE S256** | RFC 7636 makes `plain` the default when no method is given, so a missing method is refused rather than read as S256 |
| a **redirect URI** not registered exactly | shown on the page, never sent to the URI: an error sent anywhere a request names is an open redirector. Loopback URIs may change port (RFC 8252) |
| a parameter **twice** | RFC 6749 3.1 |
| a **code used twice** | refused, and the token the first use bought stops working (RFC 6749 4.1.2) |
| a code exchanged by **another client**, with **another redirect URI**, or the **wrong verifier** | a code is bound to all three |
| a **public client that sends a secret** | it is configured as something it is not |
| an IdP response delivered **into another browser** | the login is found through a cookie, not through the RelayState the response carries -- otherwise anybody could log somebody else in as themselves |
| an IdP that releases **no persistent identifier** | nobody could be recognised twice |
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
- The refusals were **sabotage-checked**: PKCE made optional, redirect URIs
  matched by prefix, the login found through RelayState, the replay revocation,
  the code's binding to its client, verifier and redirect URI, the scopes, the
  token type, `email_verified`, and a public client's secret each turn a test
  red.

## What it is not, yet

- **One process.** Logins in progress, codes and issued tokens live in memory:
  a restart costs people one login, and two instances behind a load balancer
  would each know half the codes.
- No refresh tokens, no device flow, no dynamic registration, no front- or
  back-channel logout.
- The device flow (for WebDAV clients without a browser), SSH certificates for
  SFTP and application passwords for SMB and S3 -- so that
  [go-fileshare](https://github.com/go-fileshare/fileshare) can serve every
  protocol to federated people -- are the next pieces.

## Licence

BSD-3-Clause.
