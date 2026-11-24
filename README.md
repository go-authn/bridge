# bridge

[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/bridge/actions/workflows/ci.yml)

**An OpenID Connect provider in front of a SAML federation.** People log in at
their own university, through RENATER's Fédération Éducation-Recherche or
eduGAIN, and applications get an OpenID Connect token. Pure Go,
`CGO_ENABLED=0`, one binary.

```sh
go install github.com/go-authn/bridge/cmd/authn-bridge@latest

authn-bridge keygen   --key /var/lib/authn-bridge/oidc.key --salt /var/lib/authn-bridge/salt
authn-bridge metadata --config /etc/authn-bridge > sp.xml     # register this with the federation
authn-bridge check    --config /etc/authn-bridge
authn-bridge          --config /etc/authn-bridge   # serve
```

Release binaries, and installing one as a hardened systemd service:
[docs/install.md](docs/install.md). Before v0.20.0 the command was `bridge`
(see [Upgrading to v0.20.0](#upgrading-to-v0200)).

It does what SATOSA does for RENATER, which RENATER's technical framework names
as the gateway a bilateral-trust product such as Keycloak needs. The SAML half
is [go-authn/saml](https://github.com/go-authn/saml).

## The configuration

```hcl
issuer            = "https://login.example.org"
signing_key_file  = "/var/lib/authn-bridge/oidc.key" # authn-bridge keygen --key
subject_salt_file = "/var/lib/authn-bridge/salt"     # authn-bridge keygen --salt; NEVER change it
listen            = "127.0.0.1:8080"                 # the public listener: loopback by default, behind a TLS proxy

saml {
  key_file  = "/etc/authn-bridge/saml.key"   # IdPs encrypt assertions to this
  cert_file = "/etc/authn-bridge/saml.crt"

  metadata_url         = "https://pub.federation.renater.fr/metadata/fer/idps.xml"
  metadata_cert_file   = "/etc/authn-bridge/metadata-signature-2026.pem"
  metadata_fingerprint = "68:2F:20:58:41:9E:D0:79:EB:FE:3C:27:D6:A4:A4:09:39:6F:AE:3F:10:5F:22:EA:04:0F:04:F3:78:2D:5C:C0"

  discovery = "https://discovery.renater.fr/renater"   # or leave it out for this provider's own list
  # idps    = ["https://idp.univ-example.example/idp/shibboleth"]   # restrict; one entry skips the choice

  names             = { fr = "Passerelle OIDC de l'IRHC", en = "IRHC OIDC gateway" }
  technical_contact = "admin@example.org"
}

claims {
  username = "eppn"            # becomes preferred_username: eppn, subject_id, uid or mail
  groups   = ["entitlement"]   # becomes groups: entitlement, scoped_affiliation, affiliation, is_member_of
}

client "fileshare-web" {
  secret_file   = "/etc/authn-bridge/fileshare-web.secret"   # absent: a public client
  redirect_uris = ["https://files.example.org/callback"]
  audience      = ["fileshare"]                         # what the access token is for
}
```

The metadata signing certificate is **pinned by its fingerprint**, which is
checked at every start: a key that arrives over the same channel as the
document it vouches for vouches for nothing. RENATER publishes the fingerprint
on its metadata page; the one above is the 2026 certificate's.

### Describing this provider to the federation

A registry (RENATER, eduGAIN) asks more of an SP's metadata
(`/saml/metadata`) than names and a technical contact. Three blocks inside
`saml { }` are optional; configured, they add `md:Organization`, more
`md:ContactPerson`s and `mdui:Logo`s. Left out, the metadata is byte-for-byte
what it was. Every value is checked at start, and a bad one refuses to start
(the provider never publishes it to a federation): URLs are `https`, a logo has
a positive `width` and `height`, a contact `type` is one of `technical`,
`support`, `administrative`, `billing`, `other`, an e-mail is a bare address.

```hcl
saml {
  # ... as above ...
  technical_contact = "admin@example.org"      # written first, as before

  organization {
    names         = { en = "Example Org" }     # each map: by language, at least one entry
    display_names = { en = "Example Organisation", fr = "Organisation Exemple" }
    urls          = { en = "https://www.example.org/" }
  }

  contact {
    type       = "support"                     # technical, support, administrative, billing, other
    given_name = "Help desk"
    email      = "help@example.org"
  }
  contact {
    type       = "other"
    security   = true                          # the REFEDS security contact; type "other" only
    given_name = "Example CSIRT"               # required for a security contact (REFEDS)
    email      = "security@example.org"
  }

  ui {
    logo {
      url    = "https://login.example.org/logo.png"   # no lang: the default logo
      width  = 200
      height = 80
    }
    information_urls       = { en = "https://login.example.org/info/en", fr = "https://login.example.org/info/fr" }
    privacy_statement_urls = { en = "https://login.example.org/privacy/en", fr = "https://login.example.org/privacy/fr" }
  }
}
```

`information_url` and `privacy_statement_url` stay, and stand for the `en`
entry: giving one and an `en` entry of its map is refused. A data URI is not
accepted for a logo (saml2int SDP-MD10 allows one; here only `https`).

## What an application gets

| | |
|---|---|
| **flow** | authorization code, with **PKCE S256 required for every client** |
| **ID token** | RS256, `aud` = the client, `nonce`, `auth_time`, `acr` (the IdP's authentication context), `at_hash`, and **nothing about the person**: what the scopes release is at `/userinfo` (OIDC Core §5.4, since an access token is always issued). A client whose ID token is itself the credential, such as opkssh, sets `id_token_claims = true` to have them copied in |
| **access token** | RS256, `typ: at+jwt` (RFC 9068), `aud` = the client's `audience`, or the one resource it asked for ([RFC 8707](#several-resource-servers-a-token-for-one-at-a-time)), with `preferred_username`, `groups` and `idp` (the entity ID of the IdP that vouched) so that a resource server can decide without asking anybody -- `groups` unless the client sets `access_token_groups = false` ([ssh-oidc](#ssh-oidc-kit-oidc-agent-mccli-motley-cue-pam-ssh-oidc)). A token carrying `ssh`, `nfs`, `kerberos`, `wireguard` or `wireguard_peers` is addressed to **this provider alone** (`aud` = the issuer), and those endpoints refuse any other: a token a resource server received cannot be replayed here |
| **`sub`** | an HMAC of the institution's identifier under the salt: stable, not reversible, not an address. `public` (the same for every client) or `pairwise` per client (OIDC Core 8.1) |
| **scopes** | `profile` (name, given_name, family_name, preferred_username), `email`, `eduperson` (AARC-G056 names: `eduperson_principal_name`, `eduperson_scoped_affiliation`, `eduperson_entitlement`, `entitlements`, `schac_home_organization`, `voperson_id`...), `groups` |

`schac_home_organization` is released only when it is one of the asserting IdP's
`shibmd:Scope` values (exact, case-sensitive; go-authn/saml v0.6.0, bridge
v0.23.9): an IdP of one institution cannot state another's, which a relying
party that filters on the claim (the gateway's `accept`) would take for that
institution. **Upgrade:** an IdP whose metadata publishes no Scope for its domain
no longer has the claim released; ask its federation to publish it.

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
re-authenticate only "if the elapsed time is greater"). An `AuthnInstant` in
the future beyond the clock skew (three minutes) tells nothing about the
elapsed time, so it is treated like a stale one: the person is sent back with
`ForceAuthn`.
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

## Local accounts

For a deployment that is not (yet) registered with a federation, or that has a
few people no federation knows -- a computing centre's own staff -- the
provider can also hold accounts itself. They are **one more configured identity
source**, beside `saml`, not a built-in test IdP: every account is a person,
with one or more **passkeys**.

**Local accounts are passkey-only.** There is no password: no password field,
no route that reads one, no hash, no switch that brings them back. A password
is a secret both sides know, which can be phished and guessed; a provider that
holds none has none to lose. A person proves themselves with a WebAuthn
credential, unlocked on their device by a PIN or a biometric, and an account
exists only because an administrator invited it.

```hcl
local {
  accounts_file = "/etc/authn-bridge-local/accounts.hcl"   # root:authn-bridge 0640
  scope         = "mesocentre.example"                     # the accounts' domain
}

state {                                              # required: the passkeys live here
  driver   = "sqlite"
  dsn_file = "/etc/authn-bridge/state.dsn"
}
```

`saml` stays required: local accounts are added to the federation login, they
do not replace it (a provider with no federation at all is not what this is
for, yet). `state` is required with `local`: the passkeys, their signature
counters (which change at every login) and the invitations are in the state
database, never in the accounts file. The accounts file says who exists, and
holds nothing secret. It goes in a directory of its own: `--config DIR` reads
every `*.hcl` file of DIR as configuration, so an accounts file placed there is
refused by `check`, at startup and by `local-account`. `authn-bridge
local-account` writes it:

```hcl
account "alice" {
  name   = "Alice Martin"                              # required
  mail   = "alice@mesocentre.example"                  # optional
  groups = ["urn:geant:mesocentre.example:hpc:users"]  # optional
}
```

A `password_hash` (or `password`) in the file is **refused** when it is read,
with a message that says local accounts are passkey-only: the file was written
for a version that never shipped with them.

**More passkeys, without an administrator.** A signed-in local person adds,
lists and removes their own passkeys at `<issuer>/account` ("My account",
below); the login page links to it. `authn-bridge local-account invite` stays
the way to create an account and to recover one that lost every key.

**Which kind of account a client takes: `accounts` (v0.38.0).** A `client` block
may say that only one kind of person signs in to it:

```hcl
client "forgejo" {
  secret_file   = "/etc/authn-bridge/forgejo.secret"
  redirect_uris = ["https://git.example.org/user/oauth2/bridge/callback"]
  accounts      = ["local"]       # "local", "federated", or both (the default)
}
```

`accounts = ["local"]` is for a service that wants a hardware key: a person of
a SAML institution is refused, whatever their institution says. The rule is not
a menu entry. It is asked **everywhere a grant is made or used**: the
authorization endpoint sends the person to the one path the client takes (the
passkey page, or the federation; `prompt=none` for a local-only client answers
`login_required`); the federation step, the passkey step and the end of a login
each refuse a login of the other kind; and every token -- the code exchange, a
refresh, a device poll -- is refused for a person of the other kind, so a grant
bought before the restriction was written stops with it. The answer is
`access_denied`, at the client's redirect URI during a login and at the token
endpoint afterwards. `check` prints it on the client's line (`..., local
accounts only)`), and `accounts = ["local"]` without a `local` block is a
configuration error. The journal says why, without anything of the person but
the name the login line already carries:

```text
login: alice@univ-ex.example via https://idp.univ-ex.example/idp/shibboleth refused for forgejo: this client takes local accounts only
token: account kind not accepted by this client: this client takes local accounts only (alice@univ-ex.example via https://idp.univ-ex.example/idp/shibboleth for forgejo)
```

**Known limit.** The certificate endpoints (SSH, X.509, Kerberos, WireGuard) are
not tied to a client, so `accounts` does not apply to them: the restriction
covers OAuth/OIDC clients only.

## My account (`/account`)

Every signed-in person, federated or local, has a profile space at
`<issuer>/account` (the login page links to it; `/local/account` redirects).
There is no password in it and nothing is kept in the browser's storage.

**Getting in takes a fresh authentication**, made for this page and at most
five minutes old. A local account confirms with a passkey assertion (user
verification required, a challenge of its own kind: an OIDC login's assertion
does not open this page, nor the reverse). A federated person is sent to their
institution with `ForceAuthn`; the `AuthnInstant` the institution answers with
is checked as well, because an IdP may ignore `ForceAuthn`. What it buys is a
random token in a `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`,
no `Domain`), held in memory for five minutes, bound to the person, and judged
again at every use: disabling the person, removing the account or removing the
passkey it was made with ends it.

| Section | Who | What |
|---|---|---|
| Identity | everyone | login or eppn, name, mail, groups, and the source (local, or the institution's entity ID and name), **read-only**. Only a local account may change its **display name** (it is then the name its next sign-in carries). Mail and groups are never editable here: the page says who changes them (the administrator, or the institution), and a request to change them is refused and logged. |
| Passkeys | local accounts | add (`residentKey` and user verification required, existing keys excluded, at most 10), list (ID prefix, created, last used, backup-eligible, the one this confirmation was made with), remove. The last key is never removed; removing a key refuses the grants it bought (the #87 invariant), and ends the confirmation if it was made with that key. |
| Applications and sessions | everyone | the live refresh-token families, per client, with when they started and when they last rotated; revoke one, or all. This is `revokeFamily` and `revokeMatching`, the pieces `RevokePerson` uses. |
| Technical access | where configured | the SSH and X.509 certificates and WireGuard keys this provider issued, listed and revocable in the stores they were issued into. Access tokens already handed out stay valid at their resource servers until they expire, as with `RevokePerson`. |

Every change needs the page's CSRF token (derived from the session, under a
label of its own), a same-origin request (a form post carries `Origin: null`
with `Sec-Fetch-Site: same-origin`, a `fetch()` the real origin), room in the
host's failure budget, and leaves one audit line:
`account: audit: <login> <action> <what> from <address>`.

**What the journal says about a success.** One line per successful sign-in,
and nothing secret in it (no code, token, assertion, mail, name or group):

```text
login: <username> via <idp entityID> for <client_id> from <address>
login: <login> via <issuer>/local with passkey <8 hex> for <client_id> from <address>
account: <username> confirmed through <idp entityID> from <address>
account: audit: <login> stepup <16 hex> from <address>
token: authorization_code issued to <client_id> for <username>
token: refresh_token issued to <client_id> for <username>
```

The first two are a login at the authorization endpoint, federated and local
(`<8 hex>` is the passkey's ID as `local: <login> enrolled a passkey (<8 hex>)`
prints it); the next two are the account page's sign-in through an institution
and with a passkey (the page then opens with `account: audit: <login> confirm
federation …`); the last two are the tokens handed to the client.

The pages and the script are exercised in a real Chrome by
`TestRealBrowserPasskeyLifecycle` (`BRIDGE_REQUIRE_BROWSER=1` turns "no Chrome"
into a failure, as `BRIDGE_REQUIRE_JUDGE` does for the judges): enrolment from
an invitation, an OIDC login, the step-up, an identity edit refused, a second
passkey, a session ended from the page, a login with the second passkey, the
first passkey removed, and its login refused. The browser is driven through the
DevTools WebAuthn domain's virtual authenticator; no request is made on its
behalf.

**Adding a person, and the first administrator.** An administrator with access
to the host (root, or the service's user) issues a one-time invitation:

```sh
authn-bridge local-account invite --config /etc/authn-bridge --name "Alice Martin" \
          --mail alice@mesocentre.example --group urn:geant:mesocentre.example:hpc:users alice
# https://login.example.org/local/enroll#Qk3f...        (standard output: the URL, alone)

authn-bridge local-account invite        --config /etc/authn-bridge alice   # another key for alice
authn-bridge local-account revoke-invite --config /etc/authn-bridge alice
authn-bridge local-account passkeys      --config /etc/authn-bridge alice   # ID, created, last used, backup-eligible
authn-bridge local-account remove-passkey --config /etc/authn-bridge alice <id>   # 8+ hex characters of the ID
authn-bridge local-account remove        --config /etc/authn-bridge alice
```

Run `local-account` as **root** when the accounts directory is `root:authn-bridge`
0750 and the file 0640 (the layout of `docs/install.md`): the command replaces
the file through a temporary one next to it (`.accounts-NNN`), and as
`authn-bridge` it fails with `open /etc/authn-bridge-local/.accounts-NNN:
permission denied`. It keeps the file's owner and mode. Over SSH,
`ssh host sudo authn-bridge local-account … --name "Two words"` needs an inner
quote layer (`--name '"Two words"'`): ssh joins its arguments into one string
and the remote shell splits it again.

A passkey's ID, as `passkeys` lists it and `remove-passkey` takes it, is the
SHA-256 of the credential ID in lowercase hex: 64 characters, of which any
unique prefix of eight or more will do.

`invite` with `--name` creates the account (and its file); on an existing one it
adds a key. The token is in the URL's **fragment**, which a browser never sends,
so it is in no access log and no `Referer`; it is stored only as its SHA-256,
works **once**, expires (`--ttl`, 24 hours by default and 72 at most), and a new
invitation for a login replaces the pending one. There is no first-administrator
special case: the first account is an invitation like any other, issued from the
host, and "administrator" is a group in the `groups` the resource servers know
(`--group urn:geant:<scope>:hpc:admins`). Give the URL to the person over a
channel only they read. The commands read only the `local` and `state` blocks,
check what they write with the provider's own parser, keep the comments and the
order of the accounts file, and replace it atomically. The invitations and
passkeys are read from the database at every use, so none of this needs a
restart.

**Enrolment.** `<issuer>/local/enroll` is a static page whose script reads the
token from the fragment (and removes it from the address bar), posts it, and
calls `navigator.credentials.create` with the RP ID the **issuer's host**,
`residentKey: "required"` (a discoverable credential), `userVerification:
"required"`, `attestation: "none"`, the algorithms ES256, EdDSA and RS256, and
the account's existing keys in `excludeCredentials`. The server verifies the
registration with [go-authn/webauthn](https://github.com/go-authn/webauthn)
(origin, rpIdHash, challenge, user presence and verification, COSE key on its
curve, a credential ID of at most 1023 bytes, strict CBOR), refuses a credential
already registered, **burns the invitation** (only the request whose delete
found it goes on), and stores the credential. At most ten per account.

**What a login is.** When `local` is configured, an authorization request goes
to a page offering the federation or a local account (`prompt=none` keeps going
to the federation: there is no session of a local account to find). The local
page offers "Se connecter avec une clé d'accès / Sign in with a passkey", with
**discoverable credentials**: `allowCredentials` is empty, `userVerification` is
required, and the user handle the authenticator returns -- an HMAC of the login
under a key derived from the subject salt, which says nothing about the login --
must be the credential's account. The page is served by the provider: one
script from this origin (`script-src 'self'`, nothing inline),
`default-src 'none'`, `base-uri 'none'`, a CSRF token bound to the login (an HMAC
of its handle under a key derived from the subject salt), a refused
`Sec-Fetch-Site: cross-site` and foreign `Origin`, and a destination taken only
from the redirect URI the request registered (no open redirect). A challenge is
single use, bound to its login and good for five minutes. The signature counter
is checked as WebAuthn says (refused when both are non-zero and it did not
advance; a synced passkey reports zero and is not refused). Refusals are
throttled **before any verification**: the eleventh from one host (an IPv6 /64;
its network gets ten times as many) in fifteen minutes is refused with 429, the
right key included. These counters are per process, in memory.

**The claims.**

| | |
|---|---|
| `idp` | `<issuer>/local`: the local accounts' entity ID, not configurable |
| `sub` | an HMAC under the subject salt of `local:` and the login, as for a federated person (`pairwise` per client too) |
| `preferred_username` | the login: lowercase `a-z 0-9 . _ -`, **never an `@`**, so that it cannot be taken for an eppn or a subject-id (at a relying party that matches on `preferred_username`, or as an SSH principal) |
| `name`, `email` | from the file; no `email_verified` |
| `eduperson_principal_name` | `<login>@<scope>` |
| `groups` | from the file, **held to `scope`** as an IdP's are held to its shibmd scopes: a group is accepted only if its namespace -- `urn:mace:<domain>:...`, `urn:geant:<domain>:...`, `https://<host>/...` -- is the scope or under it, or begins with a `claims { trusted_groups }` prefix listed for `<issuer>/local`. A group outside is **refused when the file is read**, not dropped |
| `acr` (ID token) | `https://refeds.org/profile/mfa`: REFEDS MFA. A passkey with user verification is two factors of different kinds (the authenticator the person holds, the PIN or biometric that unlocks it) and a signature over this origin and a fresh challenge, so it resists phishing and replay; user verification is **required** here, so it is always set |
| `auth_time` | the time of the login |

**Held to the configuration, like every grant.** Local accounts go through
`refused()` and `configuredIdP` as an IdP does: authorization codes, refresh
tokens, device grants, Kerberos tickets and SSH certificates bought with a
local account are refused as soon as the `local` block leaves the
configuration -- as soon as the account leaves the file -- and as soon as the
**passkey** it was bought with is removed ("account removed"): a token carries
the passkey that signed in, so removing one key ends what that key bought and
nothing else. What the certificate and application-password stores keep is the
login, not the key, so those are held to the account having at least one
passkey. Disabling the person through the admin API works by login. The local
entity ID is never accepted as a SAML IdP. With a `local` block, `claims {
username }` must be `eppn` or `subject_id` (a `uid` or a `mail` is not scoped,
and an IdP's `alice` would be the local `alice`), `groups = ["affiliation"]` is
refused, and the single IdP of `saml { idps }` is no longer trusted for every
group value: its groups are held to its shibmd scopes, since it is one of two
sources.

The accounts file is refused unless it is a regular file written by its owner
alone (it decides who is in which group), and it is read at most 1 MiB, 10 000
accounts. It holds no secret.

A browser end-to-end test (Chrome's virtual authenticator over the DevTools
protocol) is not run here: none of bridge, oidc, fido or rp has a headless-browser lane.
The tests drive the same HTTP routes the page's script does, with
`webauthntest`'s software authenticator, whose output is checked against an
independent verifier in go-authn/webauthn's judge.

## Telling the owner by e-mail: the `mail` block (v0.32.0)

A passkey can always cancel a pending removal, so a thief holding one key can
cancel the removal the owner asked for with another. Only a notice through a
channel that holds none of the person's passkeys lets the owner see it. With a
`mail` block, the bridge sends **a plain-text notice to the account's own
address** when a removal is requested or cancelled.

```hcl
mail {
  host          = "smtp.example.org"
  security      = "tls"                              # "tls" (port 465, the default) or "starttls" (587)
  username      = "authn-bridge"
  password_from = "systemd-creds:smtp"               # a secretsource reference to the SMTP password
  from          = "authn-bridge@example.org"
  # window      = "10m"                                # least time between two mails to one account (1m to 24h)
}
```

- **Who is told.** The `mail` of the account in the local accounts file, as
  the bridge knows it. Never an address taken from the request. It needs a
  `local` block (the notice is about local accounts' passkeys).
- **The password** comes from `password_from`, a
  [secretsource](https://github.com/go-authn/secretsource) reference, and from
  nowhere else (not the environment, not a command line, and never the
  password itself in this configuration file): `systemd-creds:NAME`,
  `file:PATH` (a regular file, not a symlink, owned by the user the bridge runs as and readable by that user alone, `0600`),
  `keychain:SERVICE/ACCOUNT`, and the other schemes of secretsource. A secret is
  one non-empty line of at most 4096 bytes. `password_file = "PATH"` is the
  **deprecated** spelling of `password_from = "file:PATH"`; setting both is a
  configuration error. A bad reference, and a block without `username` and
  `password_from`, is refused at startup.
- **TLS, always.** Implicit TLS, or STARTTLS the server offers and completes
  (otherwise the notice is not sent: never a conversation in clear). The server
  certificate is verified against the system roots and the host name. The
  bridge authenticates (PLAIN, else LOGIN; the strongest the server advertises)
  only once TLS is up, never over cleartext, not even to 127.0.0.1; a server
  advertising no usable mechanism after TLS is refused.
- **No link.** The text carries no URL to follow, says so, and tells the reader
  to open their account page from their own bookmark. Header values with CR, LF
  or other line separators are refused (the builder is fuzzed).
- **Rate limit.** One mail per account per `window`; the events that arrive
  meanwhile are collapsed into one digest sent when the window ends.

Two rules on failure, both visible to the person and in the log:

1. **A removal request whose notice cannot be sent stays pending.** It is not
   carried out when its delay ends. The bridge retries (up to 5 tries, with a
   growing pause), then logs `GAVE UP` loudly; the request resumes with the
   next event or a restart. The key keeps working meanwhile, as before.
2. **A cancellation always applies**, even if its mail fails. The failure is
   logged (`mailing <login> failed`) and the account page says the notice
   could not be sent.

An account with no usable address is not blocked: its request proceeds as
without a `mail` block, the log says `<login> has no usable mail address ...
nobody is told`, and the account page says so. Without a `mail` block nothing
changes.

## The pages, and your branding

Every page a person sees (the choice between the federation and a local
account, the passkey sign-in with its help panel, enrolment from an invitation,
`/account`, the device-code and confirmation pages, errors, the signed-out
state) is a server-rendered `html/template` page, in light or dark mode as the
browser asks, or as the person chose. A page is in ONE language, among the seven
of the fleet's documentation sites: `fr`, `en`, `de`, `es`, `ja`, `ko` and
`zh-cn`. The language is the `lang` cookie if there is one, else the browser's
`Accept-Language` (parsed with its q-values; `zh-CN`, `zh-Hans` and the other
`zh-*` tags give `zh-cn`), else French; `<html lang>` follows (`zh-CN` for
Chinese). The header has a language combo, a `<select>` that names each language
in itself (Français, English, Deutsch, Español, 日本語, 한국어, 简体中文). It is a
form (`GET /lang?lang=<code>&next=<path>`, which sets the cookie,
`SameSite=Lax`, and goes back) that works without script, with a visible submit
button; a tiny static same-origin script (`/ui.js`) submits it on change and
hides the button. Every string is in one catalogue (`internal/app/i18n.go`,
with `i18n_<code>.go` for the languages after French and English) and a test
fails on a missing translation in any of the seven. **The German, Spanish,
Japanese, Korean and Chinese texts were written without a native review;
corrections are welcome** (an issue or a pull request on `i18n_<code>.go`). The
terms follow the documentation sites' (the theme words are hextra's own). CJK
text uses system fonts only (PingFang, Hiragino, Noto Sans CJK, Microsoft
YaHei, Yu Gothic, Malgun Gothic) and wraps between characters on narrow screens.

`GET /` is a **home page**: what the service is, a "My account" button to
`/account`, what a passkey is (when there is a `local` block), and the
federation people can sign in through. An optional block lists the
deployment's own applications; every URL must be `https` (anything else stops
the start) and is escaped on the page:

```hcl
home {
  title = "Mésocentre de Saclay"                     # optional heading
  link "Fileshare" { url = "https://files.example.org" }
}
```

It shows nothing about clients, users or keys, and every other unknown path
stays 404.

The **theme** is light, dark or system (the default: the browser's
`prefers-color-scheme`), as on the docs: three buttons next to the combo, a form
(`GET /theme?theme=light|dark|system&next=<path>`) that works without script.
The choice is the `theme` cookie (`SameSite=Lax`, `Path=/`, nothing but the
word), and the SERVER writes `class="dark"` or `class="light"` on `<html>`, so
the first byte of the page is already right and nothing flashes. Tailwind's
`dark` variant follows that class when it is set and the media query when it is
not; the brand colour's computed variants exist for both. The enrolment page
(`/local/enroll`) and the auto-submitting page have neither control, because the
invitation lives in the URL's fragment, which a reload would lose; they still
follow the cookies and `Accept-Language`. They are drawn by one
[Tailwind CSS](https://tailwindcss.com) v4 stylesheet compiled at build time and
embedded in the binary, and by [Lucide](https://lucide.dev) icons (ISC licence,
`internal/app/web/icons/LICENSE`) inlined as SVG. Nothing is fetched from a CDN
or a third-party font: the stylesheet, the brand colour and the logo are served
from the provider's own origin, under `/assets/<name>.<hash>.<ext>`, so they
can be cached for good, and the content security policy of a page is
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'` (plus
`connect-src 'self'` on the pages that run the passkey script). There is no
inline script, no inline style and no `'unsafe-inline'`.

The theme is neutral. A deployment gives it its own face with an optional
`branding` block:

```hcl
branding {
  name         = "Mésocentre de Calcul"            # the header and the page titles; 60 characters at most
  logo_file    = "/etc/authn-bridge/logo.svg"      # SVG or PNG, 256 KiB at most (PNG: 2048 px at most)
  accent_color = "#0b6e4f"                         # #rrggbb: buttons, links, focus ring
  support_url  = "https://aide.example.org"        # https or mailto:, shown as "Aide / Help"
}
```

Every field is optional; without the block the pages carry the go-authn mark
and name and its cyan accent. A wrong value is refused when the configuration is
loaded (`authn-bridge check`), naming the field. Nothing is written into a page
as markup or style: the name and the link are escaped like any template value,
the logo is a file served as an image (an SVG may hold shapes, groups and
gradients and nothing else: no script, style sheet, `foreignObject`, text or
reference to another file; it is also served with a sandboxing policy), and the
colour becomes four CSS custom properties computed from its six hex digits. The
accent is adjusted where it must be so text stays at WCAG AA contrast (4.5:1):
the text on a button is white or black, whichever reads; the accent as a link or
focus ring is darkened on light pages and lightened on dark ones until it does.

The stylesheet and the icons are generated, not written by hand:
`go run ./internal/webbuild` regenerates them with the Tailwind v4 standalone CLI
(v4.3.5, `@tailwindcss/forms` bundled; its sha256 is pinned in the program) and
the icons named in `internal/app/web/icons.txt` from `lucide-static` 1.75.0 (its
sha512 pinned). Nothing is installed; a download whose digest is not the pinned
one is refused. CI runs `go run ./internal/webbuild -check` and fails if what is
committed differs. The `web` sources are `internal/app/web/input.css` and
`internal/app/web/templates/`. Every CI run also draws each page, light and
dark, in Chrome (`TestPageScreenshots`) and keeps the PNGs as the
`page-screenshots` artifact, written outside the checkout.

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

These are tested end to end, through the ACS, with crafted responses
(`internal/app/attack_test.go`): the signature-wrapping layouts XSW1 to XSW8
of Somorovsky et al. ("On Breaking SAML", 2012) and their same-ID variants, a
comment inserted into a signed value (CVE-2017-11427), a DOCTYPE (entity
expansion, external entities), and assertions signed for another SP, another
ACS, another request or another Destination. Fuzzers hold the same property
on arbitrary input: a response, the federation's metadata, an access token or
a login cookie is accepted only as exactly what was signed or sealed
(`internal/app/fuzz_test.go`). The clocks may differ by three minutes either
way; an hour is refused.

When the federation's metadata server is slow, down, or serves something that
does not verify, logins go on with the last good copy until its `validUntil`.
A refresh is never scheduled past half of what remains of that validity, and
with no valid metadata left, it is retried within a minute, backing off to an
hour.

And at configuration time: an issuer that is not https, a salt under 32 bytes,
an RSA key under 2048 bits, a code lifetime over ten minutes, a client secret
somebody can guess, a redirect over cleartext http, a restricted IdP list
together with RENATER's discovery service (which cannot be restricted).

## Verified against things this repository did not write

- The **federation and the IdP are xmlsec1** where it matters that an
  implementation nobody here wrote is read correctly: it signs the
  federation's metadata and signs and encrypts the response (AES-128-GCM,
  RSA-OAEP, Response signed -- a Shibboleth IdP v5's defaults) for a whole
  login, for every hand-built attack document (signature wrapping, comments,
  entities, another audience), and for each subject shape whose `sub` must not
  change. Everywhere else they are
  [go-authn/saml/samltest](https://pkg.go.dev/github.com/go-authn/saml/samltest),
  pure Go, itself checked against xmlsec1 in its own module, so the suite also
  runs on macOS and Windows, where xmlsec1 is not installed.
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
- **go-fileshare against the EuroHPC SSH CA profile**: go-fileshare v0.22.1
  is configured as a site trusting EFP's CA would be. The CA key comes from
  `GET /ssh/config` into `trusted_user_ca_file`, and `ssh_domains` names the
  host. A certificate from an EFP-profile client logs in only where both of
  these hold: its `ssh_domain_grants` name the host, and its
  `ssh_source_address` allows the address the connection comes from. A
  certificate granted another host is refused and logged as such. One pinned
  elsewhere is refused. On Linux, the same certificate that gets in from
  127.0.0.1 is refused from 127.0.0.2 (`interop_efp_test.go`).
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

## Without a browser: the device grant, and `authn-bridge token`

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
authn-bridge token --issuer https://login.example.org --client rclone
```

prints an access token, logging in the first time and refreshing quietly after
that -- which is exactly rclone's `bearer_token_command` for
[go-fileshare](https://github.com/go-fileshare/fileshare) over WebDAV. It is
golang.org/x/oauth2's device client, not one written here.

| | |
|---|---|
| **user codes** | eight letters from RFC 8628's alphabet (no vowels, no digits); ten wrong codes per host per ten minutes, where an IPv6 host is its /64, and a hundred for the /48 or IPv4 /24 around it (before v0.16.6, per address, so one /64 had no limit) |
| **the confirmation page** | names the application and says to refuse a code somebody else sent: RFC 8628 5.4's remote phishing, where the ATTACKER's device gets the token |
| **polling** | `slow_down` adds five seconds for good; a device code buys one set of tokens |
| **refresh tokens** | rotate (RFC 9700 4.14.2) inside a family whose end is fixed at the login; a retired one used again revokes the family and the access tokens it bought |

## Several resource servers: a token for one at a time

A client whose `audience` names several resource servers -- a
[go-fileshare/portal](https://github.com/go-fileshare/portal) in front of
several fileshare servers -- would get tokens addressed to all of them, and
any one of them could replay a token it received to the others (RFC 8707 §3).
Since v0.21.0 it can ask for a token for **one**, with RFC 8707's `resource`:

```hcl
client "portal" {
  secret_file      = "/etc/authn-bridge/portal.secret"
  redirect_uris    = ["https://files.example.org/callback"]
  audience         = ["https://fs-paris.example.org/", "https://fs-lyon.example.org/"]
  refresh_lifetime = "8h"
}
```

| | |
|---|---|
| **at the token endpoint** | `resource=https://fs-paris.example.org/` on the `authorization_code` or `refresh_token` grant: the access token's `aud` is that one alone (RFC 8707 §2.2). The refresh token keeps the whole grant, so the next refresh can ask for another server |
| **at the authorization endpoint** | `resource` may be repeated, and bounds the grant: a later token request can narrow it to one of those, never widen it. A refresh token is bound to what was consented (RFC 9700 §4.14.2), across a restart too |
| **what may be named** | an absolute URI, without a fragment (RFC 8707 §2), that the client's `audience` lists. With a scope of this provider's own (`ssh`, `nfs`, …) the token is for the provider alone, so only the issuer may be named |
| **refused** | `invalid_target`, at the authorization endpoint as a redirect, at the token endpoint as an error. A refused refresh does **not** spend the refresh token. `resource` on the device or client-credentials grants is refused rather than ignored: a client that asked for a token for one server must not be handed one for another |
| **without `resource`** | exactly as before: the grant's resources if the authorization request named some, otherwise the client's whole `audience` |

Refresh tokens still rotate for every client, confidential ones included: RFC
9700 §4.14.2 requires it only for public clients, but it costs a confidential
client nothing that does not refresh twice with one token -- and the portal
spends its refresh token in one place for exactly that reason.

## SSH certificates, for SFTP

```hcl
certificates_file = "/var/lib/authn-bridge/certificates.json"   # every certificate issued, and the revoked
ssh_ca {
  key_file = "/var/lib/authn-bridge/ssh-ca"   # authn-bridge keygen --ssh-ca
  validity = "12h"
}
client "sftp" {
  device           = true
  ssh_certificates = true
}
```

`authn-bridge ssh-cert --issuer ... --client sftp` logs in with a code and writes
`~/.ssh/id_ed25519-cert.pub`, where ssh and sftp find it. The certificate has
**exactly one principal**, the `preferred_username` -- PROTOCOL.certkeys makes
an empty list valid for ANY user, so there is never one -- no `permit-*`
extension, the person's groups in `groups@go-authn.org`, and it ends with the
IdP's session when that is sooner. go-fileshare trusts it with `oidc {
ssh_ca_file }`.

## EuroHPC SSH CA profile

A client can have its certificates issued in the profile of the [EuroHPC
Federation Platform SSH
CA](https://integration.docs.my-eurohpc.eu/aai/ssh-ca-overview/) (GÉANT /
MyAccessID): Ed25519, one hour, ONE principal that names the person across
the federation, and the hosting entity's domain in an extension. Every key
below is per client and optional; a client that sets none of them gets the
certificate above, unchanged byte for byte apart from serial, nonce,
signature and times.

```hcl
ssh_ca {
  key_file = "/var/lib/authn-bridge/ssh-ca"
  validity = "12h"                       # the most any client may ask for
}
client "efp" {
  device              = true
  ssh_certificates    = true
  ssh_principal_claim = "voperson_id"    # preferred_username (default), voperson_id, eduperson_principal_name, sub
  ssh_validity        = "1h"             # never longer than ssh_ca's, nor past the IdP's session
  ssh_extensions      = ["permit-pty"]   # none by default
  # ssh_source_address = ["192.0.2.0/24"]          # the source-address critical option
  # ssh_domain_grants  = ["login.my-hpc.eu"]       # the hosting entity's hosts: see below
}
```

| key | |
|---|---|
| `ssh_principal_claim` | the claim the one principal comes from. `voperson_id` and `eduperson_principal_name` are released by the `eduperson` scope, which the token must hold (`authn-bridge ssh-cert --scope eduperson`); a token without it, or a person whose IdP released no such attribute, gets a **403** saying which. The value goes through the same check as a username: a comma, a quote, a space or a control character is refused, since sshd would read two names. |
| `ssh_extensions` | OpenSSH's `permit-pty`, `permit-user-rc`, `permit-port-forwarding`, `permit-agent-forwarding`, `permit-X11-forwarding`, and nothing else: an unknown name stops the provider from starting. Not `no-touch-required`: it waives the user-presence test of the person's own security key, which is not the provider's to give away. |
| `ssh_source_address` | addresses or CIDR prefixes (no host bits under the mask), in the `source-address` critical option. OpenSSH's sshd enforces it, and so does go-fileshare: with `ssh_domains` as without it, since fileshare v0.22.1. |
| `ssh_validity` | shorter than `ssh_ca`'s `validity`, for this client. |
| `ssh_domain_grants` | domain patterns for GÉANT's `ssh-domain-grant@core.aai.geant.org` extension, checked at load by go-authn/sshcert's `ValidatePattern` (the specification's syntax), then lower case, at least two labels, and a wildcard only under a registrable domain (what stays fixed to its right is not a public suffix: `*.ac.uk`, `*.gouv.fr`, `*.github.io` are refused, `*.hpc.example.ac.uk` is not); encoded by go-authn/sshcert. |

**`GET /ssh/config`** publishes the CA key as EFP publishes its own,
`{"PublicKey":"ssh-ed25519 AAAA..."}`, so a site follows EFP's
[trust instructions](https://integration.docs.my-eurohpc.eu/aai/ssh-ca-trust/)
with this provider's URL in place of EFP's:

```sh
curl -s https://login.example.org/ssh/config | jq -r '.PublicKey' > /etc/ssh/bridge-ssh-ca.pub
echo "TrustedUserCAKeys /etc/ssh/bridge-ssh-ca.pub" >> /etc/ssh/sshd_config
```

and authorizes the principal as EFP's [authorization
instructions](https://integration.docs.my-eurohpc.eu/aai/ssh-ca-authz/) say:
an `AuthorizedPrincipalsCommand` that reads the domain grant and refuses a
certificate meant for another hosting entity, and the
person's principal mapped to a local account. Use go-authn/sshcert's
`sshcert-authorize`, a drop-in for GÉANT's `ssh-cert-authorize` with one
difference that matters: GÉANT's lets in a certificate that carries **no**
domain grant, so on a host that trusts this CA and EFP's, or any second CA,
the grant filters nothing; `sshcert-authorize` refuses it unless told
otherwise (`--allow-no-grant`). It is not advertised in the
discovery document: no OpenID Connect metadata names an SSH CA, and this
provider does not invent one.

What remains different from EFP:

- **The principal is `voperson_id`**, the SAML subject-id the person's own
  institution released, lower-cased (`a1b2c3@univ-example.example`) -- not a
  MyAccessID CUID (`<id>@myaccessid.org`). A site maps the one or the other;
  a person known to both has two.
- **There is a KRL.** `GET /ssh/krl`, for `RevokedKeys`, lists the
  certificates of the people disabled here, these included; EFP documents no
  revocation, so a site configured only as EFP says is not told.
- **The groups extension** (`groups@go-authn.org`) is still there when the
  token carries groups; EFP's certificates have none.
- **The domain grant** is `ssh-domain-grant@core.aai.geant.org`, as GÉANT's
  specification and EFP's authorisation page spell it, encoded by
  [go-authn/sshcert](https://github.com/go-authn/sshcert). Its patterns follow
  the specification, and this provider refuses one more thing: a wildcard over
  a public suffix (`*.ac.uk`, by the Public Suffix List), which would grant
  every institution under it.

## X.509 certificates, for NFS over TLS

NFS over TLS (RFC 9289) can name the client by its certificate. This
provider issues one to a person who logged in, for a key made on their machine:

```hcl
certificates_file = "/var/lib/authn-bridge/certificates.json"
x509_ca {
  key_file  = "/var/lib/authn-bridge/nfs-ca/ca.key"    # authn-bridge keygen --x509-ca /var/lib/authn-bridge/nfs-ca
  cert_file = "/var/lib/authn-bridge/nfs-ca/ca.crt"    # what go-fileshare trusts
  validity  = "12h"
}
client "nfs" {
  device            = true
  x509_certificates = true
}
```

`authn-bridge nfs-cert --issuer ... --client nfs` makes a P-256 key, sends a
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
  certificates and says `revoked` once they are listed. A certificate request
  held open across a disabling is answered 401, and what it had already recorded
  is revoked. The token is checked when the request starts and the body read
  after, so before v0.16.6 such a request came back with a certificate that no
  list named.

⛔ **A certificate names the machine, not the user of it.** RFC 9289: the
server 'cannot utilize the remote TLS peer identity to authenticate RPC
users'. Linux sets the client certificate per mount (`cert_serial`,
`privkey_serial`), so everybody using that mount is the person it names:
this is for a machine one person uses, and `authn-bridge nfs-cert` says so.

On the Linux client (measured by go-fileshare against Linux 6.17 and
ktls-utils 0.9): tlshd verifies the SERVER's certificate against the system
trust store only, ignoring `x509.truststore`; certificate files named in
`/etc/tlshd.conf` must be root's, the key mode 600 -- either mistake shows
only as `gnutls: Error in the certificate (-43)`; and MOUNT's MNT goes in the
clear, so a refused person sees "access denied" at the first access, not at
mount. `authn-bridge nfs-cert` prints all three.

Every certificate, SSH and X.509, is recorded in `certificates_file` before it
is handed out: one that cannot be recorded is not issued, since it could
never be revoked. The file is required with `ssh_ca` or `x509_ca`.

## Kerberos tickets, for SMB without a password

A person who logs in with a passkey has no password, so a KDC cannot give them
a ticket by the usual means. With a `kerberos` block, a token with the
`kerberos` scope (only for a client with `kerberos_tickets = true`) buys a
TGT: `POST /kerberos/tgt` with the bearer token asks the realm's KDC
(go-authn/kdc `Server.MintHandler`) over mutually authenticated TLS and returns
the answer, a KRB-CRED (RFC 4120 5.8), for the person's machine to load into its
credential cache (go-authn/kinit does it on Windows).

A token is held to the passkey it was bought with: removing that passkey ends
what it bought, even if the account keeps other keys. A ticket never outlives
the login (`session_end`); refresh families are a separate matter, fixed at the
login and bounded as described under refresh tokens.

```hcl
kerberos {
  kdc_url   = "https://kdc.internal.example.org:8443/mint"  # https only
  ca_file   = "/etc/authn-bridge/kdc-ca.pem"                # signed the KDC's certificate
  cert_file = "/etc/authn-bridge/bridge-client.pem"         # URI name = what the KDC lists
  key_file  = "/etc/authn-bridge/bridge-client.key"
  validity  = "10h"                                         # at most ten hours
}
client "kinit" {
  device           = true
  kerberos_tickets = true
}
```

`authn-bridge check` reports the block, like the `local` and federation ones:
`kerberos      https://kdc.internal.example.org:8443/mint, client certificate
https://login.example.org until 2029-02-12, validity 10h` (on one line; the
date is UTC). Loading the configuration, so `check` and the server, refuses, naming
the field, what could not work at the first login: a client certificate that
has expired (as kdcd's `check` does for its mint certificate) or is not valid
yet, a `key_file` that does not belong to `cert_file`, a `ca_file` that is
missing or holds no certificate, a `kdc_url` that is not https, a `validity`
out of range. A configuration without the block prints nothing.

The principal is the person's scoped name, never a bare one: a federated
person's `preferred_username` (their eppn, `user@domain`), and for a local
account, whose login never holds an `@`, the login at the `local` block's scope
(`alice@mesocentre.example`). The KDC's directory must hold that exact name. A machine with a registered key (`jwks`, see "Machines with a key and no
secret") and `kerberos_tickets = true` may ask `client_credentials` for the
`kerberos` scope by name (never part of its default scopes) and buys a TGT for
itself: `<client id>@<issuer host>`, derived from the client the token was issued
to; a client ID holding `@` or `/` gets none. The ticket never outlives the identity
provider's session, nor `validity`, and nothing renews it: a longer day needs a
new login. A person disabled while the KDC was answering gets nothing.

## No passwords: application passwords are gone (v0.30.0)

This provider issues no password of any kind. Application passwords, which let
a person who logged in through their institution set a generated password for
SMB (an NT hash) and S3, were removed in v0.30.0, completely: there is no
issuance path, no configuration option and no way to turn them back on.

- SMB: use a Kerberos ticket (the previous section). The server needs no
  secret of the person's, and with `ntlm = false` in go-fileshare none can be
  presented.
- S3: temporary credentials from an STS (go-authn/awscred), not a password.

What changed for a deployment that used them:

- A configuration with an `app_passwords` block, or `app_passwords = true` in a
  client, is refused at start (`Unsupported block type`, `Unsupported
  argument`): delete them.
- A client asking for the `app_password` scope is refused, `invalid_scope`, at
  `/authorize` and `/device_authorization` (a client credentials grant never
  had it). `POST` and `DELETE /app-password` answer 404 and `authn-bridge
  app-password` is not a command. The account page no longer lists or revokes
  one, and the admin API's `Client` and `Revoked` messages lost their
  `app_passwords` fields (the numbers are reserved).
- bridge no longer opens, reads, writes or deletes the table. A password
  already stored is not touched by bridge, which can no longer revoke it
  (disabling a person or an institution does not reach it): it stops working
  where it is checked, so remove the `users "sql"` block from go-fileshare's
  configuration (with `ntlm = false` it could not answer anything anyway: an NT
  hash is only good for NTLM) and drop the `app_passwords` table and its DSN
  file.

## WireGuard keys, for a VPN such as claimward

WireGuard authenticates a peer by its public key and by nothing else: the
protocol has no certificates, no expiry and no revocation. bridge keeps the
answer to *whose is this key, and may it still connect?*:
- a person's VPN client registers the public key of its device, for a lease;
- the private key never leaves the device;
- a gateway reads the live keys back as a list signed for it alone.

The format both sides share, and the gateway's side, are in
[go-authn/wireguard](https://github.com/go-authn/wireguard).

```hcl
certificates_file = "/var/lib/authn-bridge/certs.json"   # keys are recorded beside the certificates

wireguard {
  lifetime = "24h"              # a key is listed this long; registering it again renews it
  max_keys = 10                 # devices per person
}

client "claimward" {            # the VPN client people log in with
  device           = true
  wireguard_keys   = true       # its tokens, with the wireguard scope, may register a key
  refresh_lifetime = "720h"
}

client "claimward-gw" {         # the gateway's own client
  secret_file     = "/etc/authn-bridge/claimward-gw.secret"
  wireguard_peers = ["claimward"]   # it reads the keys registered through these clients
  ssf_receiver    = true            # optional: told at once when somebody is disabled
}
```

| | |
|---|---|
| `POST /wireguard/key` | `{"public_key": "...", "device": "laptop"}` with a token of the `wireguard` scope. Answers the lease's end. |
| `DELETE /wireguard/key` | `{"public_key": "..."}`: the owner takes a key back |
| `GET /wireguard/peers` | for the gateway's own `client_credentials` token, scope `wireguard_peers`: a JWT of type `wireguard-peers+jwt`, signed with the access-token key (in the JWKS), addressed to that gateway, valid five minutes |

**What it refuses:**
- **A key someone else holds** (409). A public key is public, so whoever reads
  one off a configuration must not be able to take it over.
- **A key that was taken back** (409). It may have been taken back because its
  device was lost.
- **One key too many** (409).
- **A point of low order**, a key in any but its canonical spelling, or a device
  name that does not print (400).
- **A token for the list from a person**, or a gateway's token registering a key
  (403).

**Taking keys back.** Disabling a person or an institution takes their keys
back with their certificates, and the list's `version` goes up. go-authn/wireguard's
`Source` refuses a list older than one it has seen, so the list from before
the disabling, still signed and still in its five minutes, cannot be
replayed. A gateway that is also an SSF receiver is told at once and fetches
the list then; otherwise its next fetch does it. A registration held open
across a disabling is answered 401, and its key taken back.

**`sub` in the list** is the person as the *registering* client sees them,
public or pairwise. It is the same value the gateway finds in that person's
tokens for that client.

**One login, two tokens.** A token with the `wireguard` scope is addressed to
bridge alone, like every scope of bridge's own: it is never one a VPN server
can be shown. A client therefore logs in once for `openid wireguard`, registers
its key with that token, and refreshes asking for `scope=openid`. RFC 6749 §6
lets a refresh ask for less than was granted, which bridge honours since
v0.17.0. The narrower token is addressed to the client's own audience
(`claimward`, unless `audience` says otherwise), and the refresh token keeps
everything it had.

## OpenPubkey and opkssh

[OpenPubkey](https://github.com/openpubkey/openpubkey) commits the user's key in
the ID token's nonce, and opkssh turns that into SSH logins with no CA at all.
This provider does what that needs: the nonce comes back verbatim in the code
flow and in the device flow (where the openpubkey client sends it on the
device authorization request), RS256 so that GQ signatures work, and

```hcl
retired_signing_key_files = ["/var/lib/authn-bridge/oidc-2026-03.key"]
```

because a PK Token outlives the ID token inside it and the openpubkey verifier
only fetches the keys published now: a retired key stays in the JWKS,
verifying and never signing, for at least the longest PK Token lifetime any
verifier allows (opkssh: a day by default, up to a week). Give opkssh a client
of its own -- `http://localhost:3000/login-callback` and its two siblings as
redirect URIs -- because its ID token travels to every server it logs into.
That client needs `id_token_claims = true`: opkssh matches people on the PK
Token's claims (`email`, `preferred_username`), and since v0.18.0 an ID token
carries none unless its client asks.

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
  cache_dir = "/var/lib/authn-bridge/acme"  # account key and certificates
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
  eab_hmac_key_file = "/etc/authn-bridge/harica-eab.key"   # the HMAC key, base64url
  email             = "noc@example.org"             # HARICA requires one
  cache_dir         = "/var/lib/authn-bridge/acme"
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
above are checked too, not only the last one. A `/var/lib/authn-bridge` that a
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
  access_token_groups = false  # motley-cue reads the groups at /userinfo
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
  access_token_key_file = "/var/lib/authn-bridge/access-token.key"   # authn-bridge keygen --access-token-key
  ```

  and the access token leaves out `auth_time` and `acr`, which nothing reads
  from it (they are in the ID token). Measured by `TestES256AccessTokens` for a
  long eppn and three AARC entitlements, against the `shibmd:Scope` lengths of
  RENATER's metadata (743 scopes):

  | scope length | | characters |
  |---|---|---|
  | 13 | median | 885 |
  | 22 | 95th percentile | 945 |
  | 29 | 99th percentile | 992 |
  | 44 | the longest | **1092: over** |

  Before v0.22.0 the same token was 1014 / 1074 / 1121 / 1221: over from the
  95th percentile on. What still does not fit is the longest scopes and, above
  all, many groups: every entitlement adds its whole URN, and nothing bounds how
  many an IdP sends. **`access_token_groups = false`** on the ssh-oidc client
  (v0.23.0) leaves the groups out of its access tokens: motley-cue reads them at
  `/userinfo` anyway, which still serves all of them. Measured with fifty groups
  and the longest scope: 732 characters. The client cannot also have
  `ssh_certificates` or `x509_certificates`: certificates take the groups from
  the access token, so configuration refuses the pair rather than issue
  certificates that silently carry none. Past 1023, mccli asks motley-cue for a one-time password
  instead, which motley-cue allows by default; a token pasted into plain `ssh`
  has to fit.
  go-authn/oidc (go-fileshare), coreos/go-oidc and flaat (motley-cue) all
  verify ES256.
- **`/userinfo` is how motley-cue checks every token.** Give the provider a
  `state` block (below) so that a restart does not refuse every token handed
  out before it.

## Rotating the token signing key

Every relying party verifies tokens with the keys published at `/jwks`. A key
changed in place invalidates every token they hold, and one used before they
have fetched it is refused. `retired_signing_key_files` makes both safe: a key
listed there is **published and never signs**. Rotating takes two restarts
(the provider does not reload its configuration, and a SIGHUP is ignored; see
[docs/install.md](docs/install.md)):

1. **Make the next key**, beside the current one:

   ```sh
   authn-bridge keygen --key /var/lib/authn-bridge/oidc-2026-10.key   # refuses to overwrite a file
   ```

2. **Publish it before it signs.** Add it to `retired_signing_key_files`, leave
   `signing_key_file` alone, run `authn-bridge check`, and restart:

   ```hcl
   signing_key_file          = "/var/lib/authn-bridge/oidc-2026-04.key"   # still signing
   retired_signing_key_files = ["/var/lib/authn-bridge/oidc-2026-10.key"] # published only
   ```

   `/jwks` now lists **both** `kid`s, and new tokens still carry the old one.
   Wait at least as long as the longest a relying party caches the key set.
   One that fetches again on an unknown `kid` (go-authn/oidc does, at most
   once per its `MinRefresh`) needs no wait. One that caches for a fixed time needs that time.

3. **Swap.** Make the new key `signing_key_file` and move the old one to
   `retired_signing_key_files`. Then `authn-bridge check` and restart:

   ```hcl
   signing_key_file          = "/var/lib/authn-bridge/oidc-2026-10.key"
   retired_signing_key_files = ["/var/lib/authn-bridge/oidc-2026-04.key"]
   ```

   `/jwks` still lists both `kid`s, and new tokens carry the new one. Tokens
   signed with the old key keep verifying.

4. **Retire the old key** once no token it signed can still be presented:
   after at least the longest of `token_lifetime` (1 h by default) and
   `id_token_lifetime` (5 min), plus the relying parties' clock skew and
   their key-set cache. For opkssh, wait the PK Token lifetime instead (a day
   by default, up to a week; see [OpenPubkey and opkssh](#openpubkey-and-opkssh)).
   Then remove it from the list and restart. `/jwks` then lists one `kid`.

Check at each step:

```sh
curl -s https://login.example.org/jwks          # the kids published
# the kid of a fresh token: the first segment of any access or ID token, base64url-decoded
```

An `access_token_key_file` (ES256) rotates the same way. Write the next one with
`authn-bridge keygen --access-token-key`, and a retired one goes in
`retired_signing_key_files` like any other. Without a `state` block, each
restart logs everybody out: refresh tokens and `/userinfo` live in memory. The
access tokens already issued still verify at the resource servers.

Verified end to end with llmflow-gateway as the relying party, in
[go-llmflow/bench](https://github.com/go-llmflow/bench)
(`e2e/oidc`, `TestBridge/c/key-rotation`):
- after step 2, `/jwks` lists both kids while tokens still carry the old one;
- after step 3, a token signed before the swap and one signed after are both
  accepted, with a single key-set fetch;
- an SSO login right after the swap works.

## State: what a restart must not forget

```hcl
state {
  driver   = "postgres"                  # or sqlite, mysql
  dsn_file = "/etc/authn-bridge/state.dsn"
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
  the provider is **not ready** (`/readyz`, the gRPC health). A write the
  database is merely away from does not hold the deletes back, and a row it
  refuses **for good** (PostgreSQL SQLSTATE class 22 or 23, MySQL data too
  long / out of range / bad value / key errors, SQLite constraint errors) is
  logged once, counted in `bridge_state_rows_rejected_total{kind}`, and given
  up: it works until a restart but is not persisted, and the provider stays
  ready. Any other error is retried, within a bound: a row that keeps failing
  (five flushes over at least thirty seconds) while the database takes other
  writes or deletes is given up the same way. A database that is away takes
  nothing, so an outage gives no row up.
- Tested across restarts on SQLite and PostgreSQL: tokens still work, revoked
  ones stay revoked, a retired refresh token used again still revokes its
  family; with no `state` block the same restart forgets, which is the control.

## Machines with a key and no secret: `private_key_jwt`

An unattended machine -- a Windows service nobody logs into -- should hold a
key, not a password. A confidential client registers PUBLIC keys and proves
itself by signing a short JWT with the private one (RFC 7523 2.2, OpenID
Connect Core 9), on the token endpoint, for `client_credentials` (and for
`authorization_code`, for a client that has a redirect URI):

```hcl
client "winpc-17" {
  jwks_file = "/etc/authn-bridge/winpc-17.jwks.json"   # or jwks = <<EOT { "keys": [ … ] } EOT
  audience  = ["https://s3.example.org"]               # what its token is addressed to
}
```

- `jwks` / `jwks_file` is a JWK Set (RFC 7517) of public keys: RS256 (2048 bits
  at least), ES256 (P-256) or EdDSA. A private key, a symmetric key, another
  curve, a duplicate `kid` or a set of more than 16 keys is refused at load.
  Several keys are how a key is rotated: add the new one, reload, retire the
  old one.
- The client has **no `secret_file`**: both together are refused, and a request
  that carries an assertion and a secret is refused as well. A key client
  cannot be authenticated with an empty secret.
- The assertion (`client_assertion_type =
  urn:ietf:params:oauth:client-assertion-type:jwt-bearer`) has `iss` = `sub` =
  the client ID, `aud` = the token endpoint (`<issuer>/token`) or the issuer,
  `exp` at most five minutes ahead (a minute of clock skew is allowed, and
  `exp - iat` is bounded too), and a `jti`. A `jti` is accepted once, until the
  assertion would have expired; the cache holds 20000 and a full one refuses
  rather than forgets. `alg: none`, HMAC and every algorithm other than the
  three above are refused, and a key of another kind than the header says does
  not verify.
- The `client_credentials` token of such a client has `sub` and `azp` = the
  client ID, `aud` = the client's `audience`, scope `machine`, no refresh token
  and no ID token. Discovery lists `private_key_jwt` and
  `token_endpoint_auth_signing_alg_values_supported`.

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
  secret_file  = "/etc/authn-bridge/fileshare-ssf.secret"
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
  listen = "unix:///run/authn-bridge/admin.sock"      # mode 0600
  # or, over the network, mutual TLS and nothing less (loopback included):
  # listen         = "10.0.0.5:9443"
  # tls_cert_file  = "/etc/authn-bridge/admin.crt"
  # tls_key_file   = "/etc/authn-bridge/admin.key"
  # client_ca_file = "/etc/authn-bridge/operators-ca.crt"
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
| `RevokePerson` | end somebody's refresh token families, the access tokens they bought and their device grants in progress, and revoke everything the certificate store holds for them: SSH and X.509 certificates (into the next KRL and CRL) and WireGuard keys |
| `DisablePerson`, `EnablePerson` | refuse somebody here -- at login and at every token, whatever their institution says -- and revoke what they hold; optionally until a given time |
| `DisableIdP`, `EnableIdP` | the same for everybody one institution vouches for: when its IdP is compromised, say. A metadata refresh does not lift it |
| `ListDisabled` | who is disabled, why, by whom, until when |

Removing an IdP from `saml { idps }` ends what it vouched for, the way
`DisableIdP` does: a new login is refused, and so is every grant of someone who
came through it -- a refresh token (even across a restart), an application
password, an SSH certificate request -- at the next use, with `institution not
configured`. Put the IdP back and they work again; nothing needs revoking.

A person is disabled as who they are: usernames compare without case (eppn,
uid, mail and subject-id all compare so; ASCII letters only, with go-authn/oidc's
`ASCIILower`, so a Kelvin sign U+212A is not a "k" and `kate` and `Kate` with one
are two people, two disable entries and two certificate principals), the entry records the stable
identity of everybody known under that name, so another spelling from their
IdP does not let them back in, and a person whose IdP releases no username
is disabled by the `sub` a relying party knows them by -- public or pairwise,
matched at every login, whether or not anything of theirs is still live here.
Their SSF events reach every spelling of their name the provider handed out.

Disabling is kept in a file, and refused without one -- somebody disabled
until the next restart would be let back in by the next deployment:

```hcl
disabled_file = "/var/lib/authn-bridge/disabled.json"   # written whole, mode 0600
```

A file that cannot be read stops the provider from starting, for the same
reason.

⛔ A person's SMB session is closed by go-fileshare, not here: the SSF event
reaches it (`ssf_receiver`), or it is asked
(`fileshare.admin.v1.AdminService/ReloadDirectory`, since fileshare v0.10.0).
Call it after `DisablePerson` for the effect to be immediate, and note that a
Kerberos ticket already issued is good until it expires (at most `validity`,
ten hours). Everything that comes back to this provider is refused at once.

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
a refresh, `/userinfo`, an SSH certificate or a Kerberos ticket asked
with that token -- is refused at once; an SSH certificate already issued lasts
its validity, which is why that is short.

**Health and metrics** are
[go-net-health/endpoint](https://github.com/go-net-health/endpoint)'s, as in
go-fileshare: `/healthz` is up while the process answers; `/readyz` is ready
while the federation's metadata is loaded and still valid (a provider past
its `validUntil` knows no IdP); `/metrics` is Prometheus text 0.0.4 with
`bridge_*` families -- logins by outcome, tokens by grant, SSH certificates,
metadata validity and refreshes, what is held in
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

## Upgrading to v0.20.0

**The command is now `authn-bridge`.** It was `bridge`, which is also
iproute2's `/sbin/bridge`, installed on practically every Linux distribution:
whichever came first on `PATH` won. The repository and the module path stay
`github.com/go-authn/bridge`; only the command and the binary are renamed.

- `go install github.com/go-authn/bridge/cmd/authn-bridge@latest`. The old
  path, `go install github.com/go-authn/bridge@...`, no longer builds a
  command from v0.20.0 on: the program moved to `internal/app`, with
  `cmd/authn-bridge` calling it.
- The release assets are `authn-bridge-<os>-<arch>`, no longer
  `bridge-<os>-<arch>`.
- Scripts, cron jobs, systemd units and `bearer_token_command` lines that run
  `bridge ...` must run `authn-bridge ...`. The subcommands, flags and
  configuration are unchanged.
- The start-up log line and error prefix say `authn-bridge`; a log alert that
  matched `bridge v0.` matches `authn-bridge v0.` now. Metric names (`bridge_*`),
  cookie names and the database table `bridge_state` are unchanged.
- The user-side cache (`~/.config/go-authn-bridge`) is unchanged, so
  `authn-bridge token` and `ssh-cert` reuse the logins `bridge` cached.

[docs/install.md](docs/install.md) installs it as a hardened systemd service
(`packaging/systemd/authn-bridge.service`).

## Upgrading to v0.18.0

Two changes a deployment must look at.

**The ID token carries nothing about the person.** `email`, `name`,
`preferred_username` and the eduperson claims are at `/userinfo`, as OIDC Core
§5.4 says when an access token is issued; the OpenID Foundation's suite warned
about them. An application that read them from the ID token calls `/userinfo`
instead, or its client sets `id_token_claims = true` (an opkssh client must).

**Some people get a new `sub`.** go-authn/saml v0.3.0 holds an unscoped
identifier to the IdP that signed it, and that changes two shapes of the
identifier `sub` is derived from:

| the IdP releases | `sub` before (an HMAC of) | from v0.18.0 |
|---|---|---|
| an opaque string eduPersonTargetedID `v` | `idp!v` | `idp!idp!sp!v` |
| an ePTID or persistent NameID with no NameQualifier | `idp!!spq!v` | `idp!idp!spq!v` |

subject-id, pairwise-id, eppn and correctly qualified identifiers are
unchanged. A person in the two rows above is **a new person** to every relying
party: their refresh grants, WireGuard keys and
disable-by-sub entries no longer match. The change cannot be undone after the
fact, since two old identifiers can map to one new one. Before upgrading, find
the IdPs that release only those shapes (a log line `login: ... via <idp>` and
the attribute the IdP sends) and tell their users that their accounts at the
relying parties start afresh. `TestASubjectKeepsItsShape` pins the new shapes,
so the next change will show up as a failing test, not as renamed people.

## What it is not, yet

- **One process.** With a `state` block, refresh tokens and the access tokens
  honoured at `/userinfo` survive a restart; logins in progress, codes and
  device grants (minutes) do not. It is written through and read at start, so
  two instances on one database would each miss what the other wrote since:
  one instance still.
- No dynamic registration, no front- or back-channel logout.

## Release binaries

Each release carries `authn-bridge` for linux, darwin and windows on amd64 and arm64
(pure Go, `CGO_ENABLED=0`), a `SHA256SUMS` manifest, and a build provenance
attestation per binary, made by this repository's release workflow at the
tag. Check a download before running it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify authn-bridge-linux-amd64 --repo go-authn/bridge
```

`authn-bridge --version` prints the tag it was built from.
[docs/install.md](docs/install.md) takes a release binary to a running
systemd service, upgrades it and rolls it back.

## Licence

BSD-3-Clause.
