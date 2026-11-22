# Changelog

Versions follow [semantic versioning](https://semver.org). Releases before
v0.23.6 are described in their [GitHub releases](https://github.com/go-authn/bridge/releases).

## v0.34.0

- `authn-bridge check` prints the kerberos block as the issue (#117) asked:
  `kerberos      <kdc_url>, client certificate <name> until <date>, validity <d>`
  (supersedes the v0.33.1 line).
- The `kerberos` block now refuses at load, naming the field: an expired or
  not-yet-valid client certificate (the one thing with a lifetime; kdcd's
  `check` refuses its mint certificate the same way), and errors for a
  `ca_file` that is missing or not a certificate and for a key that does not
  belong to the certificate. A deployment whose client certificate already
  expired no longer starts: renew it.

## v0.33.1

- `authn-bridge check` now reports the `kerberos` block (#117): the KDC URL,
  the TGT validity and how many clients have `kerberos_tickets`, on a line of
  its own like the `local` and federation blocks.

## v0.33.0

- The `mail` block's SMTP password is now a secretsource reference:
  `password_from = "systemd-creds:smtp"` (or `file:PATH`, `keychain:...`, any
  scheme of go-authn/secretsource v0.9.0 (`file:` refuses symlinks and files owned by another uid); at most 4096 bytes). `password_file`
  stays as a **deprecated** alias of `password_from = "file:PATH"`; setting
  both is a configuration error. The file rules of `password_file` (owner,
  `0600`) are now secretsource's `file:` rules. AUTH is still sent only after
  TLS. Docs show `LoadCredentialEncrypted=` with `--with-key=host+tpm2` and the
  re-seal recovery path.

## v0.32.0

- New `mail` block (#122): an out-of-band plain-text e-mail to the account's
  own address (from the local accounts file, never from the request) when a
  passkey removal is requested or cancelled, so a thief holding one key cannot
  silently cancel the owner's removal with it. TLS only (implicit, or required
  STARTTLS), certificate verified; username and `password_file` are mandatory
  (a file owned by the service user, no group/other bits, one open); AUTH
  (PLAIN, else LOGIN) only after TLS, never in clear, not even to 127.0.0.1.
  No link in the text; CR/LF in headers refused (fuzzed). One mail per account
  per `window` (default 10m), events collapsed into a digest.
- Failure rules: a removal request whose notice cannot be sent **stays
  pending** (5 tries, then a loud `GAVE UP` log; a restart resumes it); a
  cancellation **applies even if its mail fails**, and the failure is logged
  and shown on the account page. An account with no address still gets its
  removal; the log and the page say nobody was told. Without a `mail` block,
  nothing changes. New record field `notice_pending`.

## v0.31.3

Dependencies (security fixes the 2026-11-21 audit led to):

- go-authn/directory v0.26.0 (Set names now compare by their LDAP equality
  key, case-insensitively, across sources; ldap v0.15.0 arrives as an indirect
  requirement), oidc v0.8.0, webauthn v0.2.0, saml v0.7.2,
  revocation v0.7.1, servercert v0.7.1 and wireguard v0.2.0: the audit's
  second round. oidc now honours a JWK's `alg` and binds ES256/384/512 to
  their curves; bridge's own uses (the verifier only) and the full suite are
  unchanged and pass. ldap, rp, scim, fido, krb5, kdc, cms and awscred are not
  required by bridge's go.mod, so none is bumped.
- go-authn/directory v0.17.0 to v0.24.0, go-authn/saml v0.7.0 to v0.7.1 and
  go-authn/webauthn v0.1.0 to v0.1.1: the audit's fixes in those modules.
  No change to bridge's configuration or behaviour is needed; the full suite
  passes unchanged.
- The other modules of the release train (ldap, krb5, cms, rp, totp,
  secretsource, scim, awscred, authnd) are not required by bridge's go.mod,
  so none is bumped. Bridge does not read secrets through secretsource, so
  its v0.6.0 refusal of an empty `file:` secret does not apply here.

Security (audit follow-up, [#125](https://github.com/go-authn/bridge/issues/125)):

- **MEDIUM: a token of a removed passkey still bought a Kerberos ticket (and
  kept an SSH certificate's person live).** The recheck built the person
  without the credential, so it only asked that the account kept some
  passkey. An access token now records the passkey it was bought with (state
  field `credential`, optional: a token stored before holds to the account
  only) and is held to it, before the KDC is asked, after it, and when an SSH
  certificate is withdrawn, as a refresh grant already was.
- **LOW: the Kerberos ticket lifetime used the host clock** instead of the
  provider's (`s.now`); a provider clock behind refused a valid login.
- **LOW: a display name could hold direction controls and invisible
  characters** (U+202E, U+2066, U+200E, U+200B, U+FEFF, U+2028, U+00AD...).
  They are refused; ZWJ and ZWNJ stay.
- **LOW: finishing an enrolment could exceed ten passkeys** when a key was
  added between its begin and its finish. The finish takes the account lock
  and rechecks the cap (409) before the invitation is burnt.
- Documentation: the Kerberos comment no longer reads as if the endpoint
  bounded refresh families.
- Examined and not defects: refresh lifetime (#2), certificate rows without
  an IdP (#5), the anonymous step-up begin (#7), HTML escaping of the
  authorize page (#8).

Security (found by the 2026-11-21 audit):

- **MEDIUM: a federated person and a local account could be one principal.**
  With a `local { scope }` equal to a federated IdP's scope (shibmd:Scope in
  the metadata), local `alice` and federated `alice@<scope>` were the same
  Kerberos principal, the same `eduperson_principal_name` and so the same SSH
  principal. A federated login whose username or eppn is in the local scope is
  now refused (`access_denied`) when it is minted, because metadata scopes
  change at every refresh; a federated token that exists anyway gets no
  Kerberos ticket; and `authn-bridge check` fails when a usable IdP's scope is
  the local scope. **Upgrade:** if `check` now reports the clash, give the
  `local` block another scope (local accounts' principals and eppn change
  with it).
Tests (no change to the program):

- The SAML side of the test suite is go-authn/saml/samltest by default
  (#81), so the suite runs where xmlsec1 is not installed: on a machine
  without it, 297 tests pass and 17 skip, where 88 passed and 226 skipped.
  xmlsec1 stays the independent judge for the attack documents and for a
  second run of the whole login (`TestLoginEndToEnd/xmlsec1`).
- With go-authn/saml v0.7.0, samltest also writes a non-Success status, a
  NameID subject, an ePTID given as a NameID and an AuthnInstant of its own
  (go-authn/saml#28), so those tests no longer fall back to xmlsec1: 301 pass
  and 13 skip without it. `TestASubjectKeepsItsShape` now runs each shape
  under both producers. The declined-authentication case of the account page
  sent `AuthnFailed` as bare text inside `samlp:Status`, with no StatusCode
  element; it now sends `Responder` / `AuthnFailed`, so the refusal it checks
  is the IdP's answer, not a malformed document. The parser the program
  links is unchanged by the go-authn/saml bump (v0.6.1 added fuzz targets
  and tests, v0.7.0 changed only samltest).

Removed (breaking, v0.30.0):

- **Application passwords, completely.** This provider issues no password of
  any kind. Gone: the `app_passwords` block and the client's
  `app_passwords = true` (a configuration that has either is refused at start),
  the `app_password` scope (`invalid_scope` at `/authorize` and
  `/device_authorization`), `/app-password` (404), the `authn-bridge
  app-password` command, the account page's row and revocation, the
  `bridge_app_passwords_total` metric, and the `app_passwords` fields of the
  admin API's `Client` and `Revoked` (field numbers reserved). SMB uses a
  Kerberos ticket (`kerberos` block), S3 temporary credentials. Passwords
  already stored are no longer reached by bridge: remove go-fileshare's
  `users "sql"` block and drop the table. See "No passwords" in the README.

Fixed:

- **An `accounts_file` that `--config` reads as configuration is refused**
  (#99). `docs/install.md` put it in `/etc/authn-bridge`, where `--config DIR`
  reads every `*.hcl`: `check` passed while it was empty, and the first account
  written to it stopped the next start with "Unsupported block type". `check`,
  startup and `local-account` now refuse that place, and `invite` no longer
  creates the file there. A configuration already in that state says which file
  holds account blocks and where to move it. The docs use
  `/etc/authn-bridge-local/accounts.hcl`.

Added:

- **`private_key_jwt` client authentication** (RFC 7523 2.2, OIDC Core 9) for
  confidential clients: `jwks` / `jwks_file` in a client block registers
  RS256, ES256 or EdDSA public keys instead of a `secret_file`, for
  `client_credentials` and `authorization_code`. One-use `jti` (bounded
  cache), `exp` within five minutes, `aud` = token endpoint or issuer. A
  machine client's token has `sub` and `azp` = the client ID and the client's
  `audience`; scope `machine`. See "Machines with a key and no secret".
- **Kerberos TGTs after a passkey login.** A `kerberos` block and a
  `kerberos_tickets` client flag: a token with the `kerberos` scope buys, at
  `POST /kerberos/tgt`, a KRB-CRED the realm's KDC minted over mutual TLS, for
  the token's scoped username, no longer than the session or ten hours. For SMB
  without a password on non-domain Windows (go-authn/kinit). A machine with a
  registered key and `kerberos_tickets` may ask `client_credentials` for the
  `kerberos` scope by name and gets a TGT for `<client>@<issuer host>`.
- **Guardrails on removing a passkey from `/account`.** Removing a key other
  than the one the page was opened with is deferred for `local {
  passkey_removal_delay }` (default `24h`, `"0"` = immediate as before): the key
  keeps working, any of the person's keys can cancel (`/account/removal/cancel`,
  a banner on every visit), and it is removed at its time. The session's own key
  still goes at once; the last key, and any removal that would leave only keys
  on their way out, is refused. Key added / removal requested / cancelled / done
  go to the audit log and, with `notify { url, secret_file, include_address }`,
  to an HMAC-SHA-256 signed webhook (`X-Bridge-Signature: sha256=<hex>`; client
  address family only unless `include_address`); the bridge has no mail facility,
  so the webhook feeds whatever sends the mail. Strings in all seven languages.
- **A home page at `/`** (it answered 404): what the service is, a "My account"
  button, what a passkey is, the federation people can sign in through (RENATER
  and eduGAIN by name, else the metadata host) and, from an optional `home {
  title, link "Name" { url } }` block, the deployment's own links (https only,
  refused at load otherwise, escaped on the page). Same design, seven languages,
  language combo and theme; same CSP. It shows nothing about clients, users or
  keys. Every other unknown path is still 404.
- **Seven languages and a theme switcher.** Pages now speak `fr`, `en`, `de`,
  `es`, `ja`, `ko` and `zh-cn` (the languages of the docs sites), chosen by the
  `lang` cookie, then `Accept-Language` with q-values (`zh-CN`/`zh-Hans` give
  `zh-cn`), then French; `<html lang>` is exact (`zh-CN`). The FR | EN link pair
  is replaced by a combo of language names in themselves, a form (`GET /lang`)
  that works without script, with a tiny static `/ui.js` that submits on change.
  A light / dark / system theme (`GET /theme`, `theme` cookie) is drawn by the
  server on `<html>`, with no flash and no script needed. The passkey script's
  words come from the page (`#msgs`), not from the script. German, Spanish,
  Japanese, Korean and Chinese were written without native review; corrections
  welcome. CSP gains `script-src 'self'` on every page (it already had it on the
  passkey pages); nothing inline. CJK uses system fonts.
- **Designed pages, and a `branding` block.** Every page is now a template file
  drawn by one Tailwind CSS v4 stylesheet (compiled at build time by
  `go run ./internal/webbuild` with the standalone CLI, pinned by version and
  sha256) and Lucide icons (lucide-static 1.75.0, ISC), light and dark, with a
  help panel on the passkey pages and a signed-out state. `branding { name,
  logo_file, accent_color, support_url }` gives a deployment its own name, logo
  (SVG or PNG, 256 KiB at most), accent (a validated `#rrggbb`, adjusted for
  WCAG AA) and support link. The assets are served from the provider's origin
  as `/assets/<name>.<hash>.<ext>`.
- **One language per page**, French or English: the `lang` cookie, else
  `Accept-Language`, else French, with an FR | EN switch (`/lang/<code>`, a plain
  link; `SameSite=Lax` cookie) and one catalogue of strings with a test for
  missing translations. This replaces the "fr / en" doubling of every label; the
  account page's "changed by X" sentence, which interpolated an
  already-bilingual value into each language, is now one sentence per language.
- **CSP:** `style-src 'unsafe-inline'` is replaced by `style-src 'self'` and
  `img-src 'self'` on every page; the pages have no inline style.
- CI: a `web` job regenerates the stylesheet and icons and fails on a
  difference; the Chrome lane keeps a screenshot of every page, light and dark,
  as an artifact.
- **"Mon compte / My account" at `/account`**, for every signed-in person,
  federated or local, behind a fresh authentication at most five minutes old
  (a passkey assertion for a local account; a SAML login with `ForceAuthn`,
  whose `AuthnInstant` is checked, for a federated person) held in a `__Host-`
  `SameSite=Strict` cookie. Sections: identity (read-only; a local account may
  change its display name; mail and groups never), passkeys for local accounts
  (add, list, remove, never the last; a removed key refuses the grants it
  bought), applications and sessions (the refresh-token families, revoke one or
  all), and technical access where configured (application password, SSH and
  X.509 certificates, WireGuard keys). CSRF, same-origin, per-host throttling
  and an audit line on every change. `/local/account` redirects. A real-Chrome
  test lane (`BRIDGE_REQUIRE_BROWSER=1` in CI) drives the provider's real pages
  with a virtual authenticator. `chromedp` is a test-only dependency.

- **Local accounts, passkey-only**: a `local { accounts_file, scope }` block
  (with a `state` block, which it requires), a login page served by the
  provider, and `authn-bridge local-account invite|revoke-invite|passkeys|
  remove-passkey|remove`. **There is no password**: no password field, no route
  that reads one, no hash, no setting that brings them back, and no
  `passwd` command. A person signs in with a passkey (WebAuthn, discoverable
  credentials, user verification required) and is enrolled by a one-time,
  admin-issued invitation, `<issuer>/local/enroll#<token>`: the token is in the
  fragment (in no log), stored only as a hash, single-use, expiring (24 hours,
  72 at most) and revocable. The credentials and invitations are in the state
  database. One more configured identity source under the entity ID
  `<issuer>/local`, held by `refused()` like an IdP: removing the block, the
  account or the passkey a grant was bought with refuses it. Verification is
  [go-authn/webauthn](https://github.com/go-authn/webauthn) (ES256, EdDSA,
  RS256; attestation `none`). `acr` is `https://refeds.org/profile/mfa`. CSRF,
  same-origin checks, per-host throttling, no open redirect, groups held to the
  scope. A `password_hash` in an accounts file is refused with a message that
  says so. No released version ever had local accounts with passwords. See
  the README. `saml` stays required. A passkey's ID, as the CLI lists and takes
  it, is lowercase hex: an ID in base64url began with `-` one time in 64 and
  could not be passed to `remove-passkey`, which read it as a flag.
- Pages now send `base-uri 'none'` and `X-Content-Type-Options: nosniff`.

## v0.23.12

Fixed:

- **A state row refused with an error no classifier knows still kept the
  provider not ready** (#94, left over from #84). Retries of one row are now
  bounded: after five flushes over at least thirty seconds in which the
  database took something else (a write, a delete, or a no-op probe) while
  the row kept failing, it is given up like a classified permanent error
  (logged once, counted in `bridge_state_rows_rejected_total{kind}`). A
  flush where nothing succeeds, the database being away, counts against no
  row, so an outage gives nothing up. The behaviour no longer depends on the
  list of driver error classes.

## v0.23.11

Fixed:

- **One row the database refuses for good stopped every later flush,
  revocations included.** `flushLocked` returned at the first error, so the
  pending deletes (refresh families, access tokens) queued behind a refused
  write never reached the database, and the provider stayed not ready until a
  restart reloaded what should have been revoked. A failed write no longer
  holds the deletes back, and a row refused for good (PostgreSQL SQLSTATE
  class 22/23, MySQL 1048/1062/1264/1265/1292/1366/1406/1452, SQLite
  constraint/mismatch/too-big) is logged once, counted in the new
  `bridge_state_rows_rejected_total{kind}`, and given up: it keeps working in
  memory but does not survive a restart. Other errors are retried as before.
  (#84)

## v0.23.10

Fixed:

- **An `AuthnInstant` in the future counted as a fresh authentication under
  `max_age`.** The elapsed time came out negative, so it was never past
  `max_age`. An instant later than now plus the clock skew (three minutes,
  go-authn/saml's `ClockSkew`) is now treated as unknown elapsed time (OIDC
  Core 3.1.2.1): the person is sent back to the IdP with `ForceAuthn`, as for
  a stale one. Within the skew nothing changes. (#85)

## v0.23.6

Fixed:

- **Metadata refresh could let every IdP lapse.** The refresh loop waited
  three quarters of `cacheDuration` (twelve hours without one) whatever was
  left of the metadata's `validUntil`, and kept waiting twelve hours once no
  valid metadata remained. One failed refresh near expiry left the provider
  with no IdP for up to twelve hours after the federation server was back.
  The schedule is now go-authn/saml's `Federation.Run`: never past half of
  the remaining validity, and with no valid metadata a retry from one minute,
  doubling to one hour.
- **A long IdP entity ID could wedge the state database.** The assertion
  replay key (the IdP's entity ID and the assertion ID) was stored as is, in a
  `VARCHAR(128)` column. PostgreSQL and MySQL in strict mode refuse a longer
  value, so the write stayed pending, the provider stayed not ready, and later
  revocations queued behind it never reached the database. The key is now
  the value's SHA-256. SQLite was not affected.
- **The rate limiter treated a clock stepping back as negative time** and
  drained every bucket by the size of the step. `time.Now`'s monotonic
  reading does not step, so production clocks were not affected. This is
  defence in depth.

Tested:

- XML signature wrapping (XSW1 to XSW8 and their same-ID variants), comment
  truncation (CVE-2017-11427), DOCTYPE and entity expansion, assertions for
  another audience, recipient, request or destination, and replay, all end to
  end through the ACS.
- Fuzzers for the ACS (`FuzzACSAccept`), the federation metadata, access
  token verification (including `alg` confusion seeds), the login cookie, and
  redirect URI matching.
- Chaos: the bridge's clock ±2 minutes (accepted) and ±1 hour (refused); a
  metadata server that is slow, down, answers 500, garbage, HTML, a
  truncated or tampered document, or nothing.

Dependencies: go-authn/saml v0.5.1 (same library code as v0.4.1, plus the
pure-Go `samltest` package the fuzzers use).
