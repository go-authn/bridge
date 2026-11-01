# Changelog

Versions follow [semantic versioning](https://semver.org). Releases before
v0.23.6 are described in their [GitHub releases](https://github.com/go-authn/bridge/releases).

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
