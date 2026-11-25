# Installing authn-bridge on a Linux host

This takes a fresh Linux host with systemd to a running, hardened
`authn-bridge` service. It uses a release binary, the unit in
[`packaging/systemd/authn-bridge.service`](../packaging/systemd/authn-bridge.service)
and the user in
[`packaging/sysusers.d/authn-bridge.conf`](../packaging/sysusers.d/authn-bridge.conf).
Every command runs as root unless it says otherwise.

| | |
|---|---|
| `/usr/local/bin/authn-bridge` | the binary |
| `/etc/authn-bridge/*.hcl` | the configuration, read in name order; `root:authn-bridge`, `0750`, files `0640` |
| `/var/lib/authn-bridge/` | keys, the subject salt, the SQLite state, the certificates issued, the disabled list; `authn-bridge`, `0700` |
| `/run/authn-bridge/` | the admin socket, when the configuration asks for one |

The command was called `bridge` before v0.20.0. See "Coming from `bridge`"
below.

> **go-pkgx.** `pkgm service`, with versioned services, will install and
> upgrade this for you later. **It does not exist yet.** Until it does, this
> page is the way to install authn-bridge.

## 1. Download and verify

Pick the release and the architecture (`amd64` or `arm64`):

```sh
V=v0.20.0
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
base=https://github.com/go-authn/bridge/releases/download/$V
curl -fLO "$base/authn-bridge-linux-$ARCH"
curl -fLO "$base/SHA256SUMS"
```

Check it before running it. The checksum says the file is the one the release
lists. The attestation says the release workflow of go-authn/bridge built it
at that tag:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify "authn-bridge-linux-$ARCH" --repo go-authn/bridge
```

`--ignore-missing` skips the other platforms' lines, so a line reading
`authn-bridge-linux-$ARCH: OK` must be in the output. A host without `gh`
can run the attestation check on another machine against the same file.

## 2. Install the binary, the user and the unit

```sh
install -m 0755 "authn-bridge-linux-$ARCH" /usr/local/bin/authn-bridge
authn-bridge --version            # authn-bridge version v0.20.0

raw=https://raw.githubusercontent.com/go-authn/bridge/$V/packaging
curl -fLo authn-bridge.conf    "$raw/sysusers.d/authn-bridge.conf"
curl -fLo authn-bridge.service "$raw/systemd/authn-bridge.service"
```

The checksums and the attestation do not cover these two files. Both are
short, so read them before you install them:

```sh
install -D -m 0644 authn-bridge.conf /etc/sysusers.d/authn-bridge.conf
systemd-sysusers                  # creates the authn-bridge user and group
install -m 0644 authn-bridge.service /etc/systemd/system/authn-bridge.service
systemctl daemon-reload

install -d -m 0750 -o root -g authn-bridge /etc/authn-bridge
install -d -m 0700 -o authn-bridge -g authn-bridge /var/lib/authn-bridge
```

`/etc/sysusers.d` may not exist on a fresh host; `install -D` creates it.

The unit uses a static user, not `DynamicUser=`. The keys below are made
before the first start, last for years, and must keep the same owner across
reinstalls and restores from backup. A dynamic user gets its UID when the
service starts.

## 3. Keys

Run these as the service's user, so that it owns what they write. Each one
refuses to overwrite a file that is already there:

```sh
runuser -u authn-bridge -- authn-bridge keygen \
  --key /var/lib/authn-bridge/oidc.key --salt /var/lib/authn-bridge/salt
```

- `oidc.key` signs the ID tokens (RSA 3072). It is published at `/jwks`.
- `salt` is the subject salt. **Back it up and never change it.** A new salt
  gives every person a new `sub`, and every relying party sees a new person.

The SAML key and certificate are what the federation registers and what every
IdP encrypts to. They are not the TLS certificate and do not change with it:

```sh
runuser -u authn-bridge -- sh -c 'umask 077; openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -subj "/CN=login.example.org" \
  -keyout /var/lib/authn-bridge/saml.key -out /var/lib/authn-bridge/saml.crt'
```

The optional features have keys of their own: `--ssh-ca`,
`--access-token-key` and `--x509-ca`. The README explains them.

The federation's metadata signing certificate comes from the federation, and
so does its SHA-256 fingerprint. Get the fingerprint from the federation's web
page, not from the same download as the certificate. Then compare:

```sh
install -m 0640 -o root -g authn-bridge federation-signer.pem /etc/authn-bridge/federation-signer.pem
openssl x509 -in /etc/authn-bridge/federation-signer.pem -noout -fingerprint -sha256
```

## 4. A minimal configuration

These are all the keys the provider requires: `issuer`, `signing_key_file`,
`subject_salt_file`, a `saml` block with its five required keys, and at
least one `client`. Everything else has a default or is off:

```sh
cat > /etc/authn-bridge/bridge.hcl <<'HCL'
issuer            = "https://login.example.org"  # what relying parties see; https
listen            = "127.0.0.1:8080"             # the default: plain HTTP behind a TLS proxy
signing_key_file  = "/var/lib/authn-bridge/oidc.key"
subject_salt_file = "/var/lib/authn-bridge/salt"

saml {
  key_file             = "/var/lib/authn-bridge/saml.key"
  cert_file            = "/var/lib/authn-bridge/saml.crt"
  metadata_url         = "https://pub.federation.renater.fr/metadata/fer/idps.xml"
  metadata_cert_file   = "/etc/authn-bridge/federation-signer.pem"
  metadata_fingerprint = "<the SHA-256 fingerprint, from the federation's page>"
}

# Without it, a restart logs everybody out.
state {
  driver   = "sqlite"
  dsn_file = "/etc/authn-bridge/state.dsn"
}

client "my-app" {
  secret_file   = "/etc/authn-bridge/my-app.secret"
  redirect_uris = ["https://app.example.org/callback"]
}
HCL

printf 'file:/var/lib/authn-bridge/state.db' > /etc/authn-bridge/state.dsn
openssl rand -hex 32 | tr -d '\n' > /etc/authn-bridge/my-app.secret
chown root:authn-bridge /etc/authn-bridge/*
chmod 0640 /etc/authn-bridge/*
```

Give the secret to the relying party. The README covers the rest of the
configuration: claims, TLS and ACME, SSH and X.509 certificates, Kerberos
tickets for SMB, the admin API and metrics.

Check the configuration and the federation's metadata as the service will
read them. Then print the SP metadata to register with the federation:

```sh
runuser -u authn-bridge -- authn-bridge check    --config /etc/authn-bridge
runuser -u authn-bridge -- authn-bridge metadata --config /etc/authn-bridge > sp.xml
```

### Local accounts (optional): the first account

Until the federation has registered this provider, or for people it does not
know, the provider can hold accounts itself (README, "Local accounts"). They
are **passkey-only**: there is no password anywhere. A person gets in by an
invitation you issue from this host, and signs in with a passkey (a WebAuthn
credential on their phone, laptop or security key, unlocked by a PIN or a
biometric). Local accounts need a `state` block: the passkeys, their signature
counters and the invitations are kept there.

Once signed in, a person manages their own passkeys at
`https://login.example.org/account` ("Mon compte"): add one, list them, remove
one (never the last), after confirming with a passkey. That page is every
person's, federated ones included (identity, application sessions, technical
access); it needs no configuration. Behind a reverse proxy it needs the same
things the login does: the issuer's `https` origin reaching the provider
unchanged, and `X-Forwarded-For` trusted from the proxy only, since the
per-host throttle and the audit line name the client address.

Removing a passkey other than the one you are signed in with waits
`passkey_removal_delay` in the `local` block (default `"24h"`; `"0"` removes at
once). The key keeps working meanwhile, and any of the person's keys can cancel
the removal from `/account`, which shows a banner. This is the guard against a
stolen, unlocked phone wiping the other keys. To tell the person, add a signed
webhook (the bridge sends no mail itself):

```hcl
notify {
  url         = "https://hooks.example.org/bridge"   # https, or http to loopback
  secret_file = "/etc/authn-bridge/notify.secret"    # 16+ characters; HMAC-SHA-256 key
  # include_address = true   # the client's whole address; by default its family only
}
```

Each key added, removal requested, cancelled or done is one POST of a JSON event
(`event`, `time`, `login`, `mail`, `key` (16 characters), `effective`, `client`,
`link`), signed in `X-Bridge-Signature: sha256=<hex>` over the body. Without a
`notify` block the audit log lines and the banner remain.

Create the accounts file empty, owned by root and readable by the service's
group, name it in the configuration together with the state database, then
invite the first account. The file lives in a directory of its own, NOT in
`/etc/authn-bridge`: `--config /etc/authn-bridge` reads every `*.hcl` file
there as configuration, and an `account` block is not configuration. `check`,
startup and `local-account` refuse an accounts file placed where `--config`
reads it.

```sh
install -d -m 0750 -o root -g authn-bridge /etc/authn-bridge-local
install -m 0640 -o root -g authn-bridge /dev/null /etc/authn-bridge-local/accounts.hcl
install -m 0600 -o authn-bridge -g authn-bridge /dev/null /etc/authn-bridge/state.dsn
echo 'file:/var/lib/authn-bridge/state.db?_pragma=busy_timeout(5000)' > /etc/authn-bridge/state.dsn
install -d -m 0750 -o authn-bridge -g authn-bridge /var/lib/authn-bridge
cat >> /etc/authn-bridge/bridge.hcl <<'HCL'

local {
  accounts_file = "/etc/authn-bridge-local/accounts.hcl"   # outside --config's directory
  scope         = "login.example.org"     # your domain: groups must live under it
}

state {
  driver   = "sqlite"
  dsn_file = "/etc/authn-bridge/state.dsn"
}
HCL

# the first administrator: an invitation like any other, with the group the
# resource servers treat as administrators. The URL is printed alone.
authn-bridge local-account invite --config /etc/authn-bridge --name "Alice Martin" \
    --group urn:geant:example.org:hpc:admins alice
# https://login.example.org/local/enroll#Qk3f...

chown root:authn-bridge /etc/authn-bridge-local/accounts.hcl   # if root's group changed it
chmod 0640 /etc/authn-bridge-local/accounts.hcl
runuser -u authn-bridge -- authn-bridge check --config /etc/authn-bridge   # "local ...: 1 accounts"
```

Send the URL to Alice over a channel only she reads (it is a one-time key to
her account); she opens it on the device that will hold her passkey and
follows the browser's prompt. The part after `#` never reaches a log or a
`Referer`; it works once, expires in 24 hours (`--ttl`, 72 at most), and is
stored only as a hash. `local-account invite alice` again adds a key (a second
device); `revoke-invite` cancels one not yet used; `passkeys alice` lists the
keys (ID, created, last used, backup-eligible) and `remove-passkey alice <id>`
removes one -- and with it the tokens and codes that key bought.

`--group` takes a value under `scope` (`urn:geant:<scope>:...`,
`urn:mace:<scope>:...` or `https://<host under scope>/...`); another is
refused. Run `local-account` as **root** when the directory is `root:authn-bridge`
0750 and the file 0640, as above: it replaces the accounts file by writing a
temporary file next to it (`.accounts-NNN`), and as `authn-bridge` that fails
with `open /etc/authn-bridge-local/.accounts-NNN: permission denied`. The
command keeps the file's owner and mode. Over SSH, `ssh host sudo authn-bridge
local-account … --name "Two words"` needs one more layer of quotes
(`--name '"Two words"'`), because ssh joins its arguments into one string that
the remote shell splits again. The running provider reads the file within a second, and the
invitations and passkeys from the database at every use, so inviting, removing
a passkey and removing an account need no restart (the `local` block itself
does). A `password_hash` in an accounts file is refused: delete the line.
The RP ID is the issuer's host, so the issuer URL must be the one people use in
their browser, over HTTPS.

### Administrators who invite from the web (optional): the FIDO metadata

With `admins` and `admin_aaguids` in the `local` block, an administrator's
passkey must be PROVED to be of an allowed model through its attestation, which
the bridge checks against the FIDO Metadata Service. The host needs:

- a directory the service may write: `mds_dir`, default
  `/var/lib/authn-bridge/mds`, which the unit's `StateDirectory=authn-bridge`
  already creates (0700, files 0600). If you set another path it must be in the
  unit's `ReadWritePaths=`;
- outbound HTTPS to `mds3.fidoalliance.org`, and outbound plain HTTP to the CRL
  distribution points of its certificates (they change; allow the service's
  outbound web access, not a single address);
- the clock right: the metadata and its certificates are checked against it.

The service starts without the metadata (the log says `mds: ... could not be
loaded` and retries); until it is in, no administrator key is proved and the
invitation page refuses. Existing administrators add their key again, as the
README describes ("Registering an administrator's key again").

### Branding (optional)

The pages are neutral go-authn pages until a `branding` block gives them your
institution's face. Add it to any file in `/etc/authn-bridge`:

```hcl
branding {
  name         = "Mésocentre de Calcul"        # header and page titles
  logo_file    = "/etc/authn-bridge/logo.svg"  # SVG or PNG, 256 KiB at most
  accent_color = "#0b6e4f"                     # #rrggbb
  support_url  = "https://aide.example.org"    # https or mailto:
}
```

All four are optional. The logo file must be readable by the `authn-bridge`
user; it is read once, at start, and served from the provider's own origin (no
CDN, no font, no inline style). An SVG with a script, a style sheet, text or a
reference to another file is refused, and so is a PNG over 2048 pixels, a colour
that is not `#rrggbb`, and a support URL that is not `https:` or `mailto:`.
`authn-bridge check --config /etc/authn-bridge` reports the field. A change
needs a restart.

## 5. Start it, and check it

```sh
systemctl enable --now authn-bridge
systemctl status authn-bridge          # active (running)
journalctl -u authn-bridge -n 20       # "authn-bridge v0.20.0: https://login.example.org on 127.0.0.1:8080"
curl -s http://127.0.0.1:8080/.well-known/openid-configuration
```

The provider fetches the federation's metadata **before** it listens. Without
the metadata it exits, and systemd retries it every 5 seconds
(`Restart=on-failure`). The journal says why it stopped.

`systemd-analyze security authn-bridge` rates the unit. On Ubuntu 24.04
(systemd 255) its exposure is **1.1, OK**. The remaining points are what the
service needs to work: the host's network, AF_INET, AF_INET6 and AF_UNIX
sockets, and no IP allow list. You can add `IPAddressAllow=` in a drop-in if
the federation, the ACME CA and the database have fixed addresses.

**Configuration changes need a restart.** The provider does not reload its
configuration, so after editing `/etc/authn-bridge`, run
`systemctl restart authn-bridge`. `systemctl reload` is refused, because the
unit has no `ExecReload=`. A SIGHUP, from logrotate for example, is logged
and ignored, and the service stays up. TLS certificate files are the
exception: the provider re-reads them when they change.

### Port 443

The unit holds no capability. That is enough for its default address, which
is loopback behind a reverse proxy. If authn-bridge serves TLS itself on
port 443 (`cert_file` or `acme`), it needs `CAP_NET_BIND_SERVICE`. It must
also leave the private user namespace, because a capability held inside that
namespace does not apply to the host's network:

```sh
mkdir -p /etc/systemd/system/authn-bridge.service.d
cat > /etc/systemd/system/authn-bridge.service.d/port-443.conf <<'EOF'
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateUsers=no
EOF
systemctl daemon-reload && systemctl restart authn-bridge
```

With this drop-in the exposure is 1.4. Without `PrivateUsers=no`, the bind
fails with `permission denied` even though the service holds the capability.

### The SMTP password of the `mail` block, sealed with systemd-creds

`password_from` takes a secretsource reference, so the password never sits in
the configuration. On a systemd host, seal it to the machine and hand it to the
service as a credential:

The secret goes in on standard input, typed without echo, so it is in no
command line, no shell history and no file in clear:

```sh
# on a host WITHOUT a TPM (systemd 257): the key is the host key file
sudo systemd-creds encrypt --with-key=host --name=smtp-password \
  - /etc/credstore.encrypted/smtp-password
# type the password, then Ctrl-D twice; nothing is echoed
```

```ini
# systemctl edit authn-bridge
[Service]
LoadCredentialEncrypted=smtp-password:/etc/credstore.encrypted/smtp-password
```

```hcl
mail {
  # ...
  password_from = "systemd-creds:smtp-password"   # reads $CREDENTIALS_DIRECTORY/smtp-password
}
```

The service refuses to start if the credential is missing, and the error names
the `LoadCredentialEncrypted=` line to check. `authn-bridge check`, run from a
shell and not inside the unit, cannot read a credential, so it reports
`credential smtp-password: resolved only inside the service` and does not fail.

On a host with a TPM2, use `--with-key=host+tpm2` with no `--tpm2-pcrs`: the key
derives from the TPM2 chip and the host key file, and survives firmware and
Secure Boot updates. Do not use a bare `--tpm2-pcrs=7`: a firmware or shim
update would make the credential unreadable and the bridge would refuse to
start.

On OpenBSD there is no systemd-creds. The source of the SMTP password there is
not decided here: it is a new secretsource scheme, which `password_from` would
take like any other (`mail.go` passes the reference to `secretsource.Open`
and knows no scheme by name, except to explain a missing `systemd-creds:`
credential).

**Recovery.** The credential is lost with the TPM2 chip or
`/var/lib/systemd/credential.secret`, and a decryption failure stops the
bridge at startup with an error that says the credential may need re-sealing.
Keep the password in a place that does not depend on this machine (an offline
copy), and re-seal from that copy with the `systemd-creds encrypt` command
above, then `systemctl restart authn-bridge`.

`password_file = "PATH"` still works but is deprecated: it is read as
`password_from = "file:PATH"`. Setting both is refused.

## 6. Upgrade, and roll back

Back up `/var/lib/authn-bridge` first. It holds the keys and the salt, which
cannot be made again. Then download and verify the new release as in step 1,
and keep the binary that works now:

```sh
cp -p /usr/local/bin/authn-bridge /usr/local/bin/authn-bridge.previous
install -m 0755 "authn-bridge-linux-$ARCH" /usr/local/bin/authn-bridge
systemctl restart authn-bridge
authn-bridge --version && systemctl is-active authn-bridge
```

Read the release's "Upgrading to" section in the README before you restart.
To go back, restore the previous binary:

```sh
install -m 0755 /usr/local/bin/authn-bridge.previous /usr/local/bin/authn-bridge
systemctl restart authn-bridge
```

A newer release can also ship a newer unit. Compare it with yours
(`diff`), install it, and run `systemctl daemon-reload` before the restart.

## Coming from `bridge` (before v0.20.0)

The command was renamed, but the configuration is the same. Install the new
binary as `/usr/local/bin/authn-bridge`, and change every unit, script and
`bearer_token_command` that runs `bridge`. Then remove the old binary. Your
existing paths, such as `/etc/bridge.d` or `/var/lib/bridge`, keep working
when the configuration names them. To use them with this unit, either point
`ExecStart=` at them in a drop-in and add `ReadWritePaths=/var/lib/bridge`,
or move them:

```sh
systemctl stop bridge 2>/dev/null; systemctl disable bridge 2>/dev/null
mv /var/lib/bridge/* /var/lib/authn-bridge/ && chown -R authn-bridge:authn-bridge /var/lib/authn-bridge
# then edit the paths in /etc/authn-bridge/*.hcl to match
```

## Uninstall

```sh
systemctl disable --now authn-bridge
rm -f /etc/systemd/system/authn-bridge.service
rm -rf /etc/systemd/system/authn-bridge.service.d
systemctl daemon-reload
rm -f /usr/local/bin/authn-bridge /usr/local/bin/authn-bridge.previous
```

The keys, the salt and the state are still in `/var/lib/authn-bridge`, and
the configuration is still in `/etc/authn-bridge`. **Deleting the salt means
every person gets a new `sub` if you ever reinstall.** Delete them only if
the provider is gone for good:

```sh
rm -rf /var/lib/authn-bridge /etc/authn-bridge
userdel authn-bridge; groupdel authn-bridge 2>/dev/null
rm -f /etc/sysusers.d/authn-bridge.conf
```
