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
configuration: claims, TLS and ACME, SSH and X.509 certificates, application
passwords, the admin API and metrics.

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

Create the accounts file empty, owned by root and readable by the service's
group, name it in the configuration together with the state database, then
invite the first account:

```sh
install -m 0640 -o root -g authn-bridge /dev/null /etc/authn-bridge/accounts.hcl
install -m 0600 -o authn-bridge -g authn-bridge /dev/null /etc/authn-bridge/state.dsn
echo 'file:/var/lib/authn-bridge/state.db?_pragma=busy_timeout(5000)' > /etc/authn-bridge/state.dsn
install -d -m 0750 -o authn-bridge -g authn-bridge /var/lib/authn-bridge
cat >> /etc/authn-bridge/bridge.hcl <<'HCL'

local {
  accounts_file = "/etc/authn-bridge/accounts.hcl"
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

chown root:authn-bridge /etc/authn-bridge/accounts.hcl   # if root's group changed it
chmod 0640 /etc/authn-bridge/accounts.hcl
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
refused. Run `local-account` as root (or as the service's user, for the
passkey commands): it replaces the accounts file next to itself and keeps its
owner and group. The running provider reads the file within a second, and the
invitations and passkeys from the database at every use, so inviting, removing
a passkey and removing an account need no restart (the `local` block itself
does). A `password_hash` in an accounts file is refused: delete the line.
The RP ID is the issuer's host, so the issuer URL must be the one people use in
their browser, over HTTPS.

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
