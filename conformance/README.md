# The OpenID Foundation conformance suite, against the bridge

`run.sh` runs two of the suite's plans against the bridge built from this tree:
`oidcc-basic-certification-test-plan` (the plan OpenID Provider certification
runs; static clients, discovery), and `openid-ssf-transmitter-caep-test-plan`
against its Shared Signals transmitter (poll delivery, the receiver's token by
client credentials). `expected.txt` and `expected-ssf.txt` name, with a
reason, every module expected not to pass. The `conformance` workflow runs it on every pull
request.

On one Docker network:

| | |
|---|---|
| `server`, `nginx`, `mongodb` | the suite, from its published images, at a pinned release |
| `bridge` | the bridge, TLS on a throwaway self-signed certificate |
| `idp` | `testidp`: crewjam/saml's IdP for one person, logging in as an IdP does: a session cookie, a login page without one or on ForceAuthn, NoPassive to IsPassive without one; its metadata scoped, wrapped and signed like a federation's |
| `admin` | grpcurl on the bridge's admin socket: the operator's side of a CAEP event, which the SSF plan asks to be "triggered on the transmitter side" |

`driver` talks to the suite's REST API as the suite's own `run-test-plan.py`
does: creates the plan, starts each module, waits for it -- the suite drives
the browser itself (HtmlUnit), with the `browser` commands in the plan's
configuration -- and prints each FAILURE and WARNING the suite logged. It exits
non-zero on a module that does not pass and is not in `expected.txt`, and on
one listed there that starts passing. When a module's log asks for an event only the
tested side can send, it runs `-trigger` once: here, `RevokePerson` through
the admin API, a real revocation.

The script is for linux/amd64, where CI runs it; the keys it makes are
throwaway and live in `work/`, which git ignores.
