# The OpenID Foundation conformance suite, against the bridge

`run.sh` runs the suite's `oidcc-basic-certification-test-plan` (the plan
OpenID Provider certification runs; static clients, discovery) against the
bridge built from this tree, and `expected.txt` names, with a reason, every
module expected not to pass. The `conformance` workflow runs it on every pull
request.

On one Docker network:

| | |
|---|---|
| `server`, `nginx`, `mongodb` | the suite, from its published images, at a pinned release |
| `bridge` | the bridge, TLS on a throwaway self-signed certificate |
| `idp` | `testidp`: crewjam/saml's IdP with one person always logged in, its metadata scoped, wrapped and signed like a federation's |

`driver` talks to the suite's REST API as the suite's own `run-test-plan.py`
does: creates the plan, starts each module, waits for it -- the suite drives
the browser itself (HtmlUnit), with the `browser` commands in the plan's
configuration -- and prints each FAILURE and WARNING the suite logged. It exits
non-zero on a module that does not pass and is not in `expected.txt`, and on
one listed there that starts passing.

The script is for linux/amd64, where CI runs it; the keys it makes are
throwaway and live in `work/`, which git ignores.
