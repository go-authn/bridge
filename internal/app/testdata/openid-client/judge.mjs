// SPDX-License-Identifier: BSD-3-Clause
//
// openid-client, an OpenID Certified relying party that nobody here wrote,
// as the client of go-authn/bridge. The Go test (openidclient_test.go) runs
// the provider and plays the person in the browser; this side plays the
// application, and every check is openid-client's own.
//
// One JSON object per line each way. This side asks the Go side to walk a
// URL with {"walk": url, "kind": "login"|"device"} and reads back
// {"url": where the browser ended}; it ends with {"done": results} or
// {"error": message, "step": step}.

import * as client from 'openid-client'
import * as oauth from 'oauth4webapi'
import { createInterface } from 'node:readline'

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]()
const say = (o) => process.stdout.write(JSON.stringify(o) + '\n')
async function walk(url, kind) {
  say({ walk: url, kind })
  const { value, done } = await lines.next()
  if (done) throw new Error('the Go side went away')
  return JSON.parse(value).url
}

const { issuer, web, device } = JSON.parse(process.env.JUDGE_CONFIG)
const results = {}
let step = 'discovery'
try {
  // Discovery: openid-client requires the document's issuer to equal the
  // URL it was fetched for, character for character.
  const cfg = await client.discovery(new URL(issuer), web.client_id, undefined,
    client.ClientSecretBasic(web.secret))
  const as = cfg.serverMetadata()
  results.discovery = as.issuer

  step = 'authorization code'
  const verifier = client.randomPKCECodeVerifier()
  const state = client.randomState()
  const nonce = client.randomNonce()
  const authURL = client.buildAuthorizationUrl(cfg, {
    redirect_uri: web.redirect_uri,
    scope: 'openid profile email groups',
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state, nonce,
  })
  const back = await walk(authURL.href, 'login')
  // Checks the iss response parameter (RFC 9207, advertised), state, the
  // code exchange, and the ID Token: signature by a kid from jwks_uri,
  // iss, aud, azp, exp, iat, nonce.
  const tokens = await client.authorizationCodeGrant(cfg, new URL(back), {
    pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true,
  })
  const claims = tokens.claims()
  results.code = { sub: claims.sub, token_type: tokens.token_type, has_refresh: !!tokens.refresh_token }

  step = 'userinfo'
  // Refused unless its sub is the ID Token's (Core 5.3.2).
  const ui = await client.fetchUserInfo(cfg, tokens.access_token, claims.sub)
  results.userinfo = { sub: ui.sub, email: ui.email, preferred_username: ui.preferred_username }

  step = 'access token (RFC 9068)'
  // What a resource server would check: typ at+jwt, iss, aud, exp, iat,
  // sub, client_id, jti, signature from jwks_uri.
  const at = await oauth.validateJwtAccessToken(as,
    new Request(issuer + '/resource', { headers: { authorization: 'Bearer ' + tokens.access_token } }),
    web.audience)
  results.access_token = { sub: at.sub, client_id: at.client_id, aud: at.aud }

  step = 'refresh'
  const refreshed = await client.refreshTokenGrant(cfg, tokens.refresh_token)
  results.refresh = { rotated: !!refreshed.refresh_token && refreshed.refresh_token !== tokens.refresh_token,
    sub: refreshed.claims()?.sub }

  step = 'refresh token reused'
  try {
    await client.refreshTokenGrant(cfg, tokens.refresh_token)
    results.reuse = 'accepted'
  } catch (e) {
    results.reuse = e.error || e.code || String(e)
  }

  step = 'device authorization'
  const dcfg = await client.discovery(new URL(issuer), device.client_id, undefined, client.None())
  const da = await client.initiateDeviceAuthorization(dcfg, { scope: 'openid groups' })
  await walk(da.verification_uri_complete, 'device')
  const dt = await client.pollDeviceAuthorizationGrant(dcfg, da)
  results.device = { sub: dt.claims()?.sub, has_refresh: !!dt.refresh_token }

  say({ done: results })
} catch (e) {
  say({ error: String(e?.message || e), code: e?.code, cause: e?.cause ? JSON.stringify(e.cause) : undefined, step, results })
}
process.exit(0)
