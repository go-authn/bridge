// SPDX-License-Identifier: BSD-3-Clause

// Command authn-bridge is an OpenID Connect provider in front of a SAML
// federation such as RENATER or eduGAIN: people log in at their own
// institution, and applications get an OpenID Connect token.
//
//	authn-bridge keygen   --key /var/lib/authn-bridge/oidc.key --salt /var/lib/authn-bridge/salt
//	authn-bridge metadata --config /etc/authn-bridge > sp.xml
//	authn-bridge check    --config /etc/authn-bridge
//	authn-bridge          --config /etc/authn-bridge
//
// It was called bridge until v0.20.0. The name changed because iproute2
// installs /sbin/bridge on practically every Linux distribution.
//
//	go install github.com/go-authn/bridge/cmd/authn-bridge@latest
package main

import "github.com/go-authn/bridge/internal/app"

func main() { app.Main() }
