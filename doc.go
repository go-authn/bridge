// SPDX-License-Identifier: BSD-3-Clause

// Command bridge is an OpenID Connect provider in front of a SAML federation
// such as RENATER or eduGAIN: people log in at their own institution, and
// applications get an OpenID Connect token.
//
//	bridge keygen   --key /var/lib/bridge/oidc.key --salt /var/lib/bridge/salt
//	bridge metadata --config /etc/bridge.d > sp.xml
//	bridge check    --config /etc/bridge.d
//	bridge          --config /etc/bridge.d
//
// The SAML half is github.com/go-authn/saml; this is the OpenID Connect half
// and the mapping between them. See the README for the configuration.
package main
