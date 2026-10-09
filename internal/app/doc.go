// SPDX-License-Identifier: BSD-3-Clause

// Package app is the authn-bridge command: an OpenID Connect provider in
// front of a SAML federation such as RENATER or eduGAIN. It is internal so
// that nothing outside this module depends on the program's insides;
// cmd/authn-bridge calls [Main] and nothing else.
//
// The SAML half is github.com/go-authn/saml; this is the OpenID Connect half
// and the mapping between them. See the README for the configuration.
package app
