// SPDX-License-Identifier: BSD-3-Clause

package app

import "github.com/go-authn/saml"

// samplePages is every page, with data that fills it: what the tests render to
// check the markup and what the screenshots show. The keys are the names a
// page is shown under; the account page appears in each of its states.
func samplePages() map[string]map[string]any {
	idps := []*saml.IdP{
		{EntityID: "https://idp.univ-example.example/idp", Names: map[string]string{"fr": "Université d'Exemple", "en": "Example University"}},
		{EntityID: "https://idp.cnrs.example/idp", Names: map[string]string{"fr": "Centre national de la recherche", "en": "National Research Centre"}},
		{EntityID: "https://idp.mesocentre.example/idp", Names: map[string]string{"fr": "Mésocentre de calcul", "en": "Computing centre"}},
	}
	keys := []accountKey{
		{Key: "0123456789abcdef0123", Prefix: "0123456789abcdef", Created: "2026-11-02 09:14 UTC", LastUsed: "2026-11-18 08:02 UTC", Arg: `{"key":"0123456789abcdef0123"}`, Backup: true, Current: true},
		{Key: "fedcba9876543210fedc", Prefix: "fedcba9876543210", Created: "2026-11-10 17:40 UTC", Arg: `{"key":"fedcba9876543210fedc"}`},
	}
	apps := []accountApp{
		{Client: "Fileshare (fileshare)", Created: "2026-11-16 10:00 UTC", LastUsed: "2026-11-18 07:55 UTC", Arg: `{"id":"a1b2c3"}`},
		{Client: "rclone (WebDAV) (rclone)", Created: "2026-11-17 14:30 UTC", Arg: `{"id":"d4e5f6"}`},
	}
	access := []accountAccess{
		{What: "access.kind.ssh", Detail: "SHA256:aBcD…", Expires: "2026-11-19 08:00 UTC", Arg: `{"kind":"ssh"}`},
		{What: "access.kind.app_password", Detail: "SMB", Expires: "2026-12-01 00:00 UTC", Arg: `{"kind":"app"}`},
	}
	signed := func(local bool) map[string]any {
		m := map[string]any{
			"Signed": true, "CSRF": "sample-csrf", "Local": local, "Login": "amartin", "Name": "Alice Martin",
			"Mail": "alice.martin@mesocentre.example", "Groups": []string{"calcul", "stockage"},
			"Apps": apps, "Access": access, "AccessOn": true,
		}
		if local {
			m["Keys"], m["Max"], m["Full"] = keys, maxPasskeys, false
		} else {
			m["Source"] = "Université d'Exemple (https://idp.univ-example.example/idp)"
		}
		return m
	}
	return map[string]map[string]any{
		"message":            {"Msg": "Cette connexion est expirée ; recommencez depuis l'application. / This login has expired; start again from the application."},
		"choose":             {"IdPs": idps, "Q": "", "More": 12},
		"choose-empty":       {"IdPs": []*saml.IdP(nil), "Q": "zzz", "More": 0},
		"method":             {"Federation": "/saml/choose"},
		"locallogin":         {"CSRF": "sample-csrf"},
		"locallogin-error":   {"CSRF": "sample-csrf", "Error": "Clé d'accès refusée. / Passkey refused."},
		"localenroll":        {},
		"device":             {},
		"device-error":       {"Error": "device.err.code", "Code": "ABCD-EFGH"},
		"confirm":            {"Client": "rclone (WebDAV)", "Code": "ABCD-EFGH", "CSRF": "sample-csrf"},
		"accountopen":        {"Handle": "sample-handle"},
		"account-signed":     signed(true),
		"account-federated":  signed(false),
		"account-stepup":     {"Signed": false, "Passkey": true},
		"account-stepup-fed": {"Signed": false, "Passkey": false},
		"account-done":       {"Signed": false, "Passkey": true, "Done": true},
	}
}

// templateOf is the template a sample is shown with.
func templateOf(sample string) string {
	switch sample {
	case "choose-empty":
		return "choose"
	case "locallogin-error":
		return "locallogin"
	case "device-error":
		return "device"
	case "account-signed", "account-federated", "account-stepup", "account-stepup-fed", "account-done":
		return "account"
	}
	return sample
}
