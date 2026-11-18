// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// The home page is GET / (and HEAD): what this service is, a button to
// /account, what a passkey is, the federation people can sign in through, and
// the links the deployment chose to list. It is the same for everybody and
// shows nothing about clients, users or keys: only the brand, the optional
// `home` block and the federation's name. Every other unknown path stays 404.
//
//	home {
//	  title = "Mésocentre de Saclay"             # optional, replaces the heading
//	  link "Fileshare" { url = "https://files.example.org" }
//	}
type homeBlock struct {
	Title string     `hcl:"title,optional"`
	Links []homeLink `hcl:"link,block"`
}

type homeLink struct {
	Name string `hcl:"name,label"`
	URL  string `hcl:"url"`
}

const (
	maxHomeTitleRunes = 80
	maxHomeLinks      = 20
)

// check refuses what cannot be shown safely: a title or a name with control or
// bidirectional characters, more than maxHomeLinks links, and any URL that is
// not https (so no javascript:, data:, http: or mailto: link).
func (h *homeBlock) check() error {
	if h.Title != "" {
		if err := checkText(h.Title, maxHomeTitleRunes); err != nil {
			return fmt.Errorf("title: %w", err)
		}
	}
	if len(h.Links) > maxHomeLinks {
		return fmt.Errorf("%d links, where %d are the most", len(h.Links), maxHomeLinks)
	}
	for _, l := range h.Links {
		if strings.TrimSpace(l.Name) == "" {
			return errors.New("a link without a name")
		}
		if err := checkText(l.Name, maxBrandNameRunes); err != nil {
			return fmt.Errorf("link %q: name: %w", l.Name, err)
		}
		if err := checkHTTPS(l.URL); err != nil {
			return fmt.Errorf("link %q: url: %w", l.Name, err)
		}
	}
	return nil
}

// checkHTTPS accepts an https URL with a host and no credentials.
func checkHTTPS(s string) error {
	if err := checkSupportURL(s); err != nil {
		return err
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("an https URL with a host and no credentials")
	}
	return nil
}

// federationName is how the federation of the metadata URL is called on the
// page: RENATER and eduGAIN by name, any other by its host.
func federationName(metadataURL string) string {
	u, err := url.Parse(metadataURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	switch {
	case strings.Contains(h, "renater"):
		return "RENATER"
	case strings.Contains(h, "edugain"):
		return "eduGAIN"
	}
	return h
}

func (s *server) homePage(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Passkeys":   s.cfg.Local != nil,
		"Federation": federationName(s.cfg.SAML.MetadataURL),
	}
	if h := s.cfg.Home; h != nil {
		data["HomeTitle"], data["Links"] = h.Title, h.Links
	}
	headers(w)
	w.WriteHeader(http.StatusOK)
	s.show(w, "home", data)
}
