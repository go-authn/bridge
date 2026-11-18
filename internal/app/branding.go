// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"image/png"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The stylesheet is compiled at build time (internal/webbuild, Tailwind CSS),
// committed, and served from this origin under a name that carries its hash:
// the pages hold no inline style, so their style-src is 'self' and nothing
// else.
//
//go:embed web/static/app.css
var appCSS []byte

//go:embed web/static/logo.svg
var defaultLogo []byte

// brandingBlock is the deployment's face on the pages:
//
//	branding {
//	  name         = "Mésocentre"
//	  logo_file    = "/etc/authn-bridge/logo.svg"   # SVG or PNG, 256 KiB at most
//	  accent_color = "#0b6e4f"                      # #rrggbb
//	  support_url  = "https://help.example.org"     # https or mailto
//	}
//
// Every field is optional. Nothing here is written into a page as markup or
// style: the name and the URL go through html/template's escaping, the logo is
// a file served as an image, and the colour becomes four custom properties
// computed from its six hex digits (brand.css).
type brandingBlock struct {
	Name        string `hcl:"name,optional"`
	LogoFile    string `hcl:"logo_file,optional"`
	AccentColor string `hcl:"accent_color,optional"`
	SupportURL  string `hcl:"support_url,optional"`
}

const (
	defaultBrandName   = "go-authn"
	defaultAccent      = "#0079a8" // the go-authn mark's cyan
	maxBrandNameRunes  = 60
	maxLogoBytes       = 256 << 10
	maxLogoPixels      = 2048
	maxSupportURLBytes = 500
)

// brand is what the pages and the asset route need, built once at load.
type brand struct {
	Name       string
	SupportURL string
	// URLs of the assets, absolute paths on this origin.
	CSSURL, BrandCSSURL, LogoURL string

	assets map[string]asset // by name, under /assets/
}

type asset struct {
	body []byte
	typ  string
}

// defaultBrand is the neutral go-authn theme, for a configuration that says
// nothing (and for tests that build a config by hand).
var defaultBrand = func() *brand {
	b, err := (*brandingBlock)(nil).build()
	if err != nil {
		panic(err)
	}
	return b
}()

// brandView is the brand of this configuration.
func (c *config) brandView() *brand {
	if c.brand != nil {
		return c.brand
	}
	return defaultBrand
}

func contentName(prefix, ext string, b []byte) string {
	h := sha256.Sum256(b)
	return prefix + "." + hex.EncodeToString(h[:6]) + ext
}

// build validates the block (nil is allowed: all defaults) and prepares what
// is served.
func (bb *brandingBlock) build() (*brand, error) {
	var in brandingBlock
	if bb != nil {
		in = *bb
	}
	b := &brand{Name: defaultBrandName, assets: map[string]asset{}}
	if n := strings.TrimSpace(in.Name); n != "" {
		if err := checkText(n, maxBrandNameRunes); err != nil {
			return nil, fmt.Errorf("branding.name: %w", err)
		}
		b.Name = n
	} else if in.Name != "" {
		return nil, errors.New("branding.name: empty")
	}
	if in.SupportURL != "" {
		if err := checkSupportURL(in.SupportURL); err != nil {
			return nil, fmt.Errorf("branding.support_url: %w", err)
		}
		b.SupportURL = in.SupportURL
	}
	accent := defaultAccent
	if in.AccentColor != "" {
		c, err := parseHex(in.AccentColor)
		if err != nil {
			return nil, fmt.Errorf("branding.accent_color: %w", err)
		}
		accent = c.hex()
	}
	ac, _ := parseHex(accent)

	css := appCSSName()
	b.CSSURL = "/assets/" + css
	b.assets[css] = asset{appCSS, "text/css; charset=utf-8"}

	bc := []byte(brandCSS(ac))
	bn := contentName("brand", ".css", bc)
	b.BrandCSSURL = "/assets/" + bn
	b.assets[bn] = asset{bc, "text/css; charset=utf-8"}

	logo, typ, ext := defaultLogo, "image/svg+xml", ".svg"
	if in.LogoFile != "" {
		var err error
		if logo, typ, ext, err = readLogo(in.LogoFile); err != nil {
			return nil, fmt.Errorf("branding.logo_file: %w", err)
		}
	}
	ln := contentName("logo", ext, logo)
	b.LogoURL = "/assets/" + ln
	b.assets[ln] = asset{logo, typ}
	return b, nil
}

func appCSSName() string { return contentName("app", ".css", appCSS) }

// checkText refuses empty text, text over max runes, invalid UTF-8, control
// and format characters (line breaks, bidirectional overrides, zero-width).
func checkText(s string, max int) error {
	if !utf8.ValidString(s) {
		return errors.New("not valid UTF-8")
	}
	if utf8.RuneCountInString(s) > max {
		return fmt.Errorf("more than %d characters", max)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return fmt.Errorf("contains the control character U+%04X", r)
		}
	}
	return nil
}

func checkSupportURL(s string) error {
	if len(s) > maxSupportURLBytes {
		return fmt.Errorf("more than %d bytes", maxSupportURLBytes)
	}
	if err := checkText(s, maxSupportURLBytes); err != nil {
		return err
	}
	if strings.ContainsAny(s, " \t\"'<>\\`") {
		return errors.New("contains a space or a quote")
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" || u.User != nil {
			return errors.New("an https URL with a host and no credentials")
		}
	case "mailto":
		if u.Opaque == "" {
			return errors.New("a mailto: URL with an address")
		}
	default:
		return errors.New("an https or mailto: URL")
	}
	return nil
}

// ---- the logo ----

func readLogo(file string) (b []byte, typ, ext string, err error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, "", "", err
	}
	defer f.Close()
	b, err = io.ReadAll(io.LimitReader(f, maxLogoBytes+1))
	if err != nil {
		return nil, "", "", err
	}
	if len(b) > maxLogoBytes {
		return nil, "", "", fmt.Errorf("%s is larger than %d KiB", file, maxLogoBytes>>10)
	}
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		cfg, err := png.DecodeConfig(bytes.NewReader(b))
		if err != nil {
			return nil, "", "", fmt.Errorf("not a valid PNG: %w", err)
		}
		if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxLogoPixels || cfg.Height > maxLogoPixels {
			return nil, "", "", fmt.Errorf("a PNG logo is at most %dx%d pixels, this is %dx%d", maxLogoPixels, maxLogoPixels, cfg.Width, cfg.Height)
		}
		return b, "image/png", ".png", nil
	default:
		if err := checkSVG(b); err != nil {
			return nil, "", "", fmt.Errorf("a logo is a PNG or a plain SVG: %w", err)
		}
		return b, "image/svg+xml", ".svg", nil
	}
}

// svgElements is what a logo may contain: shapes, groups, gradients, clips.
// No script, no style sheet, no foreignObject, no text (a font is not ours to
// pick), no image or filter that could name another resource.
var svgElements = map[string]bool{
	"svg": true, "g": true, "defs": true, "path": true, "circle": true, "ellipse": true,
	"rect": true, "line": true, "polyline": true, "polygon": true, "lineargradient": true,
	"radialgradient": true, "stop": true, "clippath": true, "mask": true, "title": true,
	"desc": true, "use": true, "symbol": true,
}

// checkSVG refuses an SVG that is anything but a drawing. The logo is served
// as an image from this origin, where a script could not run, and with a
// sandboxing CSP when opened directly; this is the third layer, and the one
// that keeps the file an honest logo.
func checkSVG(b []byte) error {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	d.Entity = nil
	root := false
	depth := 0
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("not well-formed SVG: %w", err)
		}
		switch t := t.(type) {
		case xml.Directive:
			return errors.New("a DOCTYPE or entity declaration is not allowed")
		case xml.ProcInst:
			if t.Target != "xml" {
				return fmt.Errorf("the processing instruction <?%s?> is not allowed", t.Target)
			}
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if !root {
				if name != "svg" {
					return errors.New("the root element is not <svg>")
				}
				root = true
			}
			if !svgElements[name] {
				return fmt.Errorf("the element <%s> is not allowed", t.Name.Local)
			}
			depth++
			for _, a := range t.Attr {
				an := strings.ToLower(a.Name.Local)
				if strings.HasPrefix(an, "on") {
					return fmt.Errorf("the event attribute %q is not allowed", a.Name.Local)
				}
				v := strings.ToLower(strings.TrimSpace(a.Value))
				if an == "href" && !strings.HasPrefix(v, "#") {
					return errors.New("an href other than #id is not allowed")
				}
				if strings.Contains(v, "javascript:") || strings.Contains(v, "@import") || strings.Contains(v, "expression(") {
					return fmt.Errorf("the attribute %q is not allowed", a.Name.Local)
				}
				for rest := v; ; {
					i := strings.Index(rest, "url(")
					if i < 0 {
						break
					}
					rest = strings.TrimLeft(rest[i+4:], " '\"")
					if !strings.HasPrefix(rest, "#") {
						return errors.New("a url() other than #id is not allowed")
					}
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	if !root || depth != 0 {
		return errors.New("no <svg> document")
	}
	return nil
}

// ---- the colour ----

type rgb struct{ r, g, b float64 } // 0..255

func parseHex(s string) (rgb, error) {
	if len(s) != 7 || s[0] != '#' {
		return rgb{}, fmt.Errorf("%q is not a colour: #rrggbb, six hexadecimal digits", s)
	}
	v, err := hex.DecodeString(s[1:])
	if err != nil {
		return rgb{}, fmt.Errorf("%q is not a colour: #rrggbb, six hexadecimal digits", s)
	}
	return rgb{float64(v[0]), float64(v[1]), float64(v[2])}, nil
}

func (c rgb) hex() string {
	return fmt.Sprintf("#%02x%02x%02x", clamp8(c.r), clamp8(c.g), clamp8(c.b))
}

func clamp8(v float64) int { return int(math.Max(0, math.Min(255, math.Round(v)))) }

// luminance is WCAG 2.x relative luminance.
func (c rgb) luminance() float64 {
	f := func(v float64) float64 {
		v /= 255
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*f(c.r) + 0.7152*f(c.g) + 0.0722*f(c.b)
}

func contrast(a, b rgb) float64 {
	la, lb := a.luminance(), b.luminance()
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// mix is c moved t of the way to o.
func mix(c, o rgb, t float64) rgb {
	return rgb{c.r + (o.r-c.r)*t, c.g + (o.g-c.g)*t, c.b + (o.b-c.b)*t}
}

var (
	white = rgb{255, 255, 255}
	black = rgb{0, 0, 0}
	// The lightest dark surface and the page behind the light ones: a text
	// colour is judged against the worse of each scheme's backgrounds.
	darkRaised = rgb{0x24, 0x2b, 0x34}
)

// legibleOn moves c toward the extreme (black or white) until it reads at the
// contrast ratio on bg, and returns it unchanged when it already does.
func legibleOn(c, bg, toward rgb, ratio float64) rgb {
	for i := 0; i <= 100 && contrast(c, bg) < ratio; i++ {
		c = mix(c, toward, 0.04)
	}
	return c
}

// brandCSS is brand.css: the accent for both colour schemes, as four custom
// properties each. Everything is computed from the three bytes of a validated
// colour, so the text is #rrggbb four times over and nothing else.
//
//	--brand       the fill of a button
//	--brand-on    the text on that fill, white or black, whichever is legible
//	--brand-hover the fill under the pointer
//	--brand-ink   the accent as text, a link or a focus ring, on the page
//
// WCAG AA: 4.5:1 for text. The ink is held to 4.8:1 against white (light) or
// the raised dark surface (dark), the worst backgrounds it meets.
func brandCSS(accent rgb) string {
	fill := accent
	on := white
	if contrast(fill, black) > contrast(fill, white) {
		on = black
	}
	hover := mix(fill, black, 0.14)
	if on == black {
		hover = mix(fill, white, 0.14)
	}
	lightInk := legibleOn(accent, white, black, 4.8)
	darkInk := legibleOn(accent, darkRaised, white, 4.8)
	// In the dark scheme the button keeps the accent, and the hover is the
	// lighter step so it stays distinguishable from the surface.
	darkHover := mix(fill, white, 0.14)
	if on == black {
		darkHover = mix(fill, white, 0.22)
	}
	var sb strings.Builder
	w := func(sel string, f, o, h, i rgb) {
		fmt.Fprintf(&sb, "%s{--brand:%s;--brand-on:%s;--brand-hover:%s;--brand-ink:%s}\n", sel, f.hex(), o.hex(), h.hex(), i.hex())
	}
	w(":root", fill, on, hover, lightInk)
	sb.WriteString("@media (prefers-color-scheme:dark){\n")
	w(":root", fill, on, darkHover, darkInk)
	sb.WriteString("}\n")
	return sb.String()
}

// ---- serving ----

// asset serves what the pages link: the stylesheet, brand.css and the logo,
// each under a name that carries its hash, so it may be cached for good.
func (s *server) asset(w http.ResponseWriter, r *http.Request) {
	a, ok := s.cfg.brandView().assets[r.PathValue("name")]
	if !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.typ)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if r.Method == http.MethodGet {
		w.Write(a.body)
	}
}
