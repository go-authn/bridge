package app

import "unicode"

// displayNameRuneBad reports a character a display name may not hold. The name
// reaches the "name" claim and every page that shows it, so beyond control
// characters it refuses what changes how the text around it reads or hides
// that text: bidirectional controls (a name that reorders what follows it, or
// the rest of a line), line and paragraph separators, and invisible
// characters that make two different names look alike. The zero-width joiner
// and non-joiner stay: scripts such as Devanagari and Persian need them.
func displayNameRuneBad(r rune) bool {
	switch {
	case unicode.IsControl(r):
		return true
	case r == 0x200E, r == 0x200F, r == 0x061C: // LRM, RLM, Arabic letter mark
		return true
	case r >= 0x202A && r <= 0x202E: // embeddings and overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // isolates
		return true
	case r == 0x2028, r == 0x2029: // line and paragraph separator
		return true
	case r == 0x200B, r == 0x2060, r == 0xFEFF, r == 0x00AD: // invisible
		return true
	}
	return false
}
