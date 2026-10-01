package onepassword

import "strings"

// opHints maps phrases in op's stderr to an actionable hint, checked in order.
// "authorization prompt dismissed" is verified against op 2.39.0; the other
// phrases follow op's usual messages and are unverified — see
// docs/manual-verification.md.
var opHints = []struct {
	phrases []string
	hint    string
}{
	{
		[]string{"authorization prompt dismissed"},
		"approve the 1Password prompt to continue",
	},
	{
		[]string{"not currently signed in", "account is not signed in", "session expired"},
		"sign in with `op signin` or unlock the 1Password app",
	},
	{
		[]string{"desktop app"},
		"start and unlock the 1Password app and enable Settings → Developer → Integrate with 1Password CLI",
	},
	{
		[]string{"no such host", "TLS handshake", "connection refused", "network is unreachable", "i/o timeout"},
		"check your network connection to 1Password",
	},
}

// hintFor returns a hint for op's stderr, or "" if no phrase matches.
func hintFor(stderr string) string {
	for _, h := range opHints {
		for _, p := range h.phrases {
			if strings.Contains(stderr, p) {
				return h.hint
			}
		}
	}
	return ""
}
