// Package plugin runs the age plugin protocol for this binary.
package plugin

import (
	"fmt"
	"io"

	"filippo.io/age"
	ageplugin "filippo.io/age/plugin"
)

// IdentityDecoder turns an identity payload into an age.Identity.
type IdentityDecoder func(data []byte) (age.Identity, error)

// Run executes the age plugin state machine and returns the process exit code.
// Only identity-v1 is supported: encryption uses plain SSH recipients.
func Run(name, stateMachine string, decode IdentityDecoder, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if stateMachine != "identity-v1" {
		return 1, fmt.Errorf("unsupported age plugin state machine %q: "+
			"encrypt with an ssh-ed25519 or ssh-rsa recipient (age -r) instead", stateMachine)
	}
	p, err := ageplugin.New(name)
	if err != nil {
		return 1, fmt.Errorf("init age plugin: %w", err)
	}
	p.SetIO(stdin, stdout, stderr)
	p.HandleIdentity(decode)
	return p.IdentityV1(), nil
}
