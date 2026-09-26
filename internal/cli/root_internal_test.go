package cli

import (
	"errors"
	"strings"
	"testing"
)

// TestSetupErrorDecoder covers F1: when plugin-mode setup fails, the plugin
// still speaks the age protocol via a decoder that always fails, so age
// reports a proper identity error instead of an opaque EOF.
func TestSetupErrorDecoder(t *testing.T) {
	cause := errors.New("config: invalid timeout")
	decode := setupErrorDecoder(cause)

	id, err := decode([]byte("anything"))
	if id != nil {
		t.Fatalf("identity = %v, want nil", id)
	}
	if err == nil || !errors.Is(err, cause) || !strings.Contains(err.Error(), "age-plugin-onepassword:") {
		t.Fatalf("err = %v, want wrapped %v", err, cause)
	}
}
