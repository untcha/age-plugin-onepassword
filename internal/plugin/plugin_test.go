package plugin_test

import (
	"io"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/untcha/age-plugin-onepassword/internal/plugin"
)

func TestRunUnsupportedStateMachine(t *testing.T) {
	decode := func([]byte) (age.Identity, error) { return nil, nil }
	code, err := plugin.Run("onepassword", "recipient-v1", decode, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || code == 0 || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("code = %d, err = %v", code, err)
	}
}
