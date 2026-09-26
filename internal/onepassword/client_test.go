package onepassword_test

import (
	"strings"
	"testing"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

func TestValidID(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"abcdefghijklmnopqrstuvwxyz", true},
		{"ABC123", true},
		{strings.Repeat("a", 255), true},
		{"", false},
		{strings.Repeat("a", 256), false},
		{"a/b", false},
		{"a b", false},
		{"..", false},
		{"a?b", false},
	}
	for _, tt := range tests {
		if got := onepassword.ValidID(tt.in); got != tt.want {
			t.Errorf("ValidID(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseItemRef(t *testing.T) {
	tests := []struct {
		ref       string
		vault     string
		item      string
		wantError bool
	}{
		{ref: "op://Private/chezmoi-age", vault: "Private", item: "chezmoi-age"},
		{ref: "op://Private/My Key", vault: "Private", item: "My Key"},
		{ref: "Private/chezmoi-age", wantError: true},
		{ref: "op://Private", wantError: true},
		{ref: "op://Private/item/private key", wantError: true},
		{ref: "op:///item", wantError: true},
		{ref: "op://Private/", wantError: true},
	}
	for _, tt := range tests {
		vault, item, err := onepassword.ParseItemRef(tt.ref)
		if (err != nil) != tt.wantError {
			t.Fatalf("ParseItemRef(%q) err = %v, wantError %v", tt.ref, err, tt.wantError)
		}
		if vault != tt.vault || item != tt.item {
			t.Errorf("ParseItemRef(%q) = %q, %q; want %q, %q", tt.ref, vault, item, tt.vault, tt.item)
		}
	}
}
