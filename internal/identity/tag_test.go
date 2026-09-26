package identity_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

// stanzaTag returns the tag age itself writes for k.
func stanzaTag(t *testing.T, k testutil.Key) string {
	t.Helper()
	return testutil.Wrap(t, testutil.FileKey(), k.Recipient)[0].Args[0]
}

func TestTagFromFingerprint(t *testing.T) {
	ed := testutil.Ed25519(t)
	rsaKey := testutil.RSA(t)
	tests := []struct {
		name    string
		fp      string
		want    string
		wantErr bool
	}{
		{name: "ed25519", fp: ed.Fingerprint(), want: stanzaTag(t, ed)},
		{name: "rsa", fp: rsaKey.Fingerprint(), want: stanzaTag(t, rsaKey)},
		{name: "missing prefix", fp: strings.TrimPrefix(ed.Fingerprint(), "SHA256:"), wantErr: true},
		{name: "bad base64", fp: "SHA256:!!!!", wantErr: true},
		{name: "wrong length", fp: "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte("short")), wantErr: true},
		{name: "empty", fp: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identity.TagFromFingerprint(tt.fp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("tag = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTagFromPubKey(t *testing.T) {
	for _, k := range []testutil.Key{testutil.Ed25519(t), testutil.RSA(t)} {
		if got, want := identity.TagFromPubKey(k.PublicKey), stanzaTag(t, k); got != want {
			t.Errorf("%s: tag = %q, want %q", k.PublicKey.Type(), got, want)
		}
	}
}

func TestStanzaTags(t *testing.T) {
	ed := testutil.Ed25519(t)
	rsaKey := testutil.RSA(t)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	fk := testutil.FileKey()
	tests := []struct {
		name    string
		stanzas []*age.Stanza
		want    []string
	}{
		{"ed25519", testutil.Wrap(t, fk, ed.Recipient), []string{stanzaTag(t, ed)}},
		{"rsa", testutil.Wrap(t, fk, rsaKey.Recipient), []string{stanzaTag(t, rsaKey)}},
		{
			"mixed",
			testutil.Wrap(t, fk, x.Recipient(), ed.Recipient, rsaKey.Recipient),
			[]string{stanzaTag(t, ed), stanzaTag(t, rsaKey)},
		},
		{"x25519 only", testutil.Wrap(t, fk, x.Recipient()), nil},
		{"grease", []*age.Stanza{{Type: "x-grease", Args: []string{"abc"}}}, nil},
		{"ssh without args", []*age.Stanza{{Type: "ssh-ed25519"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identity.StanzaTags(tt.stanzas)
			if len(got) != len(tt.want) {
				t.Fatalf("tags = %v, want %v", got, tt.want)
			}
			for _, w := range tt.want {
				if !got[w] {
					t.Errorf("missing tag %q in %v", w, got)
				}
			}
		})
	}
}
