package identity_test

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/charmbracelet/log"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword/fake"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

func newDecoder(t *testing.T, c *fake.Client) *identity.Decoder {
	t.Helper()
	return identity.NewDecoder(t.Context(), c, log.New(io.Discard))
}

func defaultIdentity(t *testing.T, d *identity.Decoder) age.Identity {
	t.Helper()
	id, err := d.Decode(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDefaultTargeted(t *testing.T) {
	for _, target := range []testutil.Key{testutil.Ed25519(t), testutil.RSA(t)} {
		t.Run(target.PublicKey.Type(), func(t *testing.T) {
			c := &fake.Client{Keys: []fake.Key{
				testutil.Ed25519(t).FakeKey("v1", "Private", "other1", "other ed25519"),
				target.FakeKey("v1", "Private", "target", "target"),
				testutil.RSA(t).FakeKey("v2", "Work", "other2", "other rsa"),
			}}
			stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
			got, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, testutil.FileKey()) {
				t.Fatalf("file key = %x", got)
			}
			if want := []string{"list", "private v1/target"}; !slices.Equal(c.Calls(), want) {
				t.Fatalf("calls = %v, want %v", c.Calls(), want)
			}
		})
	}
}

func TestDefaultNoSSHStanza(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	c := &fake.Client{}
	_, err = defaultIdentity(t, newDecoder(t, c)).Unwrap(testutil.Wrap(t, testutil.FileKey(), x.Recipient()))
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want ErrIncorrectIdentity", err)
	}
	if len(c.Calls()) != 0 {
		t.Fatalf("calls = %v, want none", c.Calls())
	}
}

func TestDefaultNoMatch(t *testing.T) {
	c := &fake.Client{Keys: []fake.Key{testutil.Ed25519(t).FakeKey("v1", "Private", "other", "other")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), testutil.Ed25519(t).Recipient)
	_, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas)
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want ErrIncorrectIdentity", err)
	}
	if n := c.Count("private"); n != 0 {
		t.Fatalf("private key reads = %d, want 0", n)
	}
}

func TestDefaultCollision(t *testing.T) {
	target := testutil.Ed25519(t)
	impostor := testutil.Ed25519(t).FakeKey("v1", "Private", "impostor", "impostor")
	impostor.Item.Fingerprint = target.Fingerprint() // same tag, different key
	c := &fake.Client{Keys: []fake.Key{impostor, target.FakeKey("v1", "Private", "target", "target")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
	if _, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas); err != nil {
		t.Fatal(err)
	}
	want := []string{"list", "private v1/impostor", "private v1/target"}
	if !slices.Equal(c.Calls(), want) {
		t.Fatalf("calls = %v, want %v", c.Calls(), want)
	}
}

func TestDefaultBadItemsSkipped(t *testing.T) {
	target := testutil.Ed25519(t)
	var bad []fake.Key
	for i, fp := range []string{"", "garbage", "SHA256:xx"} {
		k := testutil.Ed25519(t).FakeKey("v1", "Private", "bad"+string(rune('a'+i)), "bad")
		k.Item.Fingerprint = fp
		bad = append(bad, k)
	}
	c := &fake.Client{Keys: append(bad, target.FakeKey("v1", "Private", "target", "target"))}
	stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
	if _, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas); err != nil {
		t.Fatal(err)
	}
	if n := c.Count("private"); n != 1 {
		t.Fatalf("private key reads = %d, want 1", n)
	}
}

func TestDefaultLocked(t *testing.T) {
	c := &fake.Client{Err: errors.New("account is not signed in")}
	stanzas := testutil.Wrap(t, testutil.FileKey(), testutil.Ed25519(t).Recipient)
	_, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas)
	if err == nil || errors.Is(err, age.ErrIncorrectIdentity) || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("err = %v, want fatal error mentioning 'not signed in'", err)
	}
}

func TestDefaultMultiRecipient(t *testing.T) {
	target := testutil.Ed25519(t)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	c := &fake.Client{Keys: []fake.Key{target.FakeKey("v1", "Private", "target", "target")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), x.Recipient(), target.Recipient)
	if _, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas); err != nil {
		t.Fatal(err)
	}
	if n := c.Count("private"); n != 1 {
		t.Fatalf("private key reads = %d, want 1", n)
	}
}

func TestDefaultCachePerDecoder(t *testing.T) {
	target := testutil.Ed25519(t)
	c := &fake.Client{Keys: []fake.Key{target.FakeKey("v1", "Private", "target", "target")}}
	d := newDecoder(t, c)
	for range 2 {
		stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
		if _, err := defaultIdentity(t, d).Unwrap(stanzas); err != nil {
			t.Fatal(err)
		}
	}
	if n := c.Count("private"); n != 1 {
		t.Fatalf("private key reads = %d, want 1", n)
	}
}

func TestDefaultUnparseableMatchedKey(t *testing.T) {
	target := testutil.Ed25519(t)
	k := target.FakeKey("v1", "Private", "target", "target")
	k.PrivateKey = []byte("not a key")
	c := &fake.Client{Keys: []fake.Key{k}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
	_, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas)
	if err == nil || errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want fatal parse error", err)
	}
}

func TestDecodeInvalidPayload(t *testing.T) {
	if _, err := newDecoder(t, &fake.Client{}).Decode([]byte{9}); err == nil {
		t.Fatal("expected error")
	}
}
