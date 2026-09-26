package identity_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	ageplugin "filippo.io/age/plugin"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword/fake"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

func pinnedIdentity(t *testing.T, d *identity.Decoder, k testutil.Key, vaultID, itemID string) age.Identity {
	t.Helper()
	s, err := identity.EncodePinned(identity.Pin{VaultID: vaultID, ItemID: itemID, PubKey: k.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := ageplugin.ParseIdentity(s)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPinnedTagMismatch(t *testing.T) {
	pinned, other := testutil.Ed25519(t), testutil.Ed25519(t)
	c := &fake.Client{Keys: []fake.Key{pinned.FakeKey("v1", "Private", "a", "a")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), other.Recipient)
	_, err := pinnedIdentity(t, newDecoder(t, c), pinned, "v1", "a").Unwrap(stanzas)
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want ErrIncorrectIdentity", err)
	}
	if len(c.Calls()) != 0 {
		t.Fatalf("calls = %v, want none", c.Calls())
	}
}

func TestPinnedByID(t *testing.T) {
	for _, k := range []testutil.Key{testutil.Ed25519(t), testutil.RSA(t)} {
		c := &fake.Client{Keys: []fake.Key{k.FakeKey("v1", "Private", "a", "a")}}
		stanzas := testutil.Wrap(t, testutil.FileKey(), k.Recipient)
		got, err := pinnedIdentity(t, newDecoder(t, c), k, "v1", "a").Unwrap(stanzas)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, testutil.FileKey()) {
			t.Fatalf("file key = %x", got)
		}
		if want := []string{"private v1/a"}; !slices.Equal(c.Calls(), want) {
			t.Fatalf("calls = %v, want %v", c.Calls(), want)
		}
	}
}

func TestPinnedFallbackByFingerprint(t *testing.T) {
	k := testutil.Ed25519(t)
	c := &fake.Client{Keys: []fake.Key{k.FakeKey("v2", "Work", "fresh", "moved")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), k.Recipient)
	if _, err := pinnedIdentity(t, newDecoder(t, c), k, "v1", "stale").Unwrap(stanzas); err != nil {
		t.Fatal(err)
	}
	want := []string{"private v1/stale", "list", "private v2/fresh"}
	if !slices.Equal(c.Calls(), want) {
		t.Fatalf("calls = %v, want %v", c.Calls(), want)
	}
}

func TestPinnedFallbackMissing(t *testing.T) {
	k := testutil.Ed25519(t)
	c := &fake.Client{}
	stanzas := testutil.Wrap(t, testutil.FileKey(), k.Recipient)
	_, err := pinnedIdentity(t, newDecoder(t, c), k, "v1", "gone").Unwrap(stanzas)
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want ErrIncorrectIdentity", err)
	}
}

func TestPinnedPubKeyMismatch(t *testing.T) {
	pinned, other := testutil.Ed25519(t), testutil.Ed25519(t)
	k := pinned.FakeKey("v1", "Private", "a", "a")
	k.PrivateKey = other.PrivatePEM // item now holds a different key
	c := &fake.Client{Keys: []fake.Key{k}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), pinned.Recipient)
	_, err := pinnedIdentity(t, newDecoder(t, c), pinned, "v1", "a").Unwrap(stanzas)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v, want pubkey mismatch", err)
	}
}

func TestPinnedReadError(t *testing.T) {
	k := testutil.Ed25519(t)
	c := &fake.Client{Err: errors.New("account is not signed in")}
	stanzas := testutil.Wrap(t, testutil.FileKey(), k.Recipient)
	_, err := pinnedIdentity(t, newDecoder(t, c), k, "v1", "a").Unwrap(stanzas)
	if err == nil || errors.Is(err, age.ErrIncorrectIdentity) || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("err = %v, want fatal error mentioning 'not signed in'", err)
	}
}
