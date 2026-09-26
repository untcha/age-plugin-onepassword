package testutil

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// FakeOpPackage is the import path of the fake op binary.
const FakeOpPackage = "github.com/untcha/age-plugin-onepassword/internal/onepassword/fakeop"

// OpItem is one SSH Key item in a fake op fixture directory.
type OpItem struct {
	Key         Key
	VaultID     string
	VaultName   string
	ItemID      string
	Title       string
	Fingerprint string // empty: derived from Key
}

// WriteFakeOpDir writes items.json and key files for fakeop and returns the directory.
func WriteFakeOpDir(t testing.TB, items ...OpItem) string {
	t.Helper()
	dir := t.TempDir()
	list := make([]map[string]any, 0, len(items))
	for _, it := range items {
		fp := it.Fingerprint
		if fp == "" {
			fp = it.Key.Fingerprint()
		}
		list = append(list, map[string]any{
			"id":                     it.ItemID,
			"title":                  it.Title,
			"category":               "SSH_KEY",
			"vault":                  map[string]string{"id": it.VaultID, "name": it.VaultName},
			"additional_information": fp,
		})
		keyDir := filepath.Join(dir, "keys", it.VaultID, it.ItemID)
		if err := os.MkdirAll(keyDir, 0o750); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(keyDir, "private"), it.Key.PrivatePEM)
		writeFile(t, filepath.Join(keyDir, "public"), []byte(it.Key.AuthorizedKey))
	}
	b, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "items.json"), b)
	return dir
}

// Build compiles the Go package pkg into dir/name and returns the binary path.
func Build(dir, name, pkg string) (string, error) {
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg) //nolint:gosec // G204: test helper building known packages.
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build %s: %w\n%s", pkg, err, b)
	}
	return out, nil
}

// BuildFakeOp compiles fakeop into dir/op.
func BuildFakeOp(dir string) (string, error) {
	return Build(dir, "op", FakeOpPackage)
}

func writeFile(t testing.TB, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
