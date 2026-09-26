package appmeta

import "testing"

func TestString(t *testing.T) {
	want := "dev (commit unknown, built unknown)"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
