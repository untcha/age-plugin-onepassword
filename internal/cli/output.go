package cli

import (
	"fmt"
	"io"
	"os"
)

// writeOutput writes text to stdout, or to a new file (never overwritten) with mode 0600.
func writeOutput(path string, stdout io.Writer, text string) error {
	if path == "" || path == "-" {
		_, err := io.WriteString(stdout, text)
		return err
	}
	//nolint:gosec // G304: output path is the user's -o argument.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	if _, err := io.WriteString(f, text); err != nil {
		_ = f.Close()
		_ = os.Remove(path) // all-or-nothing: don't leave a partial file, and unblock a retry.
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
