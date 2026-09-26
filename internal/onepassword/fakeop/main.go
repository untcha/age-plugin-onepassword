// Command fakeop imitates the subset of the 1Password CLI used by OpClient.
// Test-only.
//
// Environment:
//
//	FAKEOP_DIR    fixtures: items.json and keys/<vaultID>/<itemID>/{private,public}
//	FAKEOP_LOG    append each invocation's arguments (space-joined) to this file
//	FAKEOP_FAIL   print this to stderr and exit 1
//	FAKEOP_SLEEP  sleep this duration before responding
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type item struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Vault    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	AdditionalInformation string `json:"additional_information,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if err := logCall(args); err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	if d, err := time.ParseDuration(os.Getenv("FAKEOP_SLEEP")); err == nil {
		time.Sleep(d)
	}
	if msg := os.Getenv("FAKEOP_FAIL"); msg != "" {
		fmt.Fprintf(stderr, "[ERROR] 2026/01/01 00:00:00 %s\n", msg)
		return 1
	}
	pos, flags := parseArgs(args)
	dir := os.Getenv("FAKEOP_DIR")
	switch {
	case len(pos) == 2 && pos[0] == "item" && pos[1] == "list":
		return itemList(dir, flags, stdout, stderr)
	case len(pos) == 3 && pos[0] == "item" && pos[1] == "get":
		return itemGet(dir, pos[2], flags["--vault"], stdout, stderr)
	case len(pos) == 2 && pos[0] == "read":
		return read(dir, pos[1], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "fakeop: unsupported command %q\n", args)
		return 2
	}
}

func logCall(args []string) error {
	p := os.Getenv("FAKEOP_LOG")
	if p == "" {
		return nil
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: test log path.
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, strings.Join(args, " "))
	return err
}

// parseArgs splits args into positionals and "--flag value" / "--flag=value" pairs.
func parseArgs(args []string) (pos []string, flags map[string]string) {
	flags = make(map[string]string)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			if name, val, ok := strings.Cut(a, "="); ok {
				flags[name] = val
				continue
			}
			if i+1 < len(args) {
				flags[a] = args[i+1]
				i++
				continue
			}
		}
		pos = append(pos, a)
	}
	return pos, flags
}

func itemList(dir string, flags map[string]string, stdout, stderr io.Writer) int {
	if flags["--categories"] != "SSH Key" || flags["--format"] != "json" {
		fmt.Fprintln(stderr, `fakeop: item list needs --categories "SSH Key" --format json`)
		return 2
	}
	raw, err := os.ReadFile(filepath.Join(dir, "items.json")) //nolint:gosec // G304: test fixture path.
	if err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	vault := flags["--vault"]
	if vault == "" {
		_, _ = stdout.Write(raw) // raw, so tests can serve malformed JSON
		return 0
	}
	var items, out []item
	if err := json.Unmarshal(raw, &items); err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	for _, it := range items {
		if it.Vault.ID == vault || it.Vault.Name == vault {
			out = append(out, it)
		}
	}
	if out == nil {
		out = []item{}
	}
	_ = json.NewEncoder(stdout).Encode(out)
	return 0
}

func itemGet(dir, ref, vault string, stdout, stderr io.Writer) int {
	raw, err := os.ReadFile(filepath.Join(dir, "items.json")) //nolint:gosec // G304: test fixture path.
	if err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	var items []item
	if err := json.Unmarshal(raw, &items); err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	for _, it := range items {
		if (it.Vault.ID == vault || it.Vault.Name == vault) && (it.ID == ref || it.Title == ref) {
			_ = json.NewEncoder(stdout).Encode(it)
			return 0
		}
	}
	fmt.Fprintf(stderr, "[ERROR] 2026/01/01 00:00:00 %q isn't an item in the %q vault. "+
		"Specify the item with its UUID, name, or domain.\n", ref, vault)
	return 1
}

func read(dir, ref string, stdout, stderr io.Writer) int {
	rest, ok := strings.CutPrefix(ref, "op://")
	path, query, _ := strings.Cut(rest, "?")
	parts := strings.Split(path, "/")
	if !ok || len(parts) != 3 {
		fmt.Fprintf(stderr, "fakeop: bad reference %q\n", ref)
		return 2
	}
	var file string
	switch parts[2] {
	case "private key":
		if query != "ssh-format=openssh" {
			fmt.Fprintln(stderr, "fakeop: private key read without ?ssh-format=openssh")
			return 2
		}
		file = "private"
	case "public key":
		file = "public"
	default:
		fmt.Fprintf(stderr, "fakeop: unsupported field %q\n", parts[2])
		return 2
	}
	keyFile := filepath.Join(dir, "keys", parts[0], parts[1], file)
	b, err := os.ReadFile(keyFile) //nolint:gosec // G304: test fixture path.
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(
			stderr,
			"[ERROR] 2026/01/01 00:00:00 could not read secret '%s': %q isn't an item in the %q vault\n",
			ref,
			parts[1],
			parts[0],
		)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	fmt.Fprintln(stdout, strings.TrimRight(string(b), "\n"))
	return 0
}
