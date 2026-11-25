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
	"slices"
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
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
	pos, flags, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "[ERROR] 2026/01/01 00:00:00 %v\n", err)
		return 1
	}
	dir := os.Getenv("FAKEOP_DIR")
	switch {
	case len(pos) == 2 && pos[0] == "item" && pos[1] == "list":
		return itemList(dir, flags, stdout, stderr)
	case len(pos) == 3 && pos[0] == "item" && pos[1] == "get" && pos[2] == "-":
		return itemGetStdin(dir, flags, stdin, stdout, stderr)
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
// Like op, everything after "--" is positional, and a single-dash argument
// before it is an unknown shorthand flag.
func parseArgs(args []string) (pos []string, flags map[string]string, err error) {
	flags = make(map[string]string)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return append(pos, args[i+1:]...), flags, nil
		case strings.HasPrefix(a, "--"):
			if name, val, ok := strings.Cut(a, "="); ok {
				flags[name] = val
				continue
			}
			if i+1 < len(args) {
				flags[a] = args[i+1]
				i++
				continue
			}
		case len(a) > 1 && a[0] == '-':
			return nil, nil, fmt.Errorf("unknown shorthand flag: '%c' in %s", a[1], a)
		}
		pos = append(pos, a)
	}
	return pos, flags, nil
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

// itemGetStdin imitates `op item get - --fields 'label=public key' --format json`
// as verified against op 2.42.0: stdin holds a JSON array of {"id", "vault": {"id"}};
// stdout gets one indented JSON object per item, not an array; an unknown item
// fails the call after the items before it were printed.
func itemGetStdin(dir string, flags map[string]string, stdin io.Reader, stdout, stderr io.Writer) int {
	if flags["--fields"] != "label=public key" || flags["--format"] != "json" {
		fmt.Fprintln(stderr, "fakeop: item get - needs --fields label=public key --format json")
		return 2
	}
	raw, err := os.ReadFile(filepath.Join(dir, "items.json")) //nolint:gosec // G304: test fixture path.
	if err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	var items, refs []item
	if err := json.Unmarshal(raw, &items); err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	if err := json.NewDecoder(stdin).Decode(&refs); err != nil {
		fmt.Fprintln(stderr, "fakeop: stdin:", err)
		return 2
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	for i, ref := range refs {
		idx := slices.IndexFunc(items, func(it item) bool {
			return it.ID == ref.ID && (ref.Vault.ID == "" || it.Vault.ID == ref.Vault.ID)
		})
		var pub []byte
		if idx >= 0 {
			keyFile := filepath.Join(dir, "keys", ref.Vault.ID, ref.ID, "public")
			pub, err = os.ReadFile(keyFile) //nolint:gosec // G304: test fixture path.
		}
		if idx < 0 || err != nil {
			fmt.Fprintf(stderr, "[ERROR] 2026/01/01 00:00:00 unable to process element %d: %q isn't an item. "+
				"Specify the item with its UUID, name, or domain.\n", i+1, ref.ID)
			return 1
		}
		it := items[idx]
		_ = enc.Encode(map[string]string{
			"id":        "public_key",
			"type":      "STRING",
			"label":     "public key",
			"value":     strings.TrimRight(string(pub), "\n"),
			"reference": "op://" + it.Vault.Name + "/" + it.Title + "/public key",
		})
	}
	return 0
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
