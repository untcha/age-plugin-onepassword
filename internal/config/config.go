// Package config resolves runtime settings from env vars and an optional YAML
// file. age starts the plugin without user flags, so plugin-mode settings can
// only come from here.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
)

// EnvPrefix prefixes every env var, e.g. AGE_PLUGIN_ONEPASSWORD_VAULT.
const EnvPrefix = "AGE_PLUGIN_ONEPASSWORD"

// Config is the resolved configuration.
type Config struct {
	Vault    string        // limit key search to this vault
	Account  string        // op --account
	OpPath   string        // op binary
	Timeout  time.Duration // per op call
	LogFile  string        // log destination; empty = default for the mode
	LogLevel log.Level
}

// DefaultPath returns $XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml,
// falling back to ~/.config when XDG_CONFIG_HOME is unset.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "age-plugin-onepassword", "config.yaml"), nil
}

// Load resolves env > file > defaults. A non-empty path must exist; the
// default path is optional.
func Load(path string) (Config, error) {
	v := viper.New()
	v.SetDefault("vault", "")
	v.SetDefault("account", "")
	v.SetDefault("op", "op")
	v.SetDefault("timeout", "2m")
	v.SetDefault("log_file", "")
	v.SetDefault("log_level", "info")
	v.SetEnvPrefix(EnvPrefix)
	v.AutomaticEnv()

	if err := readFile(v, path); err != nil {
		return Config{}, err
	}

	timeout, err := time.ParseDuration(v.GetString("timeout"))
	if err != nil || timeout <= 0 {
		return Config{}, fmt.Errorf(
			"config: invalid timeout %q (want a positive duration like 2m)",
			v.GetString("timeout"),
		)
	}
	level, err := parseLevel(v.GetString("log_level"))
	if err != nil {
		return Config{}, err
	}
	opPath, err := resolvePath("op", v.GetString("op"), true)
	if err != nil {
		return Config{}, err
	}
	logFile, err := resolvePath("log_file", v.GetString("log_file"), false)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Vault:    v.GetString("vault"),
		Account:  v.GetString("account"),
		OpPath:   opPath,
		Timeout:  timeout,
		LogFile:  logFile,
		LogLevel: level,
	}, nil
}

func readFile(v *viper.Viper, path string) error {
	explicit := path != ""
	if !explicit {
		p, err := DefaultPath()
		if err != nil {
			return nil // no home directory: run without a config file
		}
		path = p
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return nil
		}
		return fmt.Errorf("config: %w", err)
	}
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	return nil
}

// resolvePath expands a leading "~/" and rejects other relative paths: age runs
// plugins with the temp dir as working directory, so they would silently
// resolve there. allowBare permits a bare command name looked up via PATH.
func resolvePath(key, p string, allowBare bool) (string, error) {
	if p == "" || filepath.IsAbs(p) {
		return p, nil
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config: %s: %w", key, err)
		}
		return filepath.Join(home, rest), nil
	}
	if allowBare && !strings.ContainsRune(p, filepath.Separator) {
		return p, nil
	}
	return "", fmt.Errorf("config: %s %q must be absolute or start with ~/", key, p)
}

func parseLevel(s string) (log.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return log.DebugLevel, nil
	case "info":
		return log.InfoLevel, nil
	case "warn":
		return log.WarnLevel, nil
	case "error":
		return log.ErrorLevel, nil
	default:
		return 0, fmt.Errorf("config: invalid log_level %q (want debug, info, warn or error)", s)
	}
}
