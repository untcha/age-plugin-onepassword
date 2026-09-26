// Package cli implements the age-plugin-onepassword command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"

	"github.com/untcha/age-plugin-onepassword/internal/appmeta"
	"github.com/untcha/age-plugin-onepassword/internal/config"
	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
	"github.com/untcha/age-plugin-onepassword/internal/plugin"
)

const long = `age-plugin-onepassword decrypts age files encrypted to SSH keys stored in 1Password.
It reads only the one private key a file was encrypted to.

Encrypt with plain age and an SSH public key (no plugin needed):
  age -r "ssh-ed25519 AAAA…" -o secret.age secret.txt

Decrypt:
  age -d -j onepassword secret.age
  age -d -i op.id secret.age          # identity file from "identity"

Settings (env or $XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml):
  AGE_PLUGIN_ONEPASSWORD_VAULT, _ACCOUNT, _OP, _TIMEOUT, _LOG_FILE, _LOG_LEVEL`

// Options are the process-level dependencies. Zero values use os.Std* and the op CLI.
type Options struct {
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	NewClient func(cfg config.Config, logger *log.Logger) onepassword.Client
}

// exitCodeError carries a non-zero exit code from the age plugin protocol.
type exitCodeError int

func (e exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", int(e))
}

type app struct {
	opts       Options
	configPath string
	debug      bool
	agePlugin  string
}

// Execute runs the CLI with args and returns the process exit code.
func Execute(ctx context.Context, args []string, opts Options) int {
	opts = opts.withDefaults()
	if args == nil {
		args = []string{} // cobra falls back to os.Args on nil
	}
	root := newRootCmd(opts)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	var code exitCodeError
	switch {
	case errors.As(err, &code):
		return int(code)
	case err != nil:
		fmt.Fprintf(opts.Stderr, "age-plugin-onepassword: %v\n", err)
		return 1
	default:
		return 0
	}
}

func (o Options) withDefaults() Options {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.NewClient == nil {
		o.NewClient = newOpClient
	}
	return o
}

func newRootCmd(opts Options) *cobra.Command {
	a := &app{opts: opts}
	cmd := &cobra.Command{
		Use:           "age-plugin-onepassword",
		Short:         "age plugin for SSH keys stored in 1Password",
		Long:          long,
		Version:       appmeta.String(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          a.runRoot,
	}
	cmd.SetIn(opts.Stdin)
	cmd.SetOut(opts.Stdout)
	cmd.SetErr(opts.Stderr)
	cmd.SetVersionTemplate("age-plugin-onepassword {{.Version}}\n")
	pf := cmd.PersistentFlags()
	pf.StringVar(
		&a.configPath,
		"config",
		"",
		"config file (default $XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml)",
	)
	pf.BoolVar(&a.debug, "debug", false, "enable debug logging")
	cmd.Flags().StringVar(&a.agePlugin, "age-plugin", "", "age plugin state machine (set by age)")
	_ = cmd.Flags().MarkHidden("age-plugin")
	cmd.AddCommand(newIdentityCmd(a), newRecipientsCmd(a), newVersionCmd())
	return cmd
}

// runRoot is plugin mode when age passes --age-plugin, help otherwise.
func (a *app) runRoot(cmd *cobra.Command, _ []string) error {
	if a.agePlugin == "" {
		return cmd.Help()
	}
	cfg, logger, closeLog, err := a.setup(true)
	if err != nil {
		// Setup failed before the plugin protocol ever started: age would
		// just see stdout close and report an opaque "failed to read line:
		// EOF". Run the protocol anyway with a decoder that always fails, so
		// age reports err as a proper identity error. There is no usable
		// logger here (that's part of what failed), so nothing is logged.
		return runPlugin(a.agePlugin, setupErrorDecoder(err), a.opts)
	}
	defer closeLog()
	logger.Debug("age plugin session", "state_machine", a.agePlugin, "version", appmeta.Version)
	dec := identity.NewDecoder(cmd.Context(), a.opts.NewClient(cfg, logger), logger)
	if err := runPlugin(a.agePlugin, dec.Decode, a.opts); err != nil {
		if code, ok := errors.AsType[exitCodeError](err); ok {
			logger.Error("age plugin exited", "code", int(code))
		}
		// Any other error is logged by the caller: Execute prints it once to
		// stderr, and logging it here too would duplicate it when
		// AGEDEBUG=plugin sends this logger's output to stderr as well.
		return err
	}
	return nil
}

// setupErrorDecoder is an IdentityDecoder that always fails with err. Used
// when plugin setup itself failed, so age still gets a proper identity error
// instead of a closed pipe.
func setupErrorDecoder(err error) plugin.IdentityDecoder {
	return func([]byte) (age.Identity, error) {
		return nil, fmt.Errorf("age-plugin-onepassword: %w", err)
	}
}

// runPlugin runs the age plugin protocol and turns a non-zero exit code into
// an exitCodeError.
func runPlugin(stateMachine string, decode plugin.IdentityDecoder, opts Options) error {
	code, err := plugin.Run(identity.PluginName, stateMachine, decode, opts.Stdin, opts.Stdout, opts.Stderr)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCodeError(code)
	}
	return nil
}

// setup loads config and builds the logger.
//
// CLI mode logs to log_file if set, else stderr. In plugin mode age discards
// plugin stderr unless AGEDEBUG=plugin, so logs go to log_file if set, plus
// stderr at debug level when AGEDEBUG=plugin, else nowhere.
func (a *app) setup(pluginMode bool) (config.Config, *log.Logger, func(), error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	ageDebug := pluginMode && os.Getenv("AGEDEBUG") == "plugin"
	if a.debug || ageDebug {
		cfg.LogLevel = log.DebugLevel
	}
	var writers []io.Writer
	closeLog := func() {}
	if cfg.LogFile != "" {
		//nolint:gosec // G304: log path is user configuration.
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return config.Config{}, nil, nil, fmt.Errorf("open log file: %w", err)
		}
		writers = append(writers, f)
		closeLog = func() { _ = f.Close() }
	}
	if ageDebug || (!pluginMode && cfg.LogFile == "") {
		writers = append(writers, a.opts.Stderr)
	}
	w := io.Discard
	if len(writers) > 0 {
		w = io.MultiWriter(writers...)
	}
	logger := log.NewWithOptions(w, log.Options{
		Level:           cfg.LogLevel,
		ReportTimestamp: true,
		Prefix:          "age-plugin-onepassword",
	})
	return cfg, logger, closeLog, nil
}

func newOpClient(cfg config.Config, logger *log.Logger) onepassword.Client {
	return onepassword.NewOpClient(onepassword.OpOptions{
		Bin:     cfg.OpPath,
		Vault:   cfg.Vault,
		Account: cfg.Account,
		Timeout: cfg.Timeout,
		Logger:  logger,
	})
}
