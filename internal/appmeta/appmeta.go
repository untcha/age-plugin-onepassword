// Package appmeta holds build metadata, stamped via -ldflags by the Taskfile.
package appmeta

import "fmt"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String returns a one-line version description.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
}
