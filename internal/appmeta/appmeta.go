// Package appmeta holds build metadata, stamped via -ldflags by the Taskfile.
package appmeta

import (
	"fmt"
	"runtime/debug"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Builds via `go install module@version` carry no -ldflags, but Go embeds the
// module version in the binary. Use it when the Taskfile did not stamp one.
func init() {
	info, _ := debug.ReadBuildInfo()
	Version = resolveVersion(Version, info)
}

// resolveVersion returns the stamped version, falling back to the module
// version from the build info. "(devel)" means Go knows no version, e.g. a
// build with -buildvcs=false.
func resolveVersion(stamped string, info *debug.BuildInfo) string {
	if stamped != "dev" || info == nil {
		return stamped
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return stamped
}

// String returns a one-line version description.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
}
