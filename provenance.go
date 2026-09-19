package bundle

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
)

// Provenance is what the working copy says about where it came from. It is
// an assertion the server records as such; the server decides the kind
// (local, for anything the CLI uploads) on its own.
type Provenance struct {
	// URI is the origin remote, when there is one, or the OCI repository
	// a pulled chart came from.
	URI string
	// Ref is the tag a pulled chart was asked for; git provenance leaves it
	// empty and says the commit.
	Ref string
	// Commit is HEAD, or the manifest digest of a pulled chart.
	Commit string
	// Path is the component's directory relative to the repository root.
	Path string
	// Dirty is true when the working copy has uncommitted changes anywhere
	// under the component.
	Dirty bool
}

// Describe reads git for the directory. A directory that is not in a
// repository, or a machine without git, yields an empty Provenance and no
// error: not knowing where bytes came from is allowed, lying about it is not.
func Describe(ctx context.Context, dir string) Provenance {
	var p Provenance
	git := func(args ...string) (string, bool) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(out)), true
	}

	top, ok := git("rev-parse", "--show-toplevel")
	if !ok {
		return p
	}
	if abs, err := filepath.Abs(dir); err == nil {
		if rel, err := filepath.Rel(top, abs); err == nil && rel != "." {
			p.Path = filepath.ToSlash(rel)
		}
	}
	p.Commit, _ = git("rev-parse", "HEAD")
	p.URI, _ = git("remote", "get-url", "origin")
	if status, ok := git("status", "--porcelain", "--", "."); ok {
		p.Dirty = status != ""
	}
	return p
}
