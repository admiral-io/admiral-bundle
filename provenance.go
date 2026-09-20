package bundle

import (
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

// Provenance is what the working copy says about where it came from. It is
// an assertion, and a registry records it as one rather than a fact it
// verified.
type Provenance struct {
	// URI is the origin remote, when there is one, or the repository a
	// pulled artifact came from.
	URI string
	// Ref is what a pull asked for; git provenance leaves it empty and
	// says the commit.
	Ref string
	// Commit is HEAD, or what a pull resolved to.
	Commit string
	// Path is the component's directory relative to the repository root.
	Path string
	// Dirty is true when the working copy has uncommitted changes anywhere
	// under the component.
	Dirty bool
}

// Describe reads the repository holding dir. A directory that is not in
// one yields an empty Provenance and no error: not knowing where bytes
// came from is allowed, lying about it is not.
func Describe(dir string) Provenance {
	var p Provenance
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return p
	}
	wt, err := repo.Worktree()
	if err != nil {
		return p
	}
	top := wt.Filesystem.Root()
	// The tree root comes with every link resolved; the directory must be
	// spelled the same way or the two never meet.
	if abs, err := filepath.EvalSymlinks(dir); err == nil {
		if rel, err := filepath.Rel(top, abs); err == nil && rel != "." {
			p.Path = filepath.ToSlash(rel)
		}
	}
	if head, err := repo.Head(); err == nil {
		p.Commit = head.Hash().String()
	}
	if origin, err := repo.Remote("origin"); err == nil && len(origin.Config().URLs) > 0 {
		p.URI = origin.Config().URLs[0]
	}
	if status, err := wt.Status(); err == nil {
		prefix := ""
		if p.Path != "" {
			prefix = p.Path + "/"
		}
		for file, st := range status {
			if strings.HasPrefix(file, prefix) && (st.Worktree != git.Unmodified || st.Staging != git.Unmodified) {
				p.Dirty = true
				break
			}
		}
	}
	return p
}
