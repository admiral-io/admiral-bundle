package bundle

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

// Test repositories are made with go-git, like everything else here: the
// suite needs no git binary, and a machine whose git signs through a locked
// agent cannot hang it.

// gitRepo makes a repository with the given files committed on main, and
// returns its path and HEAD.
func gitRepo(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInitWithOptions(dir, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: plumbing.Main},
	})
	require.NoError(t, err)
	return dir, commitFiles(t, repo, files, "init")
}

// commitFiles writes files into the repository's worktree and commits them.
func commitFiles(t *testing.T, repo *git.Repository, files map[string]string, msg string) string {
	t.Helper()
	wt, err := repo.Worktree()
	require.NoError(t, err)
	root := wt.Filesystem.Root()
	for name, data := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
		_, err := wt.Add(filepath.ToSlash(name))
		require.NoError(t, err)
	}
	hash, err := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@t", When: time.Now()},
	})
	require.NoError(t, err)
	return hash.String()
}

// openRepo opens a fixture for further commits, tags and remotes.
func openRepo(t *testing.T, dir string) *git.Repository {
	t.Helper()
	repo, err := git.PlainOpen(dir)
	require.NoError(t, err)
	return repo
}

func addRemote(t *testing.T, repo *git.Repository, name, url string) {
	t.Helper()
	_, err := repo.CreateRemote(&config.RemoteConfig{Name: name, URLs: []string{url}})
	require.NoError(t, err)
}

func tagHead(t *testing.T, repo *git.Repository, name string) {
	t.Helper()
	head, err := repo.Head()
	require.NoError(t, err)
	_, err = repo.CreateTag(name, head.Hash(), nil)
	require.NoError(t, err)
}
