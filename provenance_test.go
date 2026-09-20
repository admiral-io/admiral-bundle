package bundle

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDescribe(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, Provenance{}, Describe(ctx, t.TempDir()), "not a repository: nothing, honestly")

	repo := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	run("init", "-q", "-b", "main")
	run("remote", "add", "origin", "git@github.com:acme/infra.git")
	dir := filepath.Join(repo, "modules", "net")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(""), 0o644))
	run("add", ".")
	run("commit", "-q", "-m", "init")

	p := Describe(ctx, dir)
	assert.Equal(t, "git@github.com:acme/infra.git", p.URI)
	assert.Len(t, p.Commit, 40)
	assert.Equal(t, "modules/net", p.Path)
	assert.False(t, p.Dirty)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte("# changed"), 0o644))
	assert.True(t, Describe(ctx, dir).Dirty, "uncommitted changes under the component")
	assert.Empty(t, Describe(ctx, repo).Path, "the root's path is empty")
}
