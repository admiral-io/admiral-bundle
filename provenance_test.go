package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDescribe(t *testing.T) {
	assert.Equal(t, Provenance{}, Describe(t.TempDir()), "not a repository: nothing, honestly")

	repo, _ := gitRepo(t, map[string]string{"modules/net/main.tf": ""})
	addRemote(t, openRepo(t, repo), "origin", "git@github.com:acme/infra.git")
	dir := filepath.Join(repo, "modules", "net")

	p := Describe(dir)
	assert.Equal(t, "git@github.com:acme/infra.git", p.URI)
	assert.Len(t, p.Commit, 40)
	assert.Equal(t, "modules/net", p.Path)
	assert.False(t, p.Dirty)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte("# changed"), 0o644))
	assert.True(t, Describe(dir).Dirty, "uncommitted changes under the component")
	assert.Empty(t, Describe(repo).Path, "the root's path is empty")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "README.md"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(""), 0o644))
	assert.False(t, Describe(dir).Dirty, "a change elsewhere in the repository is not the component's")
}
