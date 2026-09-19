package gitcmd_test

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.admiral.io/bundle"
	"go.admiral.io/bundle/gitcmd"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, name, data string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
}

// A root in a repository pins a sibling module at an older commit of the
// same repository, by ssh URL to an origin nobody can reach. Nothing is
// cloned: the object store has it (D29).
func TestSameRepositoryPin(t *testing.T) {
	repo := t.TempDir()
	git(t, repo, "init", "-q", "-b", "main")
	write(t, repo, "modules/np/main.tf", `module "meta" { source = "../metadata" }`)
	write(t, repo, "modules/metadata/main.tf", `# metadata v1`)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "init")
	first := git(t, repo, "rev-parse", "HEAD")
	git(t, repo, "remote", "add", "origin", "git@github.com:acme/infra.git")

	write(t, repo, "modules/metadata/main.tf", `# metadata v2`)
	root := filepath.Join(repo, "projects/x")
	write(t, root, "main.tf", `module "np" { source = "git::ssh://git@github.com/acme/infra.git//modules/np?ref=`+first+`" }`)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "second")

	local := gitcmd.DescribeRepo(context.Background(), root)
	require.NotNil(t, local)
	assert.Equal(t, "github.com/acme/infra", local.Key)

	p, err := bundle.PackContext(context.Background(), root, bundle.Options{Git: &gitcmd.Transport{Repo: local}})
	require.NoError(t, err)
	prefix := "vendor/github.com/acme/infra/" + first[:12]
	assert.Equal(t, []bundle.Vendored{
		{Caller: ".", Source: "git::ssh://git@github.com/acme/infra.git//modules/np?ref=" + first, Into: prefix + "/modules/np"},
		{Caller: prefix + "/modules/np", Source: "../metadata", Into: prefix + "/modules/metadata"},
	}, p.Vendored)
	assert.Equal(t, []bundle.Pin{{Source: "git::ssh://git@github.com/acme/infra.git", Constraint: first, Resolved: first}}, p.Pins)
}

func TestCloneWithTheBinary(t *testing.T) {
	upstream := t.TempDir()
	git(t, upstream, "init", "-q", "-b", "main")
	write(t, upstream, "main.tf", `# a`)
	git(t, upstream, "add", ".")
	git(t, upstream, "commit", "-q", "-m", "init")
	git(t, upstream, "tag", "v1.0.0")
	sha := git(t, upstream, "rev-parse", "HEAD")

	u, _ := url.Parse("file://" + upstream + "?ref=v1.0.0")
	dst := filepath.Join(t.TempDir(), "clone")
	got, err := (&gitcmd.Transport{}).Clone(context.Background(), u, "v1.0.0", dst, nil)
	require.NoError(t, err)
	assert.Equal(t, sha, got)
	assert.FileExists(t, filepath.Join(dst, "main.tf"))
}

// Each family goes to the scheme it fits, through the environment, and is
// undone afterwards.
func TestCredentialPresentation(t *testing.T) {
	tr := &gitcmd.Transport{Scratch: t.TempDir()}
	parse := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err)
		return u
	}
	// Clone against an unreachable URL: what matters is the environment at
	// the moment git runs, which the failure message carries no trace of,
	// so the presentation is checked through the exported seam indirectly:
	// a family that cannot ride the scheme is refused before git runs.
	_, err := tr.Clone(context.Background(), parse("ssh://git@github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&bundle.Credential{Basic: &bundle.BasicAuth{Username: "u", Password: "p"}})
	assert.ErrorIs(t, err, bundle.ErrCredentialFamily, "basic auth cannot ride ssh")
	_, err = tr.Clone(context.Background(), parse("https://github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&bundle.Credential{SSHKey: &bundle.SSHKey{PEM: []byte("k")}})
	assert.ErrorIs(t, err, bundle.ErrCredentialFamily, "an ssh key cannot ride https")
	_, err = tr.Clone(context.Background(), parse("ssh://git@github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&bundle.Credential{SSHKey: &bundle.SSHKey{PEM: []byte("k"), Passphrase: "x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "passphrase")
	assert.Empty(t, os.Getenv("GIT_SSH_COMMAND"), "nothing leaks past a refusal")
	assert.Empty(t, os.Getenv("GIT_CONFIG_COUNT"))
}
