package gitgo_test

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
	"go.admiral.io/bundle/gitgo"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

func TestCloneInProcess(t *testing.T) {
	upstream := t.TempDir()
	git(t, upstream, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(upstream, "main.tf"), []byte("# v1"), 0o644))
	git(t, upstream, "add", ".")
	git(t, upstream, "commit", "-q", "-m", "one")
	first := git(t, upstream, "rev-parse", "HEAD")
	git(t, upstream, "tag", "v1.0.0")
	git(t, upstream, "checkout", "-q", "-b", "feature")
	require.NoError(t, os.WriteFile(filepath.Join(upstream, "main.tf"), []byte("# feature"), 0o644))
	git(t, upstream, "commit", "-q", "-am", "two")
	second := git(t, upstream, "rev-parse", "HEAD")
	git(t, upstream, "checkout", "-q", "main")

	tr := &gitgo.Transport{}
	u, _ := url.Parse("file://" + upstream)
	clone := func(ref string) (string, string) {
		dst := filepath.Join(t.TempDir(), "clone")
		sha, err := tr.Clone(context.Background(), u, ref, dst, nil)
		require.NoError(t, err, ref)
		b, err := os.ReadFile(filepath.Join(dst, "main.tf"))
		require.NoError(t, err)
		return sha, string(b)
	}
	sha, content := clone("")
	assert.Equal(t, first, sha, "default branch")
	assert.Equal(t, "# v1", content)
	sha, _ = clone("v1.0.0")
	assert.Equal(t, first, sha, "a tag")
	sha, content = clone("feature")
	assert.Equal(t, second, sha, "a branch that is not the default")
	assert.Equal(t, "# feature", content)
	sha, _ = clone(second)
	assert.Equal(t, second, sha, "a sha")
	sha, _ = clone(second[:8])
	assert.Equal(t, second, sha, "a short sha")

	_, err := tr.Clone(context.Background(), u, "nope", filepath.Join(t.TempDir(), "x"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `ref "nope"`)
}

func TestAuthFamilies(t *testing.T) {
	tr := &gitgo.Transport{}
	parse := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err)
		return u
	}
	_, err := tr.Clone(context.Background(), parse("ssh://git@github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&bundle.Credential{Basic: &bundle.BasicAuth{Username: "u", Password: "p"}})
	assert.ErrorIs(t, err, bundle.ErrCredentialFamily)
	_, err = tr.Clone(context.Background(), parse("https://github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&bundle.Credential{SSHKey: &bundle.SSHKey{PEM: []byte("k")}})
	assert.ErrorIs(t, err, bundle.ErrCredentialFamily)
	_, err = tr.Clone(context.Background(), parse("ssh://git@github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&bundle.Credential{SSHKey: &bundle.SSHKey{PEM: []byte("not a key")}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh key for github.com")
}

// recordingCredentials answers nothing and remembers what it was asked for.
type recordingCredentials struct{ asked []string }

func (r *recordingCredentials) Lookup(_ context.Context, rawURL string) (*bundle.Credential, error) {
	r.asked = append(r.asked, rawURL)
	return nil, nil
}

// A repository's submodules are fetched with a credential looked up for
// each submodule's own URL. The credential the clone itself was handed is
// never forwarded: a .gitmodules can name any host.
func TestSubmodulesGetTheirOwnCredential(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	git(t, sub, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(sub, "main.tf"), []byte("# sub"), 0o644))
	git(t, sub, "add", ".")
	git(t, sub, "commit", "-q", "-m", "sub")

	parent := filepath.Join(base, "parent")
	require.NoError(t, os.MkdirAll(parent, 0o755))
	git(t, parent, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(parent, "main.tf"), []byte(`module "s" { source = "./vendor/sub" }`), 0o644))
	// A relative submodule URL, resolved against the parent's remote the
	// way git does it; the parent's own remote is where it is cloned from.
	git(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "../sub", "vendor/sub")
	git(t, parent, "add", ".")
	git(t, parent, "commit", "-q", "-m", "parent")

	creds := &recordingCredentials{}
	tr := &gitgo.Transport{Credentials: creds}
	u, _ := url.Parse("file://" + parent)
	dst := filepath.Join(t.TempDir(), "clone")
	_, err := tr.Clone(context.Background(), u, "", dst, &bundle.Credential{Token: "parent-only"})
	require.NoError(t, err)

	b, err := os.ReadFile(filepath.Join(dst, "vendor", "sub", "main.tf"))
	require.NoError(t, err, "the submodule is checked out")
	assert.Equal(t, "# sub", string(b))
	require.Len(t, creds.asked, 1, "one submodule, one lookup")
	assert.Equal(t, "file://"+sub, creds.asked[0], "asked by the submodule's URL, not the parent's")
}
