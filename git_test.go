package bundle

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitClonesAtTagBranchAndSha(t *testing.T) {
	upstream, first := gitRepo(t, map[string]string{"main.tf": "# v1"})
	repo := openRepo(t, upstream)
	tagHead(t, repo, "v1.0.0")
	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("feature"), Create: true}))
	second := commitFiles(t, repo, map[string]string{"main.tf": "# feature"}, "two")
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.Main}))

	tr := &Git{}
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

	_, err = tr.Clone(context.Background(), u, "nope", filepath.Join(t.TempDir(), "x"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `ref "nope"`)
}

func TestGitAuthFamilies(t *testing.T) {
	tr := &Git{}
	parse := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err)
		return u
	}
	_, err := tr.Clone(context.Background(), parse("ssh://git@github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&Credential{Basic: &BasicAuth{Username: "u", Password: "p"}})
	assert.ErrorIs(t, err, ErrCredentialFamily, "basic auth cannot ride ssh")
	_, err = tr.Clone(context.Background(), parse("https://github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&Credential{SSHKey: &SSHKey{PEM: []byte("k")}})
	assert.ErrorIs(t, err, ErrCredentialFamily, "an ssh key cannot ride https")
	_, err = tr.Clone(context.Background(), parse("ssh://git@github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"),
		&Credential{SSHKey: &SSHKey{PEM: []byte("not a key")}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh key for github.com")

	// Nothing to present and no agent: the error names the host, not a
	// socket.
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err = tr.Clone(context.Background(), parse("ssh://git@github.com/acme/infra.git"), "", filepath.Join(t.TempDir(), "x"), nil)
	assert.ErrorIs(t, err, ErrNoSSHCredential)
	assert.Contains(t, err.Error(), "github.com")
}

// A root in a repository pins a sibling module at an older commit of the
// same repository, by ssh URL to an origin nobody can reach. Nothing is
// cloned: the object store has it.
func TestSameRepositoryPinReadsTheObjectStore(t *testing.T) {
	repoDir, first := gitRepo(t, map[string]string{
		"modules/np/main.tf":       `module "meta" { source = "../metadata" }`,
		"modules/metadata/main.tf": `# metadata v1`,
	})
	repo := openRepo(t, repoDir)
	addRemote(t, repo, "origin", "git@github.com:acme/infra.git")
	root := filepath.Join(repoDir, "projects/x")
	commitFiles(t, repo, map[string]string{
		"modules/metadata/main.tf": `# metadata v2`,
		"projects/x/main.tf":       `module "np" { source = "git::ssh://git@github.com/acme/infra.git//modules/np?ref=` + first + `" }`,
	}, "second")

	local := OpenRepo(root)
	require.NotNil(t, local)
	assert.Equal(t, "github.com/acme/infra", local.Key)

	p, err := PackContext(context.Background(), root, Options{Git: &Git{Repo: local}})
	require.NoError(t, err)
	prefix := "vendor/github.com/acme/infra/" + first[:12]
	assert.Equal(t, []Vendored{
		{Caller: ".", Source: "git::ssh://git@github.com/acme/infra.git//modules/np", Into: prefix + "/modules/np"},
		{Caller: prefix + "/modules/np", Source: "../metadata", Into: prefix + "/modules/metadata"},
	}, p.Vendored)
	assert.Equal(t, []Pin{{Source: "git::ssh://git@github.com/acme/infra.git", Constraint: first, Resolved: first}}, p.Pins)
	files := entries(t, p.Bytes)
	assert.Equal(t, "# metadata v1", files[prefix+"/modules/metadata/main.tf"], "the pinned commit, not HEAD")
}

// A pin the checkout does not have yet is fetched from origin, once.
func TestSameRepositoryPinFetchesWhatIsMissing(t *testing.T) {
	originDir, first := gitRepo(t, map[string]string{"modules/a/main.tf": "# a"})
	checkout := t.TempDir()
	_, err := git.PlainClone(checkout, false, &git.CloneOptions{URL: originDir})
	require.NoError(t, err)
	second := commitFiles(t, openRepo(t, originDir), map[string]string{"modules/a/main.tf": "# a2"}, "later")

	local := OpenRepo(checkout)
	require.NotNil(t, local)
	dst := filepath.Join(t.TempDir(), "tree")
	sha, err := local.Archive(context.Background(), second, dst)
	require.NoError(t, err)
	assert.Equal(t, second, sha)
	b, err := os.ReadFile(filepath.Join(dst, "modules/a/main.tf"))
	require.NoError(t, err)
	assert.Equal(t, "# a2", string(b))

	sha, err = local.Archive(context.Background(), first, filepath.Join(t.TempDir(), "old"))
	require.NoError(t, err)
	assert.Equal(t, first, sha)
	_, err = local.Archive(context.Background(), "0000000000000000000000000000000000000000", filepath.Join(t.TempDir(), "none"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in the local checkout")
}

// recordingCredentials answers nothing and remembers what it was asked.
type recordingCredentials struct{ asked []string }

func (r *recordingCredentials) Lookup(_ context.Context, rawURL string) (*Credential, error) {
	r.asked = append(r.asked, rawURL)
	return nil, nil
}

// The parent's credential is never forwarded to a submodule; each is looked
// up by its own URL. The fixture needs a git binary to add a submodule, the
// one thing go-git cannot author, so the test skips without one.
func TestSubmodulesGetTheirOwnCredential(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git binary to author a submodule fixture with")
	}
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, append([]string{"-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always", "-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	base := t.TempDir()
	sub, _ := gitRepo(t, map[string]string{"main.tf": "# sub"})
	parent := filepath.Join(base, "parent")
	require.NoError(t, os.MkdirAll(parent, 0o755))
	run(parent, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(parent, "main.tf"), []byte(`module "s" { source = "./vendor/sub" }`), 0o644))
	run(parent, "submodule", "add", "-q", sub, "vendor/sub")
	run(parent, "add", ".")
	run(parent, "commit", "-q", "-m", "parent")

	creds := &recordingCredentials{}
	tr := &Git{Credentials: creds}
	u, _ := url.Parse("file://" + parent)
	dst := filepath.Join(t.TempDir(), "clone")
	_, err = tr.Clone(context.Background(), u, "", dst, &Credential{Token: "parent-only"})
	require.NoError(t, err)

	b, err := os.ReadFile(filepath.Join(dst, "vendor", "sub", "main.tf"))
	require.NoError(t, err, "the submodule is checked out")
	assert.Equal(t, "# sub", string(b))
	require.Len(t, creds.asked, 1, "one submodule, one lookup")
	assert.Equal(t, "file://"+sub, creds.asked[0], "asked by the submodule's URL, not the parent's")
}
