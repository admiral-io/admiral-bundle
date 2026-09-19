// Package gitcmd is the bundle's git transport over the git binary: what a
// developer's machine has, with its agent, credential helpers and insteadOf
// rules, and the checkout being published, which is read directly when a
// source names it. An environment without git uses gitgo.
package gitcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	getter "github.com/hashicorp/go-getter/v2"

	"go.admiral.io/bundle"
)

// Transport clones with go-getter's git getter, which runs `git`. When Repo
// is set, a source naming that repository is read from its object store
// instead of cloned: `git fetch origin <ref>` only when the object is
// absent, then `git archive`. That is what a root pinning its own
// sibling modules at a SHA looks like, and it needs no credential on a
// laptop or under actions/checkout.
type Transport struct {
	// Repo is the checkout being published, or nil to clone every source.
	Repo *LocalRepo
	// Scratch is where a credential's key file lives for the length of a
	// clone; the process temp directory when empty.
	Scratch string
}

// Clone implements bundle.GitTransport.
func (t *Transport) Clone(ctx context.Context, u *url.URL, ref, dst string, cred *bundle.Credential) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", errors.New("git is not on the PATH; the CLI clones module sources with it")
	}
	if err := checkRef(ref); err != nil {
		return "", err
	}
	if t.Repo != nil && t.Repo.Key == bundle.RepoKey(u) {
		return t.Repo.Archive(ctx, ref, dst)
	}
	// The credential is presented through the process environment, which
	// every clone in the process shares; one at a time.
	envMu.Lock()
	defer envMu.Unlock()
	restore, err := t.env(u, cred)
	if err != nil {
		return "", err
	}
	defer restore()

	client := &getter.Client{Getters: []getter.Getter{&getter.GitGetter{}}}
	req := &getter.Request{Src: "git::" + u.String(), Dst: dst, GetMode: getter.ModeDir}
	if _, err := client.Get(ctx, req); err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, "git", "-C", dst, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse in the clone of %s: %w", u.Redacted(), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// envMu serializes clones: the environment is process-wide, and two clones
// at once could present one repository's credential to the other.
var envMu sync.Mutex

// credentialHelper answers git's credential protocol from the environment,
// and only for the host the credential was issued to: a clone touches
// exactly one remote, but a submodule or a redirect could name another.
const credentialHelper = `!f() { h=; while read -r l; do case "$l" in host=*) h=${l#host=};; esac; done; [ "$h" = "$ADMIRAL_GIT_HOST" ] || exit 0; echo "username=$ADMIRAL_GIT_USERNAME"; echo "password=$ADMIRAL_GIT_PASSWORD"; }; f`

// env presents a credential to the git go-getter runs, which inherits this
// process's environment: an SSH key through GIT_SSH_COMMAND with the key in
// a file only this process can read, basic auth or a token through a
// credential helper that answers from the environment, never the command
// line, never the URL. The returned function undoes it. A nil credential
// leaves git to its own agent and helpers.
func (t *Transport) env(u *url.URL, cred *bundle.Credential) (func(), error) {
	none := func() {}
	if cred == nil {
		return none, nil
	}
	switch {
	case cred.SSHKey != nil:
		if u.Scheme != "ssh" {
			return none, fmt.Errorf("%w: ssh key to %s", bundle.ErrCredentialFamily, u.Redacted())
		}
		if cred.SSHKey.Passphrase != "" {
			// An encrypted key would prompt; publish is not interactive.
			return none, fmt.Errorf("ssh key for %s has a passphrase; decrypt it before registering it", u.Hostname())
		}
		key, err := os.CreateTemp(t.Scratch, "key-*")
		if err != nil {
			return none, err
		}
		if err := os.Chmod(key.Name(), 0o600); err != nil {
			return none, errors.Join(err, key.Close())
		}
		if _, err := key.Write(cred.SSHKey.PEM); err != nil {
			return none, errors.Join(err, key.Close())
		}
		if err := key.Close(); err != nil {
			return none, err
		}
		undo := setenv(map[string]string{
			"GIT_SSH_COMMAND": fmt.Sprintf("ssh -i %q -o IdentitiesOnly=yes -o BatchMode=yes", key.Name()),
		})
		return func() { undo(); os.Remove(key.Name()) }, nil
	case cred.Basic != nil:
		if u.Scheme != "https" && u.Scheme != "http" {
			return none, fmt.Errorf("%w: basic auth to %s", bundle.ErrCredentialFamily, u.Redacted())
		}
		return setenv(map[string]string{
			"GIT_CONFIG_COUNT":     "1",
			"GIT_CONFIG_KEY_0":     "credential.helper",
			"GIT_CONFIG_VALUE_0":   credentialHelper,
			"ADMIRAL_GIT_HOST":     u.Host,
			"ADMIRAL_GIT_USERNAME": cred.Basic.Username,
			"ADMIRAL_GIT_PASSWORD": cred.Basic.Password,
		}), nil
	case cred.Token != "":
		if u.Scheme != "https" && u.Scheme != "http" {
			return none, fmt.Errorf("%w: bearer token to %s", bundle.ErrCredentialFamily, u.Redacted())
		}
		// GitHub and GitLab take a token as the basic password; an App's
		// installation token is presented as x-access-token.
		return setenv(map[string]string{
			"GIT_CONFIG_COUNT":     "1",
			"GIT_CONFIG_KEY_0":     "credential.helper",
			"GIT_CONFIG_VALUE_0":   credentialHelper,
			"ADMIRAL_GIT_HOST":     u.Host,
			"ADMIRAL_GIT_USERNAME": "x-access-token",
			"ADMIRAL_GIT_PASSWORD": cred.Token,
		}), nil
	default:
		return none, nil
	}
}

// setenv sets variables and returns the function that restores them.
func setenv(kv map[string]string) func() {
	prev := map[string]*string{}
	for k, v := range kv {
		if old, ok := os.LookupEnv(k); ok {
			prev[k] = &old
		} else {
			prev[k] = nil
		}
		os.Setenv(k, v)
	}
	return func() {
		for k, old := range prev {
			if old == nil {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, *old)
			}
		}
	}
}

// LocalRepo is the checkout being published, for sources that name it.
type LocalRepo struct {
	// Top is the working tree's root.
	Top string
	// Key is bundle.RepoKeyOf(origin).
	Key string
}

// DescribeRepo finds the repository holding dir and its origin. No
// repository, no origin, or no git: nil, and every git source is cloned.
func DescribeRepo(ctx context.Context, dir string) *LocalRepo {
	git := func(args ...string) (string, bool) {
		out, err := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...).Output()
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(out)), true
	}
	top, ok := git("rev-parse", "--show-toplevel")
	if !ok {
		return nil
	}
	origin, ok := git("remote", "get-url", "origin")
	if !ok || origin == "" {
		return nil
	}
	key := bundle.RepoKeyOf(origin)
	if key == "" {
		return nil
	}
	return &LocalRepo{Top: top, Key: key}
}

// checkRef refuses a ref git could read as an option. The ref comes from a
// module source in the tree being published, which a pull request or a
// vendored module can write; `--upload-pack=<cmd>` handed to `git fetch`
// runs <cmd>. Every invocation below also ends its options before the ref,
// so this is the readable half of a two-part guard.
func checkRef(ref string) error {
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("%w: %q", bundle.ErrRefInvalid, ref)
	}
	return nil
}

// Archive writes the tree at ref into dst from the local object store,
// fetching the ref from origin only when the object is not already there,
// and returns the commit it resolved to.
func (r *LocalRepo) Archive(ctx context.Context, ref, dst string) (string, error) {
	if err := checkRef(ref); err != nil {
		return "", err
	}
	git := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", r.Top}, args...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(string(out)), nil
	}
	if ref == "" {
		// tofu clones the default branch; the nearest local reading of that
		// is origin's HEAD.
		ref = "refs/remotes/origin/HEAD"
	}
	sha, err := git("rev-parse", "--verify", "--quiet", "--end-of-options", ref+"^{commit}")
	if err != nil {
		if _, ferr := git("fetch", "--quiet", "origin", "--", ref); ferr != nil {
			return "", fmt.Errorf("%s is not in the local checkout and could not be fetched from origin: %w", ref, ferr)
		}
		if sha, err = git("rev-parse", "--verify", "--quiet", "FETCH_HEAD^{commit}"); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "git", "-C", r.Top, "archive", "--format=tar", "--end-of-options", sha)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	extractErr := bundle.Untar(out, dst)
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("git archive %s: %s", sha, strings.TrimSpace(stderr.String()))
	}
	if extractErr != nil {
		return "", extractErr
	}
	return sha, nil
}
