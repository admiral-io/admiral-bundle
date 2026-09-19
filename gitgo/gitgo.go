// Package gitgo is the bundle's git transport in-process, with go-git, for
// an environment that has no git binary. Credentials are presented from the
// bundle.Credentials lookup, never from an agent or a helper, because a
// server has neither.
package gitgo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"

	"go.admiral.io/bundle"
)

// Transport clones with go-git.
type Transport struct {
	// HostKeyCallback verifies ssh hosts. Nil uses go-git's default, the
	// process's known_hosts, which a server may not have; it supplies a
	// callback over the host keys it trusts instead.
	HostKeyCallback ssh.HostKeyCallback
	// Credentials answers for submodules. The credential Clone is handed
	// is the repository's own and is never forwarded to a submodule, whose
	// remote may be any host its .gitmodules names; each is looked up by
	// its own URL here. Nil fetches submodules anonymously.
	Credentials bundle.Credentials
}

// maxSubmoduleDepth is how far nested submodules are followed, go-git's
// own default.
const maxSubmoduleDepth = 10

// Clone implements bundle.GitTransport.
func (t *Transport) Clone(ctx context.Context, u *url.URL, ref, dst string, cred *bundle.Credential) (string, error) {
	remote := *u
	remote.RawQuery = "" // ref, depth and friends are go-getter's, not git's
	auth, err := t.auth(&remote, cred)
	if err != nil {
		return "", err
	}
	repo, err := git.PlainCloneContext(ctx, dst, false, &git.CloneOptions{
		URL:  remote.String(),
		Auth: auth,
		// Submodules are updated below, each with its own credential;
		// go-git would hand every one of them auth.
		RecurseSubmodules: git.NoRecurseSubmodules,
		Tags:              git.AllTags,
	})
	if err != nil {
		return "", fmt.Errorf("clone %s: %w", remote.Redacted(), err)
	}
	hash, err := resolve(repo, ref)
	if err != nil {
		return "", fmt.Errorf("%s: %w", remote.Redacted(), err)
	}
	if ref != "" {
		wt, err := repo.Worktree()
		if err != nil {
			return "", err
		}
		if err := wt.Checkout(&git.CheckoutOptions{Hash: *hash}); err != nil {
			return "", fmt.Errorf("checkout %s in %s: %w", ref, remote.Redacted(), err)
		}
	}
	if err := t.updateSubmodules(ctx, repo, maxSubmoduleDepth); err != nil {
		return "", fmt.Errorf("%s: %w", remote.Redacted(), err)
	}
	return hash.String(), nil
}

// updateSubmodules brings every submodule of repo to the commit the tree
// pins, presenting to each the credential its own URL resolves to, then
// does the same one level down.
func (t *Transport) updateSubmodules(ctx context.Context, repo *git.Repository, depth int) error {
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	subs, err := wt.Submodules()
	if err != nil {
		return err
	}
	if len(subs) == 0 {
		return nil
	}
	if depth == 0 {
		return fmt.Errorf("submodules nest deeper than %d", maxSubmoduleDepth)
	}
	for _, sub := range subs {
		// Init records the submodule in the parent's config; Repository
		// then creates its remote with the URL resolved the way git
		// resolves it, a relative one against the parent's.
		if err := sub.Init(); err != nil && !errors.Is(err, git.ErrSubmoduleAlreadyInitialized) {
			return fmt.Errorf("submodule %s: %w", sub.Config().Path, err)
		}
		subRepo, err := sub.Repository()
		if err != nil {
			return fmt.Errorf("submodule %s: %w", sub.Config().Path, err)
		}
		u, err := submoduleURL(subRepo)
		if err != nil {
			return fmt.Errorf("submodule %s: %w", sub.Config().Path, err)
		}
		var cred *bundle.Credential
		if t.Credentials != nil {
			if cred, err = t.Credentials.Lookup(ctx, u.String()); err != nil {
				return fmt.Errorf("submodule %s: %w", sub.Config().Path, err)
			}
		}
		auth, err := t.auth(u, cred)
		if err != nil {
			return fmt.Errorf("submodule %s: %w", sub.Config().Path, err)
		}
		if err := sub.UpdateContext(ctx, &git.SubmoduleUpdateOptions{
			Auth:              auth,
			RecurseSubmodules: git.NoRecurseSubmodules,
		}); err != nil {
			return fmt.Errorf("submodule %s (%s): %w", sub.Config().Path, u.Redacted(), err)
		}
		if err := t.updateSubmodules(ctx, subRepo, depth-1); err != nil {
			return err
		}
	}
	return nil
}

// submoduleURL is the URL go-git will fetch a submodule from, as a URL the
// credential seam can look up; the scp-like `git@host:path` is read as ssh.
func submoduleURL(repo *git.Repository) (*url.URL, error) {
	remote, err := repo.Remote(git.DefaultRemoteName)
	if err != nil {
		return nil, err
	}
	raw := remote.Config().URLs[0]
	if !strings.Contains(raw, "://") {
		if user, rest, ok := strings.Cut(raw, "@"); ok && !strings.Contains(user, "/") {
			if host, p, ok := strings.Cut(rest, ":"); ok && !strings.Contains(host, "/") {
				return &url.URL{Scheme: "ssh", User: url.User(user), Host: host, Path: "/" + p}, nil
			}
		}
		return &url.URL{Scheme: "file", Path: raw}, nil
	}
	return url.Parse(raw)
}

// resolve turns a ref into a commit: a full or short sha, a tag, a branch
// of the remote, or HEAD when empty.
func resolve(repo *git.Repository, ref string) (*plumbing.Hash, error) {
	if ref == "" {
		head, err := repo.Head()
		if err != nil {
			return nil, err
		}
		h := head.Hash()
		return &h, nil
	}
	for _, rev := range []string{ref, "origin/" + ref} {
		if h, err := repo.ResolveRevision(plumbing.Revision(rev)); err == nil {
			return h, nil
		}
	}
	return nil, fmt.Errorf("ref %q is not a commit, tag or branch of the repository", ref)
}

// auth presents the credential the way go-git takes it for the scheme.
func (t *Transport) auth(u *url.URL, cred *bundle.Credential) (transport.AuthMethod, error) {
	ssh := u.Scheme == "ssh" || u.Scheme == "git+ssh"
	switch {
	case cred == nil:
		return nil, nil
	case cred.SSHKey != nil:
		if !ssh {
			return nil, fmt.Errorf("%w: ssh key to %s", bundle.ErrCredentialFamily, u.Redacted())
		}
		user := u.User.Username()
		if user == "" {
			user = "git"
		}
		keys, err := gitssh.NewPublicKeys(user, cred.SSHKey.PEM, cred.SSHKey.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("ssh key for %s: %w", u.Hostname(), err)
		}
		if t.HostKeyCallback != nil {
			keys.HostKeyCallback = t.HostKeyCallback
		}
		return keys, nil
	case cred.Basic != nil:
		if ssh {
			return nil, fmt.Errorf("%w: basic auth to %s", bundle.ErrCredentialFamily, u.Redacted())
		}
		return &githttp.BasicAuth{Username: cred.Basic.Username, Password: cred.Basic.Password}, nil
	case cred.Token != "":
		if ssh {
			return nil, fmt.Errorf("%w: bearer token to %s", bundle.ErrCredentialFamily, u.Redacted())
		}
		// GitHub and GitLab take a token as the basic password; an App's
		// installation token is presented as x-access-token.
		return &githttp.BasicAuth{Username: "x-access-token", Password: cred.Token}, nil
	default:
		return nil, nil
	}
}
