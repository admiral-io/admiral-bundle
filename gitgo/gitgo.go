// Package gitgo is the bundle's git transport in-process, with go-git. It
// is the platform's transport: the platform's image carries no git binary,
// and a binary that parses hostile remote data does not belong in the pod
// holding the tenant credential. Credentials are presented from the seam,
// never from an agent or a helper, because a server has neither.
package gitgo

import (
	"context"
	"fmt"
	"net/url"

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
	// process's known_hosts, which a server image does not have; the
	// platform supplies a callback over the host keys it trusts.
	HostKeyCallback ssh.HostKeyCallback
}

// Clone implements bundle.GitTransport.
func (t *Transport) Clone(ctx context.Context, u *url.URL, ref, dst string, cred *bundle.Credential) (string, error) {
	remote := *u
	remote.RawQuery = "" // ref, depth and friends are go-getter's, not git's
	auth, err := t.auth(&remote, cred)
	if err != nil {
		return "", err
	}
	repo, err := git.PlainCloneContext(ctx, dst, false, &git.CloneOptions{
		URL:               remote.String(),
		Auth:              auth,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
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
	return hash.String(), nil
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
