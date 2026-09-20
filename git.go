package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"
)

// Git is the transport git sources are fetched with. It is go-git, in
// process: no git binary, so the same behavior on every platform and in a
// server image that carries none.
//
// Credentials come from the seam. With none, ssh uses the ssh agent
// (SSH_AUTH_SOCK) and https goes anonymous; a laptop cloning a private
// repository over https registers its token in ~/.netrc or
// ~/.git-credentials, which AmbientCredentials reads.
type Git struct {
	// HostKeyCallback verifies ssh hosts. Nil uses ~/.ssh/known_hosts, which
	// a developer has and a server does not; a server supplies the keys it
	// trusts.
	HostKeyCallback ssh.HostKeyCallback
	// Repo, when set, is the checkout being published: a source naming the
	// same repository is read from its object store, fetching from origin
	// only when the object is absent, and never cloned. That is what a root
	// pinning its own sibling modules at a SHA looks like, and it needs no
	// credential.
	Repo *LocalRepo
	// Credentials answers for submodules. The credential Clone is handed is
	// the repository's own and is never forwarded to a submodule, whose
	// remote may be any host its .gitmodules names; each is looked up by its
	// own URL here. Nil fetches submodules anonymously.
	Credentials Credentials
}

// maxSubmoduleDepth is how far nested submodules are followed, go-git's
// own default.
const maxSubmoduleDepth = 10

// Clone implements GitTransport.
func (g *Git) Clone(ctx context.Context, u *url.URL, ref, dst string, cred *Credential) (string, error) {
	if g.Repo != nil && g.Repo.Key == RepoKey(u) {
		return g.Repo.Archive(ctx, ref, dst)
	}
	remote := *u
	remote.RawQuery = "" // ref, depth and friends are go-getter's, not git's
	auth, err := g.auth(&remote, cred)
	if err != nil {
		return "", err
	}
	repo, err := git.PlainCloneContext(ctx, dst, false, &git.CloneOptions{
		URL:  remote.String(),
		Auth: auth,
		// Submodules are updated below, each with its own credential.
		RecurseSubmodules: git.NoRecurseSubmodules,
		Tags:              git.AllTags,
	})
	if err != nil {
		return "", fmt.Errorf("clone %s: %w", remote.Redacted(), err)
	}
	hash, err := resolveRef(repo, ref)
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
	if err := g.updateSubmodules(ctx, repo, maxSubmoduleDepth); err != nil {
		return "", fmt.Errorf("%s: %w", remote.Redacted(), err)
	}
	return hash.String(), nil
}

// updateSubmodules brings every submodule of repo to the commit the tree
// pins, presenting to each the credential its own URL resolves to, then
// does the same one level down.
func (g *Git) updateSubmodules(ctx context.Context, repo *git.Repository, depth int) error {
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
		var cred *Credential
		if g.Credentials != nil {
			if cred, err = g.Credentials.Lookup(ctx, u.String()); err != nil {
				return fmt.Errorf("submodule %s: %w", sub.Config().Path, err)
			}
		}
		auth, err := g.auth(u, cred)
		if err != nil {
			return fmt.Errorf("submodule %s: %w", sub.Config().Path, err)
		}
		if err := sub.UpdateContext(ctx, &git.SubmoduleUpdateOptions{
			Auth:              auth,
			RecurseSubmodules: git.NoRecurseSubmodules,
		}); err != nil {
			return fmt.Errorf("submodule %s (%s): %w", sub.Config().Path, u.Redacted(), err)
		}
		if err := g.updateSubmodules(ctx, subRepo, depth-1); err != nil {
			return err
		}
	}
	return nil
}

// submoduleURL is the URL go-git will fetch a submodule from, as a URL the
// credential seam can be asked about.
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

// resolveRef turns a ref into a commit: a full or short sha, a tag, a
// branch of the remote, or HEAD when empty.
func resolveRef(repo *git.Repository, ref string) (*plumbing.Hash, error) {
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
func (g *Git) auth(u *url.URL, cred *Credential) (transport.AuthMethod, error) {
	isSSH := u.Scheme == "ssh" || u.Scheme == "git+ssh"
	switch {
	case cred == nil:
		if isSSH {
			return g.agentAuth(u)
		}
		return nil, nil
	case cred.SSHKey != nil:
		if !isSSH {
			return nil, fmt.Errorf("%w: ssh key to %s", ErrCredentialFamily, u.Redacted())
		}
		keys, err := gitssh.NewPublicKeys(sshUser(u), cred.SSHKey.PEM, cred.SSHKey.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("ssh key for %s: %w", u.Hostname(), err)
		}
		if g.HostKeyCallback != nil {
			keys.HostKeyCallback = g.HostKeyCallback
		}
		return keys, nil
	case cred.Basic != nil:
		if isSSH {
			return nil, fmt.Errorf("%w: basic auth to %s", ErrCredentialFamily, u.Redacted())
		}
		return &githttp.BasicAuth{Username: cred.Basic.Username, Password: cred.Basic.Password}, nil
	case cred.Token != "":
		if isSSH {
			return nil, fmt.Errorf("%w: bearer token to %s", ErrCredentialFamily, u.Redacted())
		}
		// GitHub and GitLab take a token as the basic password; an App's
		// installation token is presented as x-access-token.
		return &githttp.BasicAuth{Username: "x-access-token", Password: cred.Token}, nil
	default:
		return nil, nil
	}
}

// agentAuth is the ssh agent, when there is one; without it ssh goes
// unauthenticated, which is what a public host over ssh wants and what a
// private one refuses with a clear message.
func (g *Git) agentAuth(u *url.URL) (transport.AuthMethod, error) {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return nil, nil
	}
	auth, err := gitssh.NewSSHAgentAuth(sshUser(u))
	if err != nil {
		return nil, fmt.Errorf("ssh agent: %w", err)
	}
	if g.HostKeyCallback != nil {
		auth.HostKeyCallback = g.HostKeyCallback
	}
	return auth, nil
}

func sshUser(u *url.URL) string {
	if u.User != nil && u.User.Username() != "" {
		return u.User.Username()
	}
	return "git"
}

// --- The checkout being published -------------------------------------------

// LocalRepo is the repository a directory being published sits in.
type LocalRepo struct {
	// Top is the working tree's root.
	Top string
	// Key is RepoKeyOf(origin), what a source naming this repository
	// matches on.
	Key  string
	repo *git.Repository
}

// OpenRepo finds the repository holding dir and its origin. No repository
// or no origin: nil, and every git source is cloned.
func OpenRepo(dir string) *LocalRepo {
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil
	}
	origin, err := repo.Remote("origin")
	if err != nil || len(origin.Config().URLs) == 0 {
		return nil
	}
	key := RepoKeyOf(origin.Config().URLs[0])
	if key == "" {
		return nil
	}
	return &LocalRepo{Top: wt.Filesystem.Root(), Key: key, repo: repo}
}

// Archive writes the tree at ref into dst from the local object store,
// fetching the ref from origin only when the object is not already there,
// and returns the commit it resolved to.
func (r *LocalRepo) Archive(ctx context.Context, ref, dst string) (string, error) {
	if ref == "" {
		// A clone would take the default branch; the nearest local reading
		// of that is origin's HEAD.
		ref = "refs/remotes/origin/HEAD"
	}
	hash, err := r.repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		if ferr := r.fetch(ctx, ref); ferr != nil {
			return "", fmt.Errorf("%s is not in the local checkout and could not be fetched from origin: %w", ref, ferr)
		}
		if hash, err = r.repo.ResolveRevision(plumbing.Revision(ref)); err != nil {
			return "", fmt.Errorf("%s is not in the local checkout: %w", ref, err)
		}
	}
	commit, err := r.repo.CommitObject(*hash)
	if err != nil {
		return "", fmt.Errorf("%s is not a commit: %w", ref, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return "", err
	}
	if err := writeTree(tree, dst); err != nil {
		return "", err
	}
	return hash.String(), nil
}

// fetch brings ref from origin: the ref itself when the server lets a
// bare commit be asked for, else every branch and tag, which is where a
// commit someone pinned is reachable from.
func (r *LocalRepo) fetch(ctx context.Context, ref string) error {
	auth := r.fetchAuth()
	exact := r.repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{config.RefSpec(ref + ":" + ref)},
		Tags:       git.NoTags,
		Auth:       auth,
	})
	if exact == nil || errors.Is(exact, git.NoErrAlreadyUpToDate) {
		return nil
	}
	all := r.repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{"+refs/heads/*:refs/remotes/origin/*"},
		Tags:       git.AllTags,
		Auth:       auth,
	})
	if all == nil || errors.Is(all, git.NoErrAlreadyUpToDate) {
		return nil
	}
	return errors.Join(exact, all)
}

// fetchAuth is the ssh agent for an ssh origin; https relies on what git
// stored, which go-git does not read, so a fetch there is anonymous.
func (r *LocalRepo) fetchAuth() transport.AuthMethod {
	origin, err := r.repo.Remote("origin")
	if err != nil || len(origin.Config().URLs) == 0 {
		return nil
	}
	raw := origin.Config().URLs[0]
	u, err := url.Parse(raw)
	isSSH := err == nil && (u.Scheme == "ssh" || u.Scheme == "git+ssh") || (err != nil || u.Scheme == "") && strings.Contains(raw, "@")
	if !isSSH || os.Getenv("SSH_AUTH_SOCK") == "" {
		return nil
	}
	auth, err := gitssh.NewSSHAgentAuth("git")
	if err != nil {
		return nil
	}
	return auth
}

// writeTree lays a git tree out on disk: files with their mode, symlinks
// as symlinks, submodule entries skipped.
func writeTree(tree *object.Tree, dst string) error {
	return tree.Files().ForEach(func(f *object.File) error {
		target := filepath.Join(dst, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		switch f.Mode {
		case filemode.Symlink:
			link, err := f.Contents()
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case filemode.Submodule:
			return nil
		}
		mode := os.FileMode(0o644)
		if f.Mode == filemode.Executable {
			mode = 0o755
		}
		rc, err := f.Reader()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			return errors.Join(err, out.Close())
		}
		return out.Close()
	})
}
