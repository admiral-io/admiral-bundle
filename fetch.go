package bundle

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	getter "github.com/hashicorp/go-getter/v2"
	"github.com/hashicorp/terraform-config-inspect/tfconfig"
	tfaddr "github.com/hashicorp/terraform-registry-address"
)

// Remote sources, the other half of closing a Terraform bundle (design
// section 7). A module call names one of three things, told apart in the
// order tofu's addrs.ParseModuleSource tells them apart: a local path
// (`./` or `../`), a registry address (`GoogleCloudPlatform/cloud-armor/
// google`, three or four slash-separated parts), or anything else, which
// go-getter reads: `git::ssh://…?ref=`, `github.com/org/repo//sub`,
// `https://host/x.zip`.
//
// A registry address resolves constraint to version against the registry,
// then the registry says where the bytes are, a go-getter address again. So
// every remote source ends as one fetch into a scratch tree: an archive
// downloaded here, a git repository cloned through a GitTransport.
//
// Fetched trees are placed in the bundle by identity (D30): the registry
// address and version, the repository and commit, the archive URL and
// digest. Two calls resolving to the same thing share one copy. What the
// walk copies is the directory the call names and whatever that directory
// reaches by relative path inside the same fetched tree; a path out of the
// tree is refused.

var (
	// ErrSourceUnsupported is a source go-getter has a getter for but the
	// CLI does not link: s3::, gcs::, hg::. Each is a separate module, added
	// when a repository needs it.
	ErrSourceUnsupported = errors.New("module source scheme is not supported; vendor it into the tree before publishing")
	// ErrSourceNonLiteral is a source read from a variable or a local.
	ErrSourceNonLiteral = errors.New("module source is not a literal string; the registry needs sources it can read")
	// ErrFetchedEscapes is a module inside a fetched tree calling a path
	// outside that tree, which no fetch of the tree could satisfy.
	ErrFetchedEscapes = errors.New("module source escapes the fetched tree")
	// ErrSubdirMissing is a `//subdir` the fetched tree does not contain.
	ErrSubdirMissing = errors.New("module subdirectory is not in the fetched tree")
)

type sourceKind int

const (
	sourceLocal sourceKind = iota
	sourceRegistry
	sourceRemote
	sourceNonLiteral
	sourceUnsupported
)

// classify tells the three source shapes apart, in tofu's order.
func classify(source string) (sourceKind, tfaddr.Module) {
	switch {
	case isLocalSource(source):
		return sourceLocal, tfaddr.Module{}
	case strings.HasPrefix(source, "var.") || strings.HasPrefix(source, "local.") ||
		strings.HasPrefix(source, "${"):
		return sourceNonLiteral, tfaddr.Module{}
	}
	if m, err := tfaddr.ParseModuleSource(source); err == nil {
		return sourceRegistry, m
	}
	if forced, _ := forcedGetter(source); forced != "" {
		switch forced {
		case "git", "http", "https", "file":
		default:
			return sourceUnsupported, tfaddr.Module{}
		}
	}
	return sourceRemote, tfaddr.Module{}
}

var forcedPattern = regexp.MustCompile(`^([A-Za-z0-9]+)::(.+)$`)

// forcedGetter splits go-getter's `scheme::rest` form.
func forcedGetter(source string) (string, string) {
	if m := forcedPattern.FindStringSubmatch(source); m != nil {
		return m[1], m[2]
	}
	return "", source
}

// GitTransport clones a repository. It is the one part of fetching that
// differs by host: the CLI runs the developer's git binary (gitcmd), which
// has their agent, helpers and insteadOf rules, and can read the checkout
// being published; the platform clones in-process with go-git (gitgo),
// because its image carries no git and a binary parsing hostile remote data
// does not belong in the pod holding the tenant credential.
type GitTransport interface {
	// Clone brings the repository at u, at ref (empty is the default branch),
	// into dst, which does not exist yet, and returns the commit it is at.
	// u still carries its query; a transport may honor go-getter's `depth`.
	// cred is what the credential seam gave for u, or nil.
	Clone(ctx context.Context, u *url.URL, ref, dst string, cred *Credential) (string, error)
}

// ErrNoGitTransport is a git source with no transport to fetch it.
var ErrNoGitTransport = errors.New("module source is a git repository and no git transport is configured")

// fetched is one remote tree on disk and where it goes in the bundle.
type fetched struct {
	// abs is the tree root on disk, in the fetcher's scratch directory.
	abs string
	// prefix is the bundle directory the tree root maps to.
	prefix string
	// pin is what resolving it recorded.
	pin Pin
}

// fetcher resolves and fetches remote module sources for one Pack.
type fetcher struct {
	dir      string
	registry *registryClient
	getter   *getter.Client
	http     *http.Client
	creds    Credentials
	git      GitTransport
	// trees dedups by identity: registry address+version, git URL+ref,
	// archive URL. The key is known before the fetch.
	trees map[string]*fetched
	// Pins, in resolution order.
	pins []Pin
	// n numbers scratch directories.
	n int
}

// newFetcher makes a fetcher whose scratch lives under dir.
func newFetcher(dir string, creds Credentials, git GitTransport) *fetcher {
	httpGetter := &getter.HttpGetter{
		Netrc:                 true,
		XTerraformGetDisabled: true,
		DoNotCheckHeadFirst:   true,
	}
	return &fetcher{
		dir:      dir,
		registry: newRegistryClient(creds),
		getter: &getter.Client{
			Getters: []getter.Getter{
				&getter.GitGetter{Detectors: []getter.Detector{
					new(getter.GitHubDetector),
					new(getter.GitDetector),
					new(getter.BitBucketDetector),
					new(getter.GitLabDetector),
				}},
				httpGetter,
				new(getter.FileGetter),
			},
			Decompressors: getter.Decompressors,
		},
		http:  &http.Client{Timeout: 5 * time.Minute},
		creds: creds,
		git:   git,
		trees: map[string]*fetched{},
	}
}

// resolve turns one non-local call into a fetched tree and the subdirectory
// of it the call names. A tree is fetched once per identity.
func (f *fetcher) resolve(ctx context.Context, call *tfconfig.ModuleCall) (*fetched, string, error) {
	kind, addr := classify(call.Source)
	switch kind {
	case sourceRegistry:
		return f.resolveRegistry(ctx, call, addr)
	case sourceRemote:
		return f.resolveRemote(ctx, call.Source)
	case sourceUnsupported:
		return nil, "", ErrSourceUnsupported
	case sourceNonLiteral:
		return nil, "", ErrSourceNonLiteral
	default:
		return nil, "", fmt.Errorf("%q is a local source", call.Source)
	}
}

func (f *fetcher) resolveRegistry(ctx context.Context, call *tfconfig.ModuleCall, addr tfaddr.Module) (*fetched, string, error) {
	pkg := addr.Package
	versions, err := f.registry.Versions(ctx, pkg)
	if err != nil {
		return nil, "", err
	}
	v, err := selectVersion(versions, call.Version)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", registryAddress(pkg), err)
	}
	key := "registry|" + registryAddress(pkg) + "|" + v.Original()
	if t, ok := f.trees[key]; ok {
		return t, addr.Subdir, nil
	}
	location, err := f.registry.Location(ctx, pkg, v)
	if err != nil {
		return nil, "", err
	}
	// The registry's answer may itself carry a subdirectory: the package
	// is the repository, the module is a directory in it.
	location, locSubdir := getter.SourceDirSubdir(location)
	abs, _, err := f.fetch(ctx, location)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", registryAddress(pkg), v, err)
	}
	t := &fetched{
		abs:    abs,
		prefix: path.Join(vendorDir, registryHost(pkg), pkg.ForRegistryProtocol(), v.Original()),
		pin:    Pin{Source: registryAddress(pkg), Constraint: call.Version, Resolved: v.Original()},
	}
	f.trees[key] = t
	f.pins = append(f.pins, t.pin)
	return t, path.Join(locSubdir, addr.Subdir), nil
}

func (f *fetcher) resolveRemote(ctx context.Context, source string) (*fetched, string, error) {
	base, subdir := getter.SourceDirSubdir(source)
	key := "remote|" + base
	if t, ok := f.trees[key]; ok {
		return t, subdir, nil
	}
	abs, t, err := f.fetch(ctx, base)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", source, err)
	}
	t.abs = abs
	f.trees[key] = t
	f.pins = append(f.pins, t.pin)
	return t, subdir, nil
}

// fetch brings one go-getter address (no subdirectory) into a fresh scratch
// directory and says what it is: the tree root, and its bundle prefix and
// pin. The address is detected first so `github.com/org/repo` and the
// scp-like `git@host:org/repo` become the URLs they mean.
func (f *fetcher) fetch(ctx context.Context, source string) (string, *fetched, error) {
	// go-getter treats an existing destination as a clone to update, so
	// the directory is named, not made.
	f.n++
	dst := filepath.Join(f.dir, fmt.Sprintf("tree-%d", f.n))

	req := &getter.Request{Src: source, Dst: dst, GetMode: getter.ModeDir}
	var matched getter.Getter
	for _, g := range f.getter.Getters {
		ok, err := getter.Detect(req, g)
		if err != nil {
			return "", nil, err
		}
		if ok {
			matched = g
			break
		}
	}
	if matched == nil {
		return "", nil, fmt.Errorf("%w: %s", ErrSourceUnsupported, source)
	}
	// Detection may have rewritten the source (shorthand to URL) and may
	// have found a subdirectory in the rewritten form; the caller split its
	// own already, so any left here is part of the address itself.
	detected, _ := getter.SourceDirSubdir(req.Src)
	u, err := url.Parse(detected)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", source, err)
	}

	switch matched.(type) {
	case *getter.GitGetter:
		return f.fetchGit(ctx, source, u, dst)
	case *getter.HttpGetter:
		return f.fetchArchive(ctx, source, u, dst)
	default:
		// file:// is a local directory; go-getter symlinks it unless told to
		// copy, and a symlinked scratch tree is not ours to walk.
		req.Src, req.Copy = u.String(), true
		if _, err := f.getter.Get(ctx, req); err != nil {
			return "", nil, err
		}
		return dst, &fetched{
			prefix: path.Join(vendorDir, "file", strings.TrimPrefix(filepath.ToSlash(filepath.Clean(u.Path)), "/")),
			pin:    Pin{Source: source},
		}, nil
	}
}

// fetchGit clones u at its ref through the transport. The pin resolves the
// ref to the commit.
func (f *fetcher) fetchGit(ctx context.Context, source string, u *url.URL, dst string) (string, *fetched, error) {
	if f.git == nil {
		return "", nil, fmt.Errorf("%w: %s", ErrNoGitTransport, source)
	}
	ref := u.Query().Get("ref")
	written, _, _ := strings.Cut(source, "?")
	var cred *Credential
	if f.creds != nil {
		var err error
		if cred, err = f.creds.Lookup(ctx, u.String()); err != nil {
			return "", nil, err
		}
	}
	sha, err := f.git.Clone(ctx, u, ref, dst, cred)
	if err != nil {
		return "", nil, err
	}
	if len(sha) < 12 {
		return "", nil, fmt.Errorf("git transport returned %q for %s, not a commit", sha, written)
	}
	return dst, &fetched{
		prefix: path.Join(vendorDir, RepoKey(u), sha[:12]),
		pin:    Pin{Source: written, Constraint: ref, Resolved: sha},
	}, nil
}

// fetchArchive downloads u, records its digest, and unpacks it by the
// extension or the `archive=` parameter, with go-getter's decompressors.
func (f *fetcher) fetchArchive(ctx context.Context, source string, u *url.URL, dst string) (string, *fetched, error) {
	q := u.Query()
	format := q.Get("archive")
	checksum := q.Get("checksum")
	q.Del("archive")
	q.Del("checksum")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "admiral-cli")
	if f.creds != nil {
		cred, err := f.creds.Lookup(ctx, u.String())
		if err != nil {
			return "", nil, err
		}
		if err := cred.authorize(req); err != nil {
			return "", nil, err
		}
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("GET %s: %s", u.Redacted(), resp.Status)
	}
	archive, err := os.CreateTemp(f.dir, "archive-*")
	if err != nil {
		return "", nil, err
	}
	defer os.Remove(archive.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(archive, h), resp.Body); err != nil {
		return "", nil, errors.Join(err, archive.Close())
	}
	if err := archive.Close(); err != nil {
		return "", nil, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if checksum != "" && !checksumMatches(checksum, digest) {
		return "", nil, fmt.Errorf("%s: checksum %q does not match the bytes (sha256:%s)", u.Redacted(), checksum, digest)
	}

	if format == "" {
		for k := range f.getter.Decompressors {
			if strings.HasSuffix(u.Path, "."+k) && len(k) > len(format) {
				format = k
			}
		}
	}
	d, ok := f.getter.Decompressors[format]
	if !ok {
		return "", nil, fmt.Errorf("%s: not an archive this can unpack (%q)", u.Redacted(), path.Base(u.Path))
	}
	if err := d.Decompress(dst, archive.Name(), true, 0); err != nil {
		return "", nil, fmt.Errorf("unpack %s: %w", u.Redacted(), err)
	}
	// An archive that holds one top-level directory is that directory, the
	// way a GitHub tarball is.
	root := dst
	if entries, err := os.ReadDir(dst); err == nil && len(entries) == 1 && entries[0].IsDir() {
		root = filepath.Join(dst, entries[0].Name())
	}

	name := strings.TrimPrefix(u.Path, "/")
	if format != "" {
		name = strings.TrimSuffix(name, "."+format)
	}
	return root, &fetched{
		prefix: path.Join(vendorDir, strings.ToLower(u.Hostname()), name, digest[:12]),
		pin:    Pin{Source: stripForced(source), Constraint: checksum, Resolved: "sha256:" + digest},
	}, nil
}

// checksumMatches reads go-getter's `checksum=` forms: a bare hex digest or
// `sha256:<hex>`. Other algorithms are not what a digest pin records, and
// fail closed.
func checksumMatches(checksum, sha256hex string) bool {
	algo, hexsum, ok := strings.Cut(checksum, ":")
	if !ok {
		return strings.EqualFold(checksum, sha256hex)
	}
	return strings.EqualFold(algo, "sha256") && strings.EqualFold(hexsum, sha256hex)
}

func stripForced(source string) string {
	_, rest := forcedGetter(source)
	return rest
}

// RepoKey names a repository without the ways of reaching it:
// `github.com/org/repo` for ssh://git@github.com/org/repo.git, the scp-like
// form, and https. Two sources naming one repository share a vendor prefix,
// and the checkout being published is recognized by it (D29).
func RepoKey(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	p := strings.Trim(u.Path, "/")
	p = strings.TrimSuffix(p, ".git")
	if host == "" {
		return path.Join("file", p)
	}
	return path.Join(host, p)
}

// RepoKeyOf is RepoKey for a remote URL as git prints it, which may be the
// scp-like `git@github.com:org/repo.git` that url.Parse cannot read.
func RepoKeyOf(remote string) string {
	remote = strings.TrimSpace(remote)
	if !strings.Contains(remote, "://") {
		if user, rest, ok := strings.Cut(remote, "@"); ok && !strings.Contains(user, "/") {
			if host, p, ok := strings.Cut(rest, ":"); ok {
				return RepoKey(&url.URL{Host: host, Path: p})
			}
		}
		return RepoKey(&url.URL{Path: remote})
	}
	u, err := url.Parse(remote)
	if err != nil {
		return ""
	}
	return RepoKey(u)
}

// Untar unpacks a tar stream of a source tree into dst: directories, files,
// symlinks, nothing else. Entries that would leave dst are skipped.
func Untar(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if name == "." || strings.HasPrefix(name, "..") {
			continue
		}
		target := filepath.Join(dst, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeReg:
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				return errors.Join(err, out.Close())
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
	}
}
