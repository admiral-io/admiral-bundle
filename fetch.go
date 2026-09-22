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

// Remote sources, the other half of closing a Terraform bundle. A module
// call names one of three things, told apart in the order tofu's
// addrs.ParseModuleSource tells them apart: a local path (`./` or `../`), a
// registry address (`GoogleCloudPlatform/cloud-armor/google`, three or four
// slash-separated parts), or anything else, which go-getter reads:
// `git::ssh://…?ref=`, `github.com/org/repo//sub`, `https://host/x.zip`.
//
// A registry address resolves constraint to version against the registry,
// then the registry says where the bytes are, a go-getter address again. So
// every remote source ends as one fetch into a scratch tree: an archive
// downloaded here, a git repository cloned through a GitTransport.
//
// Fetched trees are placed in the bundle by identity: the registry
// address and version, the repository and commit, the archive URL and
// digest. Two calls resolving to the same thing share one copy. What the
// walk copies is the directory the call names and whatever that directory
// reaches by relative path inside the same fetched tree; a path out of the
// tree is refused.

var (
	// ErrSourceUnsupported is a source go-getter has a getter for but this
	// package does not support: s3::, gcs::, hg::.
	ErrSourceUnsupported = errors.New("module source scheme is not supported; vendor it into the tree before publishing")
	// ErrSourceNonLiteral is a source read from a variable or a local.
	ErrSourceNonLiteral = errors.New("module source is not a literal string; the registry needs sources it can read")
	// ErrFetchedEscapes is a module inside a fetched tree calling a path
	// outside that tree, which no fetch of the tree could satisfy.
	ErrFetchedEscapes = errors.New("module source escapes the fetched tree")
	// ErrSubdirMissing is a `//subdir` the fetched tree does not contain.
	ErrSubdirMissing = errors.New("module subdirectory is not in the fetched tree")
	// ErrVendorEscapes is a vendored path that would land outside the
	// bundle's staging tree, whichever prefix computed it.
	ErrVendorEscapes = errors.New("vendored path would land outside the bundle")
	// ErrRefInvalid is a git ref that could be read as an option by git.
	ErrRefInvalid = errors.New("git ref must not begin with a dash")
	// ErrLinkEscapes is a symlink whose target resolves outside the tree
	// being copied; a bundle carries a copy of what a link inside the tree
	// points at, never the link, and never anything outside.
	ErrLinkEscapes = errors.New("symlink resolves outside the tree")
	// ErrTooManyEntries is an archive past the entry cap.
	ErrTooManyEntries = errors.New("archive has too many entries")
)

// maxEntries bounds what one archive may unpack to, beside MaxUncompressed
// for its bytes. Generous for a module tree, small against a bomb.
const maxEntries = 1 << 17

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

// GitTransport clones a repository. Git, go-git in process, is the one
// implementation; the interface is the seam a test stands in for.
type GitTransport interface {
	// Clone brings the repository at u, at ref (empty is the default branch),
	// into dst, which does not exist yet, and returns the commit it is at.
	// u still carries its query; a transport may honor go-getter's `depth`.
	// cred is what the Credentials lookup gave for u, or nil.
	Clone(ctx context.Context, u *url.URL, ref, dst string, cred *Credential) (string, error)
}

// fetched is one remote tree on disk and where it goes in the bundle.
type fetched struct {
	// abs is the tree root on disk, in the fetcher's scratch directory.
	abs string
	// prefix is the bundle directory the tree root maps to.
	prefix string
	// pin is what resolving it recorded.
	pin Pin
	// locSubdir is the subdirectory the registry's download answer named,
	// which every call into this tree is relative to.
	locSubdir string
}

// fetcher resolves and fetches remote module sources for one Pack.
type fetcher struct {
	dir      string
	registry *registryClient
	getter   *getter.Client
	http     *http.Client
	creds    Credentials
	git      GitTransport
	insecure bool
	boundary string
	// trees dedups by identity: registry address+version, git URL+ref,
	// archive URL. The key is known before the fetch.
	trees map[string]*fetched
	// pins, in resolution order.
	pins []Pin
	// dial is the egress policy, when there is one.
	dial Dialer
	// n numbers scratch directories.
	n int
}

// newFetcher makes a fetcher whose scratch lives under dir.
func newFetcher(dir string, opts Options) *fetcher {
	httpGetter := &getter.HttpGetter{
		Netrc:                 true,
		XTerraformGetDisabled: true,
		DoNotCheckHeadFirst:   true,
	}
	return &fetcher{
		dir:      dir,
		registry: newRegistryClient(opts),
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
			// An archive is unpacked by go-getter's decompressors, bounded
			// the way Untar is: so many entries, so many bytes per file.
			Decompressors: getter.LimitedDecompressors(maxEntries, MaxUncompressed),
		},
		http:     newHTTPClient(5*time.Minute, opts.Dial),
		dial:     opts.Dial,
		creds:    opts.Credentials,
		git:      opts.git(),
		insecure: opts.AllowInsecureHTTP,
		boundary: opts.Boundary,
		trees:    map[string]*fetched{},
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
		subdir, err := cleanSubdir(path.Join(t.locSubdir, addr.Subdir))
		if err != nil {
			return nil, "", fmt.Errorf("%s %s: %w", registryAddress(pkg), v, err)
		}
		return t, subdir, nil
	}
	location, err := f.registry.Location(ctx, pkg, v)
	if err != nil {
		return nil, "", err
	}
	// The registry's answer may itself carry a subdirectory: the package
	// is the repository, the module is a directory in it.
	location, locSubdir := getter.SourceDirSubdir(location)
	abs, _, err := f.fetch(ctx, location, false)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", registryAddress(pkg), v, err)
	}
	t := &fetched{
		abs:       abs,
		prefix:    path.Join(vendorDir, registryHost(pkg), pkg.ForRegistryProtocol(), v.Original()),
		pin:       Pin{Source: registryAddress(pkg), Constraint: call.Version, Resolved: v.Original()},
		locSubdir: locSubdir,
	}
	f.trees[key] = t
	f.pins = append(f.pins, t.pin)
	subdir, err := cleanSubdir(path.Join(locSubdir, addr.Subdir))
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", registryAddress(pkg), v, err)
	}
	return t, subdir, nil
}

// resolveRemote fetches a module call's non-registry source. A file://
// source is the author's own directory, bounded by Options.Boundary.
func (f *fetcher) resolveRemote(ctx context.Context, source string) (*fetched, string, error) {
	return f.resolveSource(ctx, source, true)
}

// resolveNetwork is resolveRemote for a source that must be on the
// network: what a Pull names, which nobody's own directory can satisfy.
func (f *fetcher) resolveNetwork(ctx context.Context, source string) (*fetched, string, error) {
	return f.resolveSource(ctx, source, false)
}

func (f *fetcher) resolveSource(ctx context.Context, source string, local bool) (*fetched, string, error) {
	base, subdir := getter.SourceDirSubdir(source)
	subdir, err := cleanSubdir(subdir)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", redactSource(source), err)
	}
	key := "remote|" + base
	if t, ok := f.trees[key]; ok {
		return t, subdir, nil
	}
	abs, t, err := f.fetch(ctx, base, local)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", redactSource(source), err)
	}
	t.abs = abs
	f.trees[key] = t
	f.pins = append(f.pins, t.pin)
	return t, subdir, nil
}

// cleanSubdir validates a `//subdir`: a relative path that stays inside the
// fetched tree. `..` is refused before anything is fetched, because a subdir
// that climbs out of its tree is never something a tree could satisfy, and
// on the way up it would reach the fetcher's scratch and the host.
func cleanSubdir(subdir string) (string, error) {
	if subdir == "" {
		return "", nil
	}
	name, ok := cleanPath(subdir)
	if !ok {
		return "", fmt.Errorf("%w: subdirectory %q", ErrFetchedEscapes, subdir)
	}
	return name, nil
}

// ErrOutsideBoundary is a local or file:// source that resolves outside
// Options.Boundary.
var ErrOutsideBoundary = errors.New("source resolves outside the boundary")

// withinBoundary refuses p when a boundary is set and p, with every link
// followed, is not under it. A missing p is left for the caller to report.
func withinBoundary(boundary, p string) error {
	if boundary == "" {
		return nil
	}
	realBoundary, err := filepath.EvalSymlinks(boundary)
	if err != nil {
		return fmt.Errorf("boundary %s: %w", boundary, err)
	}
	realP, err := filepath.EvalSymlinks(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !inside(realBoundary, realP) {
		return fmt.Errorf("%w: %s is not under %s", ErrOutsideBoundary, p, boundary)
	}
	return nil
}

// ErrLocalSource is a local path where only the network will do: a
// registry's download answer, a Pull's source, or a file:// repository
// under a dial policy.
var ErrLocalSource = errors.New("local path where a network source is required")

// ErrRegistryLocalLocation is ErrLocalSource, kept for callers that named it.
var ErrRegistryLocalLocation = ErrLocalSource

// fetch brings one go-getter address (no subdirectory) into a fresh scratch
// directory and says what it is: the tree root, and its bundle prefix and
// pin. The address is detected first so `github.com/org/repo` and the
// scp-like `git@host:org/repo` become the URLs they mean. local says
// whether a file source is acceptable: from the author's own call it is
// (bounded by Options.Boundary); from a registry's download answer it is
// not, because a registry names bytes on the network.
func (f *fetcher) fetch(ctx context.Context, source string, local bool) (string, *fetched, error) {
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
		return "", nil, fmt.Errorf("%w: %s", ErrSourceUnsupported, redactSource(source))
	}
	// Detection may have rewritten the source (shorthand to URL) and may
	// have found a subdirectory in the rewritten form; the caller split its
	// own already, so any left here is part of the address itself.
	detected, _ := getter.SourceDirSubdir(req.Src)
	u, err := url.Parse(detected)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", redactSource(source), err)
	}

	switch matched.(type) {
	case *getter.GitGetter:
		// go-git reads a file:// repository off the disk, which no dial
		// policy sees, so a policy refuses it outright. Without one it is a
		// developer's own repository standing in for a server.
		if u.Scheme == "file" && f.dial != nil {
			return "", nil, fmt.Errorf("%w: %s", ErrLocalSource, redactSource(source))
		}
		return f.fetchGit(ctx, source, u, dst)
	case *getter.HttpGetter:
		return f.fetchArchive(ctx, source, u, dst)
	default:
		// file:// is a local directory; go-getter symlinks it unless told to
		// copy, and a symlinked scratch tree is not ours to walk.
		if !local {
			return "", nil, fmt.Errorf("%w: %s", ErrLocalSource, redactSource(source))
		}
		if err := withinBoundary(f.boundary, filepath.FromSlash(u.Path)); err != nil {
			return "", nil, fmt.Errorf("%s: %w", redactSource(source), err)
		}
		req.Src, req.Copy = u.String(), true
		if _, err := f.getter.Get(ctx, req); err != nil {
			return "", nil, err
		}
		return dst, &fetched{
			prefix: path.Join(vendorDir, "file", strings.TrimPrefix(filepath.ToSlash(filepath.Clean(u.Path)), "/")),
			pin:    Pin{Source: redactSource(source)},
		}, nil
	}
}

// fetchGit clones u at its ref through the transport. The pin resolves the
// ref to the commit.
func (f *fetcher) fetchGit(ctx context.Context, source string, u *url.URL, dst string) (string, *fetched, error) {
	ref := u.Query().Get("ref")
	written := redactSource(source)
	// A ref is handed to a transport that may run git; one shaped like an
	// option (`--upload-pack=…`) must never reach a command line.
	if strings.HasPrefix(ref, "-") {
		return "", nil, fmt.Errorf("%w: %q for %s", ErrRefInvalid, ref, written)
	}
	var cred *Credential
	if f.creds != nil {
		var err error
		if cred, err = f.creds.Lookup(ctx, u.String()); err != nil {
			return "", nil, err
		}
	}
	if cred != nil && u.Scheme == "http" && !f.insecure {
		return "", nil, fmt.Errorf("%w: %s to %s", ErrInsecureHTTP, cred.family(), written)
	}
	sha, err := f.git.Clone(ctx, u, ref, dst, cred)
	if err != nil {
		return "", nil, err
	}
	if !isCommitHash(sha) {
		return "", nil, fmt.Errorf("git transport returned %q for %s, not a commit", sha, written)
	}
	return dst, &fetched{
		prefix: path.Join(vendorDir, RepoKey(u), sha[:12]),
		pin:    Pin{Source: written, Constraint: ref, Resolved: sha},
	}, nil
}

var commitHash = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// isCommitHash is a full SHA-1 or SHA-256 object name, the only thing a
// transport may answer with: a ref name or an error message would otherwise
// be pinned as a commit.
func isCommitHash(s string) bool { return commitHash.MatchString(s) }

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
	req.Header.Set("User-Agent", userAgent)
	if f.creds != nil {
		cred, err := f.creds.Lookup(ctx, u.String())
		if err != nil {
			return "", nil, err
		}
		if err := cred.authorize(req, f.insecure); err != nil {
			return "", nil, err
		}
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("GET %s: %s", redactURL(u), resp.Status)
	}
	archive, err := os.CreateTemp(f.dir, "archive-*")
	if err != nil {
		return "", nil, err
	}
	defer os.Remove(archive.Name())
	h := sha256.New()
	// The archive is bounded by what it may expand to; a download past that
	// cannot be a module either.
	n, err := io.Copy(io.MultiWriter(archive, h), io.LimitReader(resp.Body, MaxUncompressed+1))
	if err != nil {
		return "", nil, errors.Join(err, archive.Close())
	}
	if err := archive.Close(); err != nil {
		return "", nil, err
	}
	if n > MaxUncompressed {
		return "", nil, fmt.Errorf("GET %s: %w", redactURL(u), ErrTooLarge)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if checksum != "" && !checksumMatches(checksum, digest) {
		return "", nil, fmt.Errorf("%s: checksum %q does not match the bytes (sha256:%s)", redactURL(u), checksum, digest)
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
		return "", nil, fmt.Errorf("%s: not an archive this can unpack (%q)", redactURL(u), path.Base(u.Path))
	}
	if err := d.Decompress(dst, archive.Name(), true, 0); err != nil {
		return "", nil, fmt.Errorf("unpack %s: %w", redactURL(u), err)
	}
	// An archive that holds one top-level directory is that directory, the
	// way a GitHub tarball is.
	root := dst
	if entries, err := os.ReadDir(dst); err == nil && len(entries) == 1 && entries[0].IsDir() {
		root = filepath.Join(dst, entries[0].Name())
	}

	// The prefix is a bundle path; a `..` in the URL's path must not become
	// one in the bundle. place() refuses an escape too; this keeps the
	// prefix readable.
	name := strings.TrimPrefix(path.Clean("/"+u.Path), "/")
	if format != "" {
		name = strings.TrimSuffix(name, "."+format)
	}
	return root, &fetched{
		prefix: path.Join(vendorDir, strings.ToLower(u.Hostname()), name, digest[:12]),
		pin:    Pin{Source: redactSource(stripForced(source)), Constraint: checksum, Resolved: "sha256:" + digest},
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
// and the checkout being published is recognized by it.
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
// symlinks, nothing else. Every entry is created through an *os.Root, so no
// path component may traverse a symlink out of dst; a symlink whose target
// resolves outside dst is refused, as is anything past MaxUncompressed bytes
// or past the entry cap. The stream may come from a remote registry, so it
// is read as hostile.
func Untar(r io.Reader, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer root.Close()

	tr := tar.NewReader(r)
	var (
		total   int64
		entries int
	)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if entries++; entries > maxEntries {
			return fmt.Errorf("%w: more than %d", ErrTooManyEntries, maxEntries)
		}
		name, ok := cleanPath(hdr.Name)
		if !ok {
			return fmt.Errorf("%w: %q", ErrBadPath, hdr.Name)
		}
		if name == "" {
			continue
		}
		target := filepath.FromSlash(name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if !linkStaysInside(name, hdr.Linkname) {
				return fmt.Errorf("%w: symlink %q -> %q escapes the tree", ErrBadPath, name, hdr.Linkname)
			}
			if err := root.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := root.Symlink(filepath.FromSlash(hdr.Linkname), target); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 {
				return fmt.Errorf("%w: %s has a negative size", ErrBadPath, name)
			}
			if total += hdr.Size; total > MaxUncompressed {
				return ErrTooLarge
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			if err := root.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := root.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			// The header's size is what was budgeted; a stream that carries
			// more than it declared is malformed, not merely large.
			n, err := io.Copy(out, io.LimitReader(tr, hdr.Size+1))
			if err != nil {
				return errors.Join(err, out.Close())
			}
			if err := out.Close(); err != nil {
				return err
			}
			if n != hdr.Size {
				return fmt.Errorf("%w: %s is not the size its header claims", ErrBadPath, name)
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			// git archive writes the commit id as a global header.
		default:
			return fmt.Errorf("%w: %q", ErrEntryKind, name)
		}
	}
}
