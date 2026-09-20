package bundle

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-config-inspect/tfconfig"
)

// Source names an artifact to pull and publish: a chart in an OCI registry
// or an HTTP repository, a module in a module registry, a git tree at a
// ref, an archive. Exactly one field is set. The artifact is somebody
// else's; what is published is a copy, with provenance saying where from.
type Source struct {
	OCIChart       *OCIChartSource
	HelmChart      *HelmChartSource
	RegistryModule *RegistryModuleSource
	GitTree        *GitTreeSource
	Archive        *ArchiveSource
}

// OCIChartSource is `oci://host/path/name` at a version, which is its tag.
type OCIChartSource struct {
	Reference string
	Version   string
}

// HelmChartSource is a chart in an HTTP repository at an exact version.
type HelmChartSource struct {
	Repository string
	Chart      string
	Version    string
}

// RegistryModuleSource is a module registry address, as a module call would
// write it, and a version constraint; empty is the newest release.
type RegistryModuleSource struct {
	Address string
	Version string
}

// GitTreeSource is a repository at a ref, optionally a directory of it.
type GitTreeSource struct {
	URL  string
	Ref  string
	Path string
}

// ArchiveSource is an archive at a URL, unpacked by its extension.
type ArchiveSource struct {
	URL string
}

// ErrNoSource is a Source with nothing set, or more than one thing.
var ErrNoSource = errors.New("a pull names exactly one source")

// Pull materializes a source into a directory to Pack from. Boundary is the
// fetched tree the directory sits in, which Pack should be told, so a
// relative call from the pulled module reaches its siblings and nothing
// else. Cleanup removes everything.
func Pull(ctx context.Context, src Source, opts Options) (*Pulled, error) {
	var set int
	for _, on := range []bool{src.OCIChart != nil, src.HelmChart != nil, src.RegistryModule != nil, src.GitTree != nil, src.Archive != nil} {
		if on {
			set++
		}
	}
	if set != 1 {
		return nil, ErrNoSource
	}
	switch {
	case src.OCIChart != nil:
		return pullOCIChart(ctx, src.OCIChart, opts)
	case src.HelmChart != nil:
		return pullHelmChart(ctx, src.HelmChart, opts)
	default:
		return pullTree(ctx, src, opts)
	}
}

func pullOCIChart(ctx context.Context, s *OCIChartSource, opts Options) (*Pulled, error) {
	ref := strings.TrimSuffix(s.Reference, "/")
	repository, name := path.Split(strings.TrimPrefix(ref, "oci://"))
	repository = "oci://" + strings.TrimSuffix(repository, "/")
	if name == "" || !strings.Contains(strings.TrimPrefix(repository, "oci://"), "/") {
		return nil, fmt.Errorf("%q is not an OCI chart reference (want oci://host/path/name)", s.Reference)
	}
	data, digest, err := newOCIClient(opts).pullChart(ctx, repository, name, s.Version)
	if err != nil {
		return nil, err
	}
	p, err := unpackChart(data, ref+":"+s.Version)
	if err != nil {
		return nil, err
	}
	p.Provenance = Provenance{URI: ref, Ref: s.Version, Commit: digest}
	p.Version = s.Version
	return p, nil
}

func pullHelmChart(ctx context.Context, s *HelmChartSource, opts Options) (*Pulled, error) {
	repo := strings.TrimSuffix(s.Repository, "/")
	data, err := newHelmFetcher(opts).fetchChart(ctx, chartDependency{Name: s.Chart, Version: s.Version, Repository: repo})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	p, err := unpackChart(data, repo+"/"+s.Chart+":"+s.Version)
	if err != nil {
		return nil, err
	}
	p.Provenance = Provenance{URI: repo + "/" + s.Chart, Ref: s.Version, Commit: "sha256:" + hex.EncodeToString(sum[:])}
	p.Version = s.Version
	return p, nil
}

// unpackChart lays a chart tgz out as its one top-level directory.
func unpackChart(data []byte, what string) (*Pulled, error) {
	dir, err := os.MkdirTemp("", "admiral-pull-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := Untar(gz, dir); err != nil {
		cleanup()
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		cleanup()
		return nil, err
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		cleanup()
		return nil, fmt.Errorf("%s: the archive is not one chart directory", what)
	}
	chart := filepath.Join(dir, entries[0].Name())
	return &Pulled{Dir: chart, Boundary: chart, Name: entries[0].Name(), Cleanup: cleanup}, nil
}

// pullTree is the registry, git and archive cases: one fetch through the
// fetcher, the way a module call would be resolved, and the directory it
// names inside the fetched tree.
func pullTree(ctx context.Context, src Source, opts Options) (*Pulled, error) {
	scratch, err := os.MkdirTemp("", "admiral-pull-*")
	if err != nil {
		return nil, err
	}
	return pullTreeWith(ctx, src, newFetcher(scratch, opts), func() { os.RemoveAll(scratch) })
}

// pullTreeWith is pullTree over a fetcher the caller made; cleanup removes
// the fetcher's scratch and runs on every error.
func pullTreeWith(ctx context.Context, src Source, f *fetcher, cleanup func()) (*Pulled, error) {
	var (
		err     error
		tree    *fetched
		subdir  string
		name    string
		version string
	)
	switch {
	case src.RegistryModule != nil:
		s := src.RegistryModule
		kind, addr := classify(s.Address)
		if kind != sourceRegistry {
			cleanup()
			return nil, fmt.Errorf("%q is not a module registry address", s.Address)
		}
		tree, subdir, err = f.resolveRegistry(ctx, &tfconfig.ModuleCall{Source: s.Address, Version: s.Version}, addr)
		name = addr.Package.Name
		if tree != nil {
			version = tree.pin.Resolved
		}
	case src.GitTree != nil:
		s := src.GitTree
		source := "git::" + s.URL
		if s.Path != "" {
			source += "//" + strings.Trim(path.Clean(s.Path), "/")
		}
		if s.Ref != "" {
			source += "?ref=" + url.QueryEscape(s.Ref)
		}
		tree, subdir, err = f.resolveRemote(ctx, source)
		name = gitTreeName(s)
	case src.Archive != nil:
		tree, subdir, err = f.resolveRemote(ctx, src.Archive.URL)
		name = archiveName(src.Archive.URL)
	}
	if err != nil {
		cleanup()
		return nil, err
	}
	if strings.Contains(subdir, "..") {
		cleanup()
		return nil, fmt.Errorf("%w: %s", ErrSubdirMissing, subdir)
	}
	dir := filepath.Join(tree.abs, filepath.FromSlash(subdir))
	if info, serr := os.Stat(dir); serr != nil || !info.IsDir() {
		cleanup()
		return nil, fmt.Errorf("%w: %s", ErrSubdirMissing, subdir)
	}
	if subdir != "" {
		name = path.Base(subdir)
	}
	pin := tree.pin
	return &Pulled{
		Dir:        dir,
		Boundary:   tree.abs,
		Name:       name,
		Version:    version,
		Provenance: Provenance{URI: pin.Source, Ref: pin.Constraint, Commit: pin.Resolved},
		Cleanup:    cleanup,
	}, nil
}

// gitTreeName is the repository's name, `infra` for
// https://github.com/acme/infra.git; a Path overrides it.
func gitTreeName(s *GitTreeSource) string {
	u, err := url.Parse(s.URL)
	p := s.URL
	if err == nil {
		p = u.Path
	}
	return strings.TrimSuffix(path.Base(strings.TrimSuffix(p, "/")), ".git")
}

// archiveName is the file's name without its archive extensions:
// `net-1.0.0` for https://host/archives/net-1.0.0.tar.gz.
func archiveName(rawURL string) string {
	u, err := url.Parse(rawURL)
	p := rawURL
	if err == nil {
		p = u.Path
	}
	base := path.Base(p)
	for _, ext := range []string{".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst", ".tzst", ".zip", ".tar", ".gz", ".bz2", ".xz", ".zst"} {
		if strings.HasSuffix(base, ext) {
			return strings.TrimSuffix(base, ext)
		}
	}
	return base
}
