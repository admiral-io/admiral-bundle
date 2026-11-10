package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/hashicorp/go-version"
	tfaddr "github.com/hashicorp/terraform-registry-address"
)

// Catalog is an upstream that offers artifacts at versions: a Helm
// repository, a namespace in an OCI registry, a namespace in a module
// registry, or a git repository. Exactly one field is set. It is the
// location a Source names, before an artifact and a version are chosen.
type Catalog struct {
	// HelmRepository is the repository URL whose index.yaml lists the
	// charts, `https://charts.jetstack.io`.
	HelmRepository string
	// OCINamespace is `oci://host/path`; artifacts are the names under it.
	OCINamespace string
	// RegistryNamespace is `host/namespace`, or `namespace` on the default
	// host; artifacts are `name/provider`.
	RegistryNamespace string
	// GitRepository is a clone URL; the artifacts are paths in the tree and
	// the versions are its tags and branches.
	GitRepository string
}

// Artifact is one thing a catalog offers, as the upstream names it.
type Artifact struct {
	Name        string
	Description string
	// Latest is the newest ordered version the catalog lists, when it says.
	Latest string
}

// Version is one version of an artifact as the upstream offers it. A tag,
// a chart version and a registry version are ordered; a branch is a moving
// head and says where it points now.
type Version struct {
	Name   string
	Branch bool
	// Commit is what a git tag or branch resolves to.
	Commit string
	// Created is when the upstream says the version was made, when it says.
	Created time.Time
}

var (
	// ErrNoCatalog is an upstream whose protocol lists no artifacts: a
	// container registry, a git repository. The caller names the artifact.
	ErrNoCatalog = errors.New("the upstream lists no artifacts; name the artifact")
	// ErrArtifactNotFound is an artifact the catalog does not have.
	ErrArtifactNotFound = errors.New("artifact not found in the catalog")
)

// ListArtifacts reads what a catalog offers, for the protocols that serve a
// catalog: a Helm repository's index and a module registry's namespace.
// Nothing is pulled. Credentials and Dial apply as they do to Pull.
func ListArtifacts(ctx context.Context, c Catalog, opts Options) ([]Artifact, error) {
	switch {
	case c.HelmRepository != "":
		return helmArtifacts(ctx, c.HelmRepository, opts)
	case c.RegistryNamespace != "":
		return registryArtifacts(ctx, newRegistryClient(opts), c.RegistryNamespace)
	case c.OCINamespace != "" || c.GitRepository != "":
		return nil, ErrNoCatalog
	default:
		return nil, ErrNoSource
	}
}

// ListVersions reads the versions of one artifact in a catalog, ordered
// versions newest first, then branches. For a git repository the artifact
// is ignored: the versions are the repository's tags and branches, each
// with the commit it points at. Nothing is pulled.
func ListVersions(ctx context.Context, c Catalog, artifact string, opts Options) ([]Version, error) {
	switch {
	case c.HelmRepository != "":
		return helmVersions(ctx, c.HelmRepository, artifact, opts)
	case c.OCINamespace != "":
		return ociVersions(ctx, c.OCINamespace, artifact, opts)
	case c.RegistryNamespace != "":
		return registryVersions(ctx, newRegistryClient(opts), c.RegistryNamespace, artifact)
	case c.GitRepository != "":
		return gitVersions(ctx, c.GitRepository, opts)
	default:
		return nil, ErrNoSource
	}
}

// --- Helm -------------------------------------------------------------------

func helmArtifacts(ctx context.Context, repoURL string, opts Options) ([]Artifact, error) {
	index, err := newHelmFetcher(opts).fetchIndex(ctx, strings.TrimSuffix(repoURL, "/"))
	if err != nil {
		return nil, err
	}
	out := make([]Artifact, 0, len(index.Entries))
	for name, entries := range index.Entries {
		a := Artifact{Name: name}
		for _, v := range orderedVersions(entryVersions(entries)) {
			if a.Latest == "" {
				a.Latest = v.Name
			}
		}
		for _, e := range entries {
			if e.Version == a.Latest {
				a.Description = e.Description
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func helmVersions(ctx context.Context, repoURL, chart string, opts Options) ([]Version, error) {
	index, err := newHelmFetcher(opts).fetchIndex(ctx, strings.TrimSuffix(repoURL, "/"))
	if err != nil {
		return nil, err
	}
	entries, ok := index.Entries[chart]
	if !ok {
		return nil, fmt.Errorf("%w: %s in %s", ErrArtifactNotFound, chart, redactSource(repoURL))
	}
	return orderedVersions(entryVersions(entries)), nil
}

func entryVersions(entries []repoEntry) []Version {
	out := make([]Version, 0, len(entries))
	for _, e := range entries {
		out = append(out, Version{Name: e.Version, Created: e.Created})
	}
	return out
}

// --- OCI --------------------------------------------------------------------

func ociVersions(ctx context.Context, namespace, name string, opts Options) ([]Version, error) {
	base, err := ociReference(namespace)
	if err != nil {
		return nil, err
	}
	if name == "" || strings.ContainsAny(name, "/:@") {
		return nil, fmt.Errorf("%q is not a name under oci://%s", name, base)
	}
	repo, err := newOCIClient(opts).repository(base + "/" + name)
	if err != nil {
		return nil, err
	}
	var out []Version
	err = repo.Tags(ctx, "", func(tags []string) error {
		for _, t := range tags {
			out = append(out, Version{Name: t})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("oci://%s/%s: %w", base, name, err)
	}
	return orderedVersions(out), nil
}

// --- Module registry ----------------------------------------------------------

// maxRegistryPages bounds a namespace listing; registry.terraform.io pages
// by a hundred and no namespace legitimately nears this.
const maxRegistryPages = 50

func registryArtifacts(ctx context.Context, r *registryClient, namespace string) ([]Artifact, error) {
	host, ns, err := splitNamespace(namespace)
	if err != nil {
		return nil, err
	}
	base, err := r.modulesBase(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []Artifact
	offset := 0
	for page := 0; page < maxRegistryPages; page++ {
		u := base.JoinPath(ns)
		q := u.Query()
		q.Set("limit", "100")
		if offset > 0 {
			q.Set("offset", fmt.Sprint(offset))
		}
		u.RawQuery = q.Encode()
		resp, err := r.get(ctx, host, u)
		if err != nil {
			return nil, err
		}
		var body struct {
			Meta struct {
				NextOffset *int `json:"next_offset"`
			} `json:"meta"`
			Modules []struct {
				Name        string `json:"name"`
				Provider    string `json:"provider"`
				Description string `json:"description"`
				Version     string `json:"version"`
			} `json:"modules"`
		}
		decodeErr := func() error {
			defer resp.Body.Close() //nolint:errcheck
			switch resp.StatusCode {
			case http.StatusOK:
			case http.StatusNotFound:
				return fmt.Errorf("%w: %s does not list a namespace", ErrNoCatalog, host)
			default:
				return registryError(namespace, resp)
			}
			return json.NewDecoder(io.LimitReader(resp.Body, maxRegistryBody)).Decode(&body)
		}()
		if decodeErr != nil {
			return nil, decodeErr
		}
		for _, m := range body.Modules {
			out = append(out, Artifact{Name: m.Name + "/" + m.Provider, Description: m.Description, Latest: m.Version})
		}
		if body.Meta.NextOffset == nil || *body.Meta.NextOffset <= offset || len(body.Modules) == 0 {
			break
		}
		offset = *body.Meta.NextOffset
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func registryVersions(ctx context.Context, r *registryClient, namespace, artifact string) ([]Version, error) {
	if strings.Count(artifact, "/") != 1 {
		return nil, fmt.Errorf("%q is not a registry artifact (want name/provider)", artifact)
	}
	m, err := tfaddr.ParseModuleSource(strings.TrimSuffix(namespace, "/") + "/" + artifact)
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %w", namespace, artifact, err)
	}
	versions, err := r.Versions(ctx, m.Package)
	if errors.Is(err, ErrRegistryNotFound) {
		return nil, fmt.Errorf("%w: %s in %s", ErrArtifactNotFound, artifact, namespace)
	}
	if err != nil {
		return nil, err
	}
	out := make([]Version, 0, len(versions))
	for _, v := range versions {
		out = append(out, Version{Name: v.Original()})
	}
	return orderedVersions(out), nil
}

// splitNamespace reads `host/namespace` or `namespace`, the way a module
// address written without a host resolves against the default registry.
func splitNamespace(namespace string) (host, ns string, err error) {
	parts := strings.Split(strings.Trim(namespace, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] != "":
		return DefaultRegistryHost, parts[0], nil
	case len(parts) == 2 && strings.Contains(parts[0], "."):
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("%q is not a registry namespace (want host/namespace)", namespace)
	}
}

// --- Git --------------------------------------------------------------------

func gitVersions(ctx context.Context, repository string, opts Options) ([]Version, error) {
	u, err := url.Parse(repository)
	if err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("%q is not a git URL", repository)
	}
	g, ok := opts.Git.(*Git)
	if !ok {
		g = &Git{Dial: opts.Dial, Credentials: opts.Credentials}
	}
	var cred *Credential
	if opts.Credentials != nil {
		if cred, err = opts.Credentials.Lookup(ctx, u.String()); err != nil {
			return nil, err
		}
	}
	auth, err := g.auth(u, cred)
	if err != nil {
		return nil, err
	}
	ctx, proxy, release := g.dialing(ctx, u)
	defer release()
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: "origin", URLs: []string{u.String()}})
	refs, err := remote.ListContext(ctx, &git.ListOptions{Auth: auth, ProxyOptions: proxy, PeelingOption: git.AppendPeeled})
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", u.Redacted(), err)
	}
	// A peeled entry, `refs/tags/v1^{}`, names the commit an annotated tag
	// points at; the tag's own entry names the tag object. The commit is
	// what a reader wants, so the peeled one wins when both exist.
	commits := map[string]string{}
	var tags, branches []Version
	for _, ref := range refs {
		name := ref.Name()
		switch {
		case name.IsTag():
			short := strings.TrimSuffix(name.Short(), "^{}")
			if strings.HasSuffix(name.String(), "^{}") || commits[short] == "" {
				commits[short] = ref.Hash().String()
			}
		case name.IsBranch():
			branches = append(branches, Version{Name: name.Short(), Branch: true, Commit: ref.Hash().String()})
		}
	}
	for short, commit := range commits {
		tags = append(tags, Version{Name: short, Commit: commit})
	}
	sort.Slice(branches, func(i, j int) bool { return branches[i].Name < branches[j].Name })
	return append(orderedVersions(tags), branches...), nil
}

// orderedVersions sorts versions newest first: semver first, newest to
// oldest, then the rest by name descending, so `v1.10.0` outranks `v1.9.0`
// and a `latest` tag sits after every number.
func orderedVersions(in []Version) []Version {
	type keyed struct {
		v      Version
		semver *version.Version
	}
	ks := make([]keyed, 0, len(in))
	for _, v := range in {
		k := keyed{v: v}
		if sv, err := version.NewSemver(v.Name); err == nil {
			k.semver = sv
		}
		ks = append(ks, k)
	}
	sort.SliceStable(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		switch {
		case a.semver != nil && b.semver != nil:
			return a.semver.GreaterThan(b.semver)
		case a.semver != nil:
			return true
		case b.semver != nil:
			return false
		default:
			return a.v.Name > b.v.Name
		}
	})
	out := make([]Version, 0, len(ks))
	for _, k := range ks {
		out = append(out, k.v)
	}
	return out
}
