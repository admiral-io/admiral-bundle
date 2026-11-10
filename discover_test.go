package bundle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func names(vs []Version) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Name)
	}
	return out
}

func TestHelmCatalogListsChartsAndOrdersVersions(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`apiVersion: v1
entries:
  cert-manager:
  - version: v1.9.3
    description: old
    created: "2024-01-01T00:00:00Z"
    urls: [cert-manager-v1.9.3.tgz]
  - version: v1.16.2
    description: A certificate manager
    created: "2025-06-01T00:00:00Z"
    urls: [cert-manager-v1.16.2.tgz]
  - version: v1.10.0
    urls: [cert-manager-v1.10.0.tgz]
  trust-manager:
  - version: 0.12.0
    urls: [trust-manager-0.12.0.tgz]
`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := Catalog{HelmRepository: srv.URL}

	artifacts, err := ListArtifacts(ctx, c, Options{})
	require.NoError(t, err)
	require.Len(t, artifacts, 2)
	assert.Equal(t, Artifact{Name: "cert-manager", Description: "A certificate manager", Latest: "v1.16.2"}, artifacts[0], "latest by semver, not by order in the index")
	assert.Equal(t, Artifact{Name: "trust-manager", Latest: "0.12.0"}, artifacts[1])

	versions, err := ListVersions(ctx, c, "cert-manager", Options{})
	require.NoError(t, err)
	assert.Equal(t, []string{"v1.16.2", "v1.10.0", "v1.9.3"}, names(versions), "v1.10.0 outranks v1.9.3")
	assert.Equal(t, 2025, versions[0].Created.Year())
	assert.False(t, versions[0].Branch)

	_, err = ListVersions(ctx, c, "nope", Options{})
	assert.ErrorIs(t, err, ErrArtifactNotFound)
}

func TestOCICatalogListsTagsAndHasNoArtifacts(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v2/charts/argo-cd/tags/list", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "charts/argo-cd", "tags": []string{"latest", "7.7.0", "7.10.1", "7.9.0"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	c := Catalog{OCINamespace: "oci://" + u.Host + "/charts"}

	versions, err := ListVersions(ctx, c, "argo-cd", Options{})
	require.NoError(t, err)
	assert.Equal(t, []string{"7.10.1", "7.9.0", "7.7.0", "latest"}, names(versions), "semver first, a bare tag after every number")

	_, err = ListArtifacts(ctx, c, Options{})
	assert.ErrorIs(t, err, ErrNoCatalog)

	_, err = ListVersions(ctx, c, "argo/cd", Options{})
	require.Error(t, err, "an artifact is one name under the namespace")
}

func TestRegistryCatalogListsANamespaceAndVersions(t *testing.T) {
	ctx := context.Background()
	fake := newFakeRegistry(t, []string{"1.0.0", "1.2.0", "1.1.0"}, "git::https://example.invalid/acme/net?ref=abc", "header")
	mux, ok := fake.srv.Config.Handler.(*http.ServeMux)
	require.True(t, ok)
	mux.HandleFunc("/api/modules/acme", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"meta":    map[string]any{"next_offset": 1},
				"modules": []map[string]string{{"name": "net", "provider": "google", "description": "A network", "version": "1.2.0"}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"modules": []map[string]string{{"name": "db", "provider": "google", "version": "0.3.0"}},
		})
	})
	r := newRegistryClient(Options{Credentials: staticCreds{fakeHost: "tok"}, AllowInsecureHTTP: true})
	fake.seed(r)

	artifacts, err := registryArtifacts(ctx, r, fakeHost+"/acme")
	require.NoError(t, err)
	assert.Equal(t, []Artifact{
		{Name: "db/google", Latest: "0.3.0"},
		{Name: "net/google", Description: "A network", Latest: "1.2.0"},
	}, artifacts, "both pages, sorted by name")

	versions, err := registryVersions(ctx, r, fakeHost+"/acme", "net/google")
	require.NoError(t, err)
	assert.Equal(t, []string{"1.2.0", "1.1.0", "1.0.0"}, names(versions))

	_, err = registryVersions(ctx, r, fakeHost+"/acme", "net")
	require.Error(t, err, "an artifact is name/provider")

	t.Run("a registry that does not list a namespace", func(t *testing.T) {
		mux.HandleFunc("/api/modules/other", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
		_, err := registryArtifacts(ctx, r, fakeHost+"/other")
		assert.ErrorIs(t, err, ErrNoCatalog)
	})
}

func TestGitCatalogListsTagsThenBranchesWithTheirCommits(t *testing.T) {
	ctx := context.Background()
	dir, first := gitRepo(t, map[string]string{"main.tf": "# v1"})
	repo := openRepo(t, dir)
	tagHead(t, repo, "v1.0.0")
	second := commitFiles(t, repo, map[string]string{"main.tf": "# v2"}, "second")
	tagHead(t, repo, "v1.2.0")
	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("release/1.x"), Create: true}))
	c := Catalog{GitRepository: "file://" + dir}

	versions, err := ListVersions(ctx, c, "", Options{})
	require.NoError(t, err)
	assert.Equal(t, []string{"v1.2.0", "v1.0.0", "main", "release/1.x"}, names(versions), "ordered tags newest first, then branches by name")
	assert.Equal(t, second, versions[0].Commit)
	assert.Equal(t, first, versions[1].Commit)
	assert.True(t, versions[2].Branch)
	assert.Equal(t, second, versions[2].Commit)

	_, err = ListArtifacts(ctx, c, Options{})
	assert.ErrorIs(t, err, ErrNoCatalog)
}

func TestOrderedVersionsPutsSemverFirstNewestToOldest(t *testing.T) {
	got := orderedVersions([]Version{{Name: "latest"}, {Name: "1.9.0"}, {Name: "v2.0.0-rc.1"}, {Name: "1.10.0"}, {Name: "alpha"}, {Name: "2.0.0"}})
	assert.Equal(t, []string{"2.0.0", "v2.0.0-rc.1", "1.10.0", "1.9.0", "latest", "alpha"}, names(got))
}

func TestACatalogNamesExactlyOneUpstream(t *testing.T) {
	_, err := ListVersions(context.Background(), Catalog{}, "", Options{})
	assert.ErrorIs(t, err, ErrNoSource)
}
