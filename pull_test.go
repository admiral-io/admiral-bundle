package bundle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullNamesExactlyOneSource(t *testing.T) {
	_, err := Pull(context.Background(), Source{}, Options{})
	assert.ErrorIs(t, err, ErrNoSource)
	_, err = Pull(context.Background(), Source{
		Archive: &ArchiveSource{URL: "https://x/a.tgz"}, GitTree: &GitTreeSource{URL: "https://x/r.git"},
	}, Options{})
	assert.ErrorIs(t, err, ErrNoSource)
}

func TestPullOCIChart(t *testing.T) {
	archive := chartArchive(t)
	reg := newFakeOCI(t, "acme/charts/openfga", "0.3.9", archive, helmChartLayer, nil)
	c := newOCIClient(Options{})
	c.docker = nil

	p, err := pullOCIChart(context.Background(), &OCIChartSource{Reference: reg.repository() + "/openfga", Version: "0.3.9"}, Options{})
	require.NoError(t, err)
	defer p.Cleanup()
	assert.Equal(t, "openfga", p.Name)
	assert.Equal(t, "0.3.9", p.Version)
	assert.Equal(t, p.Dir, p.Boundary, "a chart is its own tree")
	assert.FileExists(t, filepath.Join(p.Dir, "Chart.yaml"))
	assert.Equal(t, reg.repository()+"/openfga", p.Provenance.URI)
	assert.Equal(t, "0.3.9", p.Provenance.Ref)
	assert.True(t, strings.HasPrefix(p.Provenance.Commit, "sha256:"))

	packed, err := PackContext(context.Background(), p.Dir, Options{Boundary: p.Boundary})
	require.NoError(t, err)
	assert.Equal(t, KindHelm, packed.Kind)
	assert.Equal(t, "0.3.9", packed.Version)
}

func TestPullHelmChart(t *testing.T) {
	archive := chartArchive(t)
	repo := helmRepo(t, archive, "sha256:"+sha(archive))

	p, err := Pull(context.Background(), Source{HelmChart: &HelmChartSource{Repository: repo.URL, Chart: "openfga", Version: "0.3.9"}}, Options{})
	require.NoError(t, err)
	defer p.Cleanup()
	assert.Equal(t, "openfga", p.Name)
	assert.Equal(t, "0.3.9", p.Version)
	assert.Equal(t, repo.URL+"/openfga", p.Provenance.URI)
	assert.Equal(t, "sha256:"+sha(archive), p.Provenance.Commit, "the archive's own digest")

	_, err = Pull(context.Background(), Source{HelmChart: &HelmChartSource{Repository: repo.URL, Chart: "openfga", Version: "0.3.8"}}, Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0.3.8 is not in the index")
}

func TestPullRegistryModule(t *testing.T) {
	upstream, sha := gitRepo(t, map[string]string{
		"main.tf":             `module "inner" { source = "./modules/sub" }`,
		"modules/sub/main.tf": `module "shared" { source = "../../shared" }`,
		"shared/main.tf":      `# shared`,
	})
	fake := newFakeRegistry(t, []string{"1.0.0", "1.2.0"}, "git::file://"+upstream+"?ref="+sha, "header")

	pull := func(address, version string) (*Pulled, error) {
		scratch := t.TempDir()
		f := newFetcher(scratch, Options{Git: testGit{}})
		fake.seed(f.registry)
		return pullTreeWith(context.Background(), Source{RegistryModule: &RegistryModuleSource{Address: address, Version: version}}, f, func() {})
	}

	p, err := pull("example.test/acme/net/google", "~> 1.0")
	require.NoError(t, err)
	assert.Equal(t, "net", p.Name)
	assert.Equal(t, "1.2.0", p.Version, "the newest that satisfies")
	assert.Equal(t, "example.test/acme/net/google", p.Provenance.URI)
	assert.Equal(t, "~> 1.0", p.Provenance.Ref)
	assert.Equal(t, "1.2.0", p.Provenance.Commit)
	assert.Equal(t, p.Boundary, p.Dir, "the root module is the fetched tree")

	// The pulled module packs like any other, with the boundary keeping its
	// relative calls inside the fetched tree.
	packed, err := PackContext(context.Background(), p.Dir, Options{Boundary: p.Boundary})
	require.NoError(t, err)
	assert.Equal(t, KindTerraform, packed.Kind)
	assert.Empty(t, packed.Vendored, "everything it calls is already inside")

	// A subdirectory of the package is the module; its name is the directory's.
	p, err = pull("example.test/acme/net/google//modules/sub", "")
	require.NoError(t, err)
	assert.Equal(t, "sub", p.Name)
	assert.NotEqual(t, p.Boundary, p.Dir)
	packed, err = PackContext(context.Background(), p.Dir, Options{Boundary: p.Boundary})
	require.NoError(t, err)
	assert.Equal(t, []Vendored{{Caller: ".", Source: "../../shared", Into: "vendor/shared"}}, packed.Vendored, "the sibling it reaches comes along")

	_, err = pull("example.test/acme/net/google", "~> 9.0")
	assert.ErrorIs(t, err, ErrRegistryNoVersion)
	_, err = pull("git::https://example.test/x.git", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a module registry address")
}

func TestPullGitTree(t *testing.T) {
	upstream, sha := gitRepo(t, map[string]string{
		"modules/np/main.tf":       `module "meta" { source = "../metadata" }`,
		"modules/metadata/main.tf": `# metadata`,
		"README.md":                `x`,
	})
	opts := Options{Git: testGit{}}

	p, err := Pull(context.Background(), Source{GitTree: &GitTreeSource{URL: "file://" + upstream, Ref: sha, Path: "modules/np"}}, opts)
	require.NoError(t, err)
	defer p.Cleanup()
	assert.Equal(t, "np", p.Name)
	assert.Empty(t, p.Version)
	assert.Equal(t, "git::file://"+upstream, p.Provenance.URI)
	assert.Equal(t, sha, p.Provenance.Ref)
	assert.Equal(t, sha, p.Provenance.Commit)
	packed, err := PackContext(context.Background(), p.Dir, Options{Boundary: p.Boundary, Git: testGit{}})
	require.NoError(t, err)
	assert.Equal(t, []Vendored{{Caller: ".", Source: "../metadata", Into: "vendor/metadata"}}, packed.Vendored)

	// The whole repository, named after it.
	p, err = Pull(context.Background(), Source{GitTree: &GitTreeSource{URL: "file://" + upstream}}, opts)
	require.NoError(t, err)
	defer p.Cleanup()
	assert.Equal(t, filepath.Base(upstream), p.Name)
	assert.Equal(t, p.Boundary, p.Dir)

	_, err = Pull(context.Background(), Source{GitTree: &GitTreeSource{URL: "file://" + upstream, Path: "modules/nope"}}, opts)
	assert.ErrorIs(t, err, ErrSubdirMissing)
	_, err = Pull(context.Background(), Source{GitTree: &GitTreeSource{URL: "file://" + upstream, Path: "../etc"}}, opts)
	require.Error(t, err)
	_, err = Pull(context.Background(), Source{GitTree: &GitTreeSource{URL: "file://" + upstream}}, Options{})
	assert.ErrorIs(t, err, ErrNoGitTransport)
}

func TestPullArchive(t *testing.T) {
	archive := tgz(t, "net-1.0.0", map[string]string{"main.tf": `variable "x" {}`})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/archives/net-1.0.0.tar.gz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)

	p, err := Pull(context.Background(), Source{Archive: &ArchiveSource{URL: srv.URL + "/archives/net-1.0.0.tar.gz"}}, Options{})
	require.NoError(t, err)
	defer p.Cleanup()
	assert.Equal(t, "net-1.0.0", p.Name)
	assert.Equal(t, srv.URL+"/archives/net-1.0.0.tar.gz", p.Provenance.URI)
	assert.True(t, strings.HasPrefix(p.Provenance.Commit, "sha256:"))
	assert.FileExists(t, filepath.Join(p.Dir, "main.tf"))

	dir := p.Dir
	p.Cleanup()
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "cleanup removes the tree")
}

func TestArchiveName(t *testing.T) {
	for in, want := range map[string]string{
		"https://h/a/net-1.0.0.tar.gz": "net-1.0.0",
		"https://h/a/net.tgz":          "net",
		"https://h/a/net.zip":          "net",
		"https://h/a/net":              "net",
	} {
		assert.Equal(t, want, archiveName(in), in)
	}
	assert.Equal(t, "infra", gitTreeName(&GitTreeSource{URL: "https://github.com/acme/infra.git"}))
	assert.Equal(t, "infra", gitTreeName(&GitTreeSource{URL: "ssh://git@github.com/acme/infra"}))
}
