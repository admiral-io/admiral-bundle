package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helmRepo serves a Helm repository: an index naming one chart at one
// version, and the archive it points at, relative to the repository the
// way most indexes do. digest is the index's claim about the archive.
func helmRepo(t *testing.T, archive []byte, digest string) *httptest.Server {
	t.Helper()
	const name, version = "sample", "0.3.9"
	mux := http.NewServeMux()
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "apiVersion: v1\nentries:\n  %s:\n  - version: %s\n    urls:\n    - %s-%s.tgz\n    digest: %s\n",
			name, version, name, version, digest)
	})
	mux.HandleFunc(fmt.Sprintf("/%s-%s.tgz", name, version), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// chartArchive is sample 0.3.9 as a repository would serve it.
func chartArchive(t *testing.T) []byte {
	t.Helper()
	const name, version = "sample", "0.3.9"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	data := fmt.Sprintf("apiVersion: v2\nname: %s\nversion: %s\n", name, version)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: name + "/Chart.yaml", Mode: 0o644, Size: int64(len(data))}))
	_, _ = tw.Write([]byte(data))
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// wrapperChart is the common shape of a deployment chart: a thin chart
// around one upstream dependency, lock committed, charts/ not.
func wrapperChart(t *testing.T, repoURL, lock string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, data string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644))
	}
	write("Chart.yaml", "apiVersion: v2\nname: sample\nversion: 0.1.0\ndependencies:\n  - name: sample\n    version: \"^0.3.0\"\n    repository: "+repoURL+"\n")
	if lock != "" {
		write("Chart.lock", lock)
	}
	write("values.yaml", "sample:\n  replicaCount: 1\n")
	return dir
}

func TestPackVendorsChartDependenciesFromTheLock(t *testing.T) {
	archive := chartArchive(t)
	repo := helmRepo(t, archive, "sha256:"+sha(archive))
	dir := wrapperChart(t, repo.URL, "dependencies:\n- name: sample\n  repository: "+repo.URL+"\n  version: 0.3.9\ndigest: sha256:abc\n")

	p, err := Pack(dir)
	require.NoError(t, err)
	assert.Equal(t, KindHelm, p.Kind)
	files := entries(t, p.Bytes)
	assert.Equal(t, string(archive), files["charts/sample-0.3.9.tgz"], "the archive lands under charts/, byte for byte")
	assert.Equal(t, []Vendored{{Caller: ".", Source: repo.URL + "/sample 0.3.9", Into: "charts/sample-0.3.9.tgz"}}, p.Vendored)
	assert.Equal(t, []Pin{{Source: repo.URL + "/sample", Constraint: "^0.3.0", Resolved: "0.3.9"}}, p.Pins)

	// The working copy was not touched.
	_, err = os.Stat(filepath.Join(dir, "charts"))
	assert.True(t, os.IsNotExist(err))
}

func TestPackKeepsADependencyAlreadyUnderCharts(t *testing.T) {
	// Nothing is served: a repository that would fail if asked.
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	t.Cleanup(repo.Close)
	dir := wrapperChart(t, repo.URL, "dependencies:\n- name: sample\n  repository: "+repo.URL+"\n  version: 0.3.9\n")
	archive := chartArchive(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "charts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "charts", "sample-0.3.9.tgz"), archive, 0o644))

	p, err := Pack(dir)
	require.NoError(t, err)
	assert.Empty(t, p.Vendored, "already there; nothing fetched")
	assert.Equal(t, "0.3.9", p.Pins[0].Resolved, "but still pinned")
}

func TestPackRefusesWhatTheLockCannotVouchFor(t *testing.T) {
	archive := chartArchive(t)
	repo := helmRepo(t, archive, "sha256:"+sha(archive))

	t.Run("no lock", func(t *testing.T) {
		_, err := Pack(wrapperChart(t, repo.URL, ""))
		assert.ErrorIs(t, err, ErrChartLockMissing)
	})
	t.Run("lock names a dependency Chart.yaml does not", func(t *testing.T) {
		dir := wrapperChart(t, repo.URL, "dependencies:\n- name: redis\n  repository: "+repo.URL+"\n  version: 1.0.0\n")
		_, err := Pack(dir)
		assert.ErrorIs(t, err, ErrChartLockStale)
	})
	t.Run("version not in the index", func(t *testing.T) {
		dir := wrapperChart(t, repo.URL, "dependencies:\n- name: sample\n  repository: "+repo.URL+"\n  version: 0.3.8\n")
		_, err := Pack(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "0.3.8 is not in the index")
	})
	t.Run("alias", func(t *testing.T) {
		dir := wrapperChart(t, "\"@acme\"", "dependencies:\n- name: sample\n  repository: \"@acme\"\n  version: 0.3.9\n")
		_, err := Pack(dir)
		assert.ErrorIs(t, err, ErrChartDependencyUnsupported)
	})
}

func TestPackRefusesAnArchiveTheIndexDisowns(t *testing.T) {
	archive := chartArchive(t)
	repo := helmRepo(t, archive, "sha256:"+sha([]byte("something else")))
	dir := wrapperChart(t, repo.URL, "dependencies:\n- name: sample\n  repository: "+repo.URL+"\n  version: 0.3.9\n")
	_, err := Pack(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match the index's digest")
}

func TestPackVendorsAFileDependency(t *testing.T) {
	base := t.TempDir()
	lib := filepath.Join(base, "lib")
	require.NoError(t, os.MkdirAll(lib, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(lib, "Chart.yaml"), []byte("apiVersion: v2\nname: lib\nversion: 0.1.0\n"), 0o644))
	dir := filepath.Join(base, "app")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\ndependencies:\n  - name: lib\n    version: 0.1.0\n    repository: file://../lib\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.lock"), []byte("dependencies:\n- name: lib\n  repository: file://../lib\n  version: 0.1.0\n"), 0o644))

	p, err := Pack(dir)
	require.NoError(t, err)
	files := entries(t, p.Bytes)
	assert.Contains(t, files, "charts/lib/Chart.yaml")
	assert.Equal(t, []Pin{{Source: "file://../lib/lib", Constraint: "0.1.0", Resolved: "0.1.0"}}, p.Pins)
}

func TestResolveChartURL(t *testing.T) {
	got, err := resolveChartURL("https://charts.example.com/stable", "sample-0.3.9.tgz")
	require.NoError(t, err)
	assert.Equal(t, "https://charts.example.com/stable/sample-0.3.9.tgz", got)
	got, err = resolveChartURL("https://charts.example.com/stable", "https://github.com/acme/releases/sample-0.3.9.tgz")
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/acme/releases/sample-0.3.9.tgz", got)
}

// A file:// dependency is a chart with dependencies of its own; it is
// closed the same way, and what it lacks is named with its place.
func TestPackClosesADirectoryDependencyInTurn(t *testing.T) {
	base := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(base, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
	write("common/Chart.yaml", "apiVersion: v2\nname: common\nversion: 0.1.0\n")
	write("lib/Chart.yaml", "apiVersion: v2\nname: lib\nversion: 0.1.0\ndependencies:\n  - name: common\n    version: 0.1.0\n    repository: file://../common\n")
	write("app/Chart.yaml", "apiVersion: v2\nname: app\nversion: 0.1.0\ndependencies:\n  - name: lib\n    version: 0.1.0\n    repository: file://../lib\n")
	write("app/Chart.lock", "dependencies:\n- name: lib\n  repository: file://../lib\n  version: 0.1.0\n")

	_, err := Pack(filepath.Join(base, "app"))
	assert.ErrorIs(t, err, ErrChartLockMissing, "lib has dependencies and no lock")
	assert.Contains(t, err.Error(), "charts/lib")

	write("lib/Chart.lock", "dependencies:\n- name: common\n  repository: file://../common\n  version: 0.1.0\n")
	p, err := Pack(filepath.Join(base, "app"))
	require.NoError(t, err)
	files := entries(t, p.Bytes)
	assert.Contains(t, files, "charts/lib/Chart.yaml")
	assert.Contains(t, files, "charts/lib/charts/common/Chart.yaml", "lib's own dependency is vendored beneath it")
	assert.Equal(t, []Vendored{
		{Caller: ".", Source: "file://../lib/lib 0.1.0", Into: "charts/lib"},
		{Caller: "charts/lib", Source: "file://../common/common 0.1.0", Into: "charts/lib/charts/common"},
	}, p.Vendored)
	assert.Equal(t, []Pin{
		{Source: "file://../lib/lib", Constraint: "0.1.0", Resolved: "0.1.0"},
		{Source: "file://../common/common", Constraint: "0.1.0", Resolved: "0.1.0"},
	}, p.Pins)

	// The server's walk sees the same thing.
	n, err := Normalize(bytes.NewReader(p.Bytes))
	require.NoError(t, err)
	require.NoError(t, CloseChart(n.Files))

	// An unpacked subchart the author left under charts/ is a chart too.
	write("app2/Chart.yaml", "apiVersion: v2\nname: app2\nversion: 0.1.0\ndependencies:\n  - name: lib\n    version: 0.1.0\n    repository: file://../lib\n")
	write("app2/Chart.lock", "dependencies:\n- name: lib\n  repository: file://../lib\n  version: 0.1.0\n")
	write("app2/charts/lib/Chart.yaml", "apiVersion: v2\nname: lib\nversion: 0.1.0\ndependencies:\n  - name: common\n    version: 0.1.0\n    repository: https://charts.example.test\n")
	_, err = Pack(filepath.Join(base, "app2"))
	assert.ErrorIs(t, err, ErrChartLockMissing)
}
