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
func helmRepo(t *testing.T, name, version string, archive []byte, digest string) *httptest.Server {
	t.Helper()
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

// chartArchive is openfga 0.3.9 as a repository would serve it.
func chartArchive(t *testing.T) []byte {
	t.Helper()
	const name, version = "openfga", "0.3.9"
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

// wrapperChart is the deploy repository's shape: a thin chart around one
// upstream dependency, lock committed, charts/ not.
func wrapperChart(t *testing.T, repoURL, lock string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, data string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644))
	}
	write("Chart.yaml", "apiVersion: v2\nname: openfga\nversion: 0.1.0\ndependencies:\n  - name: openfga\n    version: \"^0.3.0\"\n    repository: "+repoURL+"\n")
	if lock != "" {
		write("Chart.lock", lock)
	}
	write("values.yaml", "openfga:\n  replicaCount: 1\n")
	return dir
}

func TestPackVendorsChartDependenciesFromTheLock(t *testing.T) {
	archive := chartArchive(t)
	repo := helmRepo(t, "openfga", "0.3.9", archive, "sha256:"+sha(archive))
	dir := wrapperChart(t, repo.URL, "dependencies:\n- name: openfga\n  repository: "+repo.URL+"\n  version: 0.3.9\ndigest: sha256:abc\n")

	p, err := Pack(dir)
	require.NoError(t, err)
	assert.Equal(t, KindHelm, p.Kind)
	files := entries(t, p.Bytes)
	assert.Equal(t, string(archive), files["charts/openfga-0.3.9.tgz"], "the archive lands under charts/, byte for byte")
	assert.Equal(t, []Vendored{{Caller: ".", Source: repo.URL + "/openfga 0.3.9", Into: "charts/openfga-0.3.9.tgz"}}, p.Vendored)
	assert.Equal(t, []Pin{{Source: repo.URL + "/openfga", Constraint: "^0.3.0", Resolved: "0.3.9"}}, p.Pins)

	// The working copy was not touched.
	_, err = os.Stat(filepath.Join(dir, "charts"))
	assert.True(t, os.IsNotExist(err))
}

func TestPackKeepsADependencyAlreadyUnderCharts(t *testing.T) {
	// Nothing is served: a repository that would fail if asked.
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	t.Cleanup(repo.Close)
	dir := wrapperChart(t, repo.URL, "dependencies:\n- name: openfga\n  repository: "+repo.URL+"\n  version: 0.3.9\n")
	archive := chartArchive(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "charts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "charts", "openfga-0.3.9.tgz"), archive, 0o644))

	p, err := Pack(dir)
	require.NoError(t, err)
	assert.Empty(t, p.Vendored, "already there; nothing fetched")
	assert.Equal(t, "0.3.9", p.Pins[0].Resolved, "but still pinned")
}

func TestPackRefusesWhatTheLockCannotVouchFor(t *testing.T) {
	archive := chartArchive(t)
	repo := helmRepo(t, "openfga", "0.3.9", archive, "sha256:"+sha(archive))

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
		dir := wrapperChart(t, repo.URL, "dependencies:\n- name: openfga\n  repository: "+repo.URL+"\n  version: 0.3.8\n")
		_, err := Pack(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "0.3.8 is not in the index")
	})
	t.Run("alias", func(t *testing.T) {
		dir := wrapperChart(t, "\"@acme\"", "dependencies:\n- name: openfga\n  repository: \"@acme\"\n  version: 0.3.9\n")
		_, err := Pack(dir)
		assert.ErrorIs(t, err, ErrChartDependencyUnsupported)
	})
}

func TestPackRefusesAnArchiveTheIndexDisowns(t *testing.T) {
	archive := chartArchive(t)
	repo := helmRepo(t, "openfga", "0.3.9", archive, "sha256:"+sha([]byte("something else")))
	dir := wrapperChart(t, repo.URL, "dependencies:\n- name: openfga\n  repository: "+repo.URL+"\n  version: 0.3.9\n")
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
	got, err := resolveChartURL("https://charts.example.com/stable", "openfga-0.3.9.tgz")
	require.NoError(t, err)
	assert.Equal(t, "https://charts.example.com/stable/openfga-0.3.9.tgz", got)
	got, err = resolveChartURL("https://charts.example.com/stable", "https://github.com/acme/releases/openfga-0.3.9.tgz")
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/acme/releases/openfga-0.3.9.tgz", got)
}
