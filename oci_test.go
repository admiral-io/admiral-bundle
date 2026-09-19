package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOCI serves one chart at one tag over the distribution protocol, with
// an optional bearer challenge whose token service takes basic auth.
type fakeOCI struct {
	srv       *httptest.Server
	name      string
	tag       string
	manifest  []byte
	layer     []byte
	layerType string
	// auth, when set, is the basic credential the token service accepts.
	auth   *BasicAuth
	tokens int
}

func newFakeOCI(t *testing.T, name, tag string, layer []byte, layerType string, auth *BasicAuth) *fakeOCI {
	t.Helper()
	f := &fakeOCI{name: name, tag: tag, layer: layer, layerType: layerType, auth: auth}
	digest := func(b []byte) string {
		sum := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	m := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    ocispec.Descriptor{MediaType: "application/vnd.cncf.helm.config.v1+json", Digest: "sha256:0", Size: 0},
		Layers:    []ocispec.Descriptor{{MediaType: layerType, Digest: godigest.Digest(digest(layer)), Size: int64(len(layer))}},
	}
	m.SchemaVersion = 2
	f.manifest, _ = json.Marshal(m)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != f.auth.Username || p != f.auth.Password {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		f.tokens++
		_, _ = w.Write([]byte(`{"token":"t0k"}`))
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if f.auth != nil && r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake",scope="repository:%s:pull"`, f.srv.URL, name))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/v2/"+name+"/manifests/"+tag:
			w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
			w.Header().Set("Docker-Content-Digest", digest(f.manifest))
			_, _ = w.Write(f.manifest)
		case strings.HasPrefix(r.URL.Path, "/v2/"+name+"/blobs/"):
			if strings.TrimPrefix(r.URL.Path, "/v2/"+name+"/blobs/") != digest(layer) {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(layer)
		default:
			http.NotFound(w, r)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// repository is the oci:// repository URL the chart lives under, minus name.
func (f *fakeOCI) repository() string {
	return "oci://" + strings.TrimPrefix(f.srv.URL, "http://") + "/" + strings.TrimSuffix(f.name, "/"+chartName(f.name))
}

func chartName(name string) string { return name[strings.LastIndex(name, "/")+1:] }

func TestOCIPullChart(t *testing.T) {
	archive := chartArchive(t)
	ctx := context.Background()

	t.Run("anonymous", func(t *testing.T) {
		reg := newFakeOCI(t, "acme/charts/openfga", "0.3.9", archive, helmChartLayer, nil)
		c := newOCIClient(nil)
		c.docker = nil
		data, digest, err := c.pullChart(ctx, reg.repository(), "openfga", "0.3.9")
		require.NoError(t, err)
		assert.Equal(t, archive, data)
		assert.True(t, strings.HasPrefix(digest, "sha256:"))
	})

	t.Run("bearer challenge with the seam's basic auth", func(t *testing.T) {
		reg := newFakeOCI(t, "acme/charts/openfga", "0.3.9", archive, helmChartLayer, &BasicAuth{Username: "u", Password: "p"})
		c := newOCIClient(staticCredentials{reg.repository(): {Basic: &BasicAuth{Username: "u", Password: "p"}}})
		c.docker = nil
		data, _, err := c.pullChart(ctx, reg.repository(), "openfga", "0.3.9")
		require.NoError(t, err)
		assert.Equal(t, archive, data)
		assert.Equal(t, 1, reg.tokens, "one token exchange")

		c = newOCIClient(staticCredentials{reg.repository(): {Basic: &BasicAuth{Username: "u", Password: "wrong"}}})
		c.docker = nil
		_, _, err = c.pullChart(ctx, reg.repository(), "openfga", "0.3.9")
		require.Error(t, err)

		c = newOCIClient(staticCredentials{reg.repository(): {SSHKey: &SSHKey{PEM: []byte("k")}}})
		c.docker = nil
		_, _, err = c.pullChart(ctx, reg.repository(), "openfga", "0.3.9")
		assert.ErrorIs(t, err, ErrCredentialFamily)
	})

	t.Run("not a chart", func(t *testing.T) {
		reg := newFakeOCI(t, "acme/images/app", "v1", []byte("rootfs"), ocispec.MediaTypeImageLayerGzip, nil)
		c := newOCIClient(nil)
		c.docker = nil
		_, _, err := c.pullChart(ctx, reg.repository(), "app", "v1")
		assert.ErrorIs(t, err, ErrOCINotAChart)
	})

	t.Run("wrapper chart with an oci dependency", func(t *testing.T) {
		reg := newFakeOCI(t, "acme/charts/openfga", "0.3.9", archive, helmChartLayer, nil)
		dir := wrapperChart(t, reg.repository(), "dependencies:\n- name: openfga\n  repository: "+reg.repository()+"\n  version: 0.3.9\n")
		p, err := Pack(dir)
		require.NoError(t, err)
		assert.Contains(t, entries(t, p.Bytes), "charts/openfga-0.3.9.tgz")
		assert.Equal(t, []Vendored{{Caller: ".", Source: reg.repository() + "/openfga 0.3.9", Into: "charts/openfga-0.3.9.tgz"}}, p.Vendored)
		assert.Equal(t, []Pin{{Source: reg.repository() + "/openfga", Constraint: "^0.3.0", Resolved: "0.3.9"}}, p.Pins)
	})
}
