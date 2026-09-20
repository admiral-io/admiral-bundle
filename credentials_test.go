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

func TestAmbientCredentials(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, ".tofurc"), []byte(
		"credentials \"app.terraform.io\" {\n  token = \"from-rc\"\n}\n"+
			"credentials \"registry.acme-corp.example\" {\n  token = \"acme-rc\"\n}\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".terraform.d"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".terraform.d", "credentials.tfrc.json"), []byte(
		`{"credentials": {"login.example": {"token": "from-login"}}}`), 0o644))

	require.NoError(t, os.WriteFile(filepath.Join(home, "repositories.yaml"), []byte(
		"repositories:\n- name: acme\n  url: https://charts.acme.example/stable\n  username: helm-user\n  password: helm-pw\n- name: public\n  url: https://charts.public.example\n"), 0o644))

	a := &AmbientCredentials{home: home, environ: []string{
		"HELM_REPOSITORY_CONFIG=" + filepath.Join(home, "repositories.yaml"),
		"TF_TOKEN_registry_acme__corp_example=acme-env",
		"tf_token_lower_example=lower",
		"TF_TOKEN_empty_example=",
	}}
	lookup := func(u string) string {
		c, err := a.Lookup(context.Background(), u)
		require.NoError(t, err)
		if c == nil {
			return ""
		}
		return c.Token
	}
	assert.Equal(t, "from-rc", lookup("https://app.terraform.io/"))
	assert.Equal(t, "from-rc", lookup("https://APP.terraform.io/v1/modules/"))
	assert.Equal(t, "acme-env", lookup("https://registry.acme-corp.example/"), "the environment wins over the rc file")
	assert.Equal(t, "lower", lookup("https://lower.example/"), "the variable name is matched case-insensitively")
	assert.Equal(t, "from-login", lookup("https://login.example/"), "tofu login's file is read too")
	assert.Equal(t, "", lookup("https://empty.example/"))
	assert.Equal(t, "", lookup("https://registry.opentofu.org/"))

	c, err := a.Lookup(context.Background(), "https://charts.acme.example/stable/index.yaml")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, &BasicAuth{Username: "helm-user", Password: "helm-pw"}, c.Basic, "helm repo add --username")
	c, err = a.Lookup(context.Background(), "https://charts.acme.example/other/index.yaml")
	require.NoError(t, err)
	assert.Nil(t, c, "a prefix, not a host")
	c, err = a.Lookup(context.Background(), "https://charts.public.example/index.yaml")
	require.NoError(t, err)
	assert.Nil(t, c, "no username, nothing to present")

	// What git stores for https: netrc first, then the store helper's file.
	require.NoError(t, os.WriteFile(filepath.Join(home, ".netrc"), []byte(
		"machine gitlab.acme.example login deploy password nr-secret\ndefault login anon password anon-pw\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".git-credentials"), []byte(
		"https://x-access-token:ghp_stored@github.com\n"), 0o600))
	c, err = a.Lookup(context.Background(), "https://gitlab.acme.example/acme/infra.git")
	require.NoError(t, err)
	assert.Equal(t, &BasicAuth{Username: "deploy", Password: "nr-secret"}, c.Basic)
	c, err = a.Lookup(context.Background(), "https://github.com/acme/infra.git")
	require.NoError(t, err)
	assert.Equal(t, &BasicAuth{Username: "anon", Password: "anon-pw"}, c.Basic, "netrc's default entry wins over git-credentials")
	require.NoError(t, os.Remove(filepath.Join(home, ".netrc")))
	c, err = a.Lookup(context.Background(), "https://github.com/acme/infra.git")
	require.NoError(t, err)
	assert.Equal(t, &BasicAuth{Username: "x-access-token", Password: "ghp_stored"}, c.Basic)
	c, err = a.Lookup(context.Background(), "ssh://git@github.com/acme/infra.git")
	require.NoError(t, err)
	assert.Nil(t, c, "ssh is the agent's business")
}

func TestCredentialFamilies(t *testing.T) {
	req := func() *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "https://example.test/x", nil)
		return r
	}

	r := req()
	require.NoError(t, (&Credential{Token: "tok"}).authorize(r, false))
	assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))

	r = req()
	require.NoError(t, (&Credential{Basic: &BasicAuth{Username: "u", Password: "p"}}).authorize(r, false))
	u, p, ok := r.BasicAuth()
	assert.True(t, ok)
	assert.Equal(t, []string{"u", "p"}, []string{u, p})

	r = req()
	require.NoError(t, (*Credential)(nil).authorize(r, false))
	assert.Empty(t, r.Header.Get("Authorization"))

	assert.ErrorIs(t, (&Credential{SSHKey: &SSHKey{PEM: []byte("k")}}).authorize(req(), false), ErrCredentialFamily, "an ssh key has no HTTP form")

	// A credential rides https or nothing, unless the caller said cleartext
	// is fine (a test fixture, a registry on localhost).
	plain, _ := http.NewRequest(http.MethodGet, "http://example.test/x", nil)
	assert.ErrorIs(t, (&Credential{Token: "tok"}).authorize(plain, false), ErrInsecureHTTP)
	assert.Empty(t, plain.Header.Get("Authorization"))
	require.NoError(t, (&Credential{Token: "tok"}).authorize(plain, true))
	assert.Equal(t, "Bearer tok", plain.Header.Get("Authorization"))
	require.NoError(t, (*Credential)(nil).authorize(plain, false), "anonymous http is not a credential")
}

// staticCredentials answers by the longest registered prefix, the way a
// server's registered credentials would.
type staticCredentials map[string]*Credential

func (s staticCredentials) Lookup(_ context.Context, rawURL string) (*Credential, error) {
	var best string
	for prefix := range s {
		if strings.HasPrefix(rawURL, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best == "" {
		return nil, nil
	}
	return s[best], nil
}

func TestNewAmbientCredentialsReadsTheProcess(t *testing.T) {
	t.Setenv("TF_TOKEN_registry_example_test", "ambient")
	c := NewAmbientCredentials()
	cred, err := c.Lookup(context.Background(), "https://registry.example.test/")
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, "ambient", cred.Token)
}

func TestHelmRepositoryMatchIgnoresCaseInSchemeAndHost(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "repositories.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("repositories:\n- name: acme\n  url: HTTPS://Charts.Example.Test/Stable/\n  username: u\n  password: p\n"), 0o644))
	a := &AmbientCredentials{environ: []string{"HELM_REPOSITORY_CONFIG=" + cfg}, home: dir}

	cred, err := a.Lookup(context.Background(), "https://charts.example.test/Stable/sample-0.3.9.tgz")
	require.NoError(t, err)
	require.NotNil(t, cred, "host and scheme are case-insensitive")
	assert.Equal(t, "u", cred.Basic.Username)

	cred, err = a.Lookup(context.Background(), "https://charts.example.test/stable/sample-0.3.9.tgz")
	require.NoError(t, err)
	assert.Nil(t, cred, "the path is not")
}

func TestCredentialsRideHTTPSOnly(t *testing.T) {
	ctx := context.Background()
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(tgz(t, "net", map[string]string{"main.tf": ""}))
	}))
	t.Cleanup(srv.Close)
	creds := staticCredentials{srv.URL: {Token: "tok"}}
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "a" { source = "`+srv.URL+`/net.tgz" }`), 0o644))

	_, err := PackContext(ctx, root, Options{Credentials: creds})
	assert.ErrorIs(t, err, ErrInsecureHTTP, "an archive over http gets no credential")
	assert.Equal(t, 0, asked, "refused before the request")

	_, err = PackContext(ctx, root, Options{Credentials: creds, AllowInsecureHTTP: true})
	require.NoError(t, err, "unless the caller allowed it")

	// git over http with a credential is refused at the seam, before any
	// transport runs.
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "a" { source = "git::http://example.test/acme/x.git" }`), 0o644))
	_, err = PackContext(ctx, root, Options{Credentials: staticCredentials{"http://example.test": {Token: "tok"}}, Git: testGit{}})
	assert.ErrorIs(t, err, ErrInsecureHTTP)

	// A chart repository over http, likewise.
	dir := wrapperChart(t, srv.URL, "dependencies:\n- name: sample\n  repository: "+srv.URL+"\n  version: 0.3.9\n")
	_, err = PackContext(ctx, dir, Options{Credentials: creds})
	assert.ErrorIs(t, err, ErrInsecureHTTP)
}
