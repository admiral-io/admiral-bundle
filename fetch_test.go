package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-version"
	tfaddr "github.com/hashicorp/terraform-registry-address"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassify(t *testing.T) {
	cases := map[string]sourceKind{
		"./x":                                    sourceLocal,
		"../modules/net":                         sourceLocal,
		".":                                      sourceLocal,
		"GoogleCloudPlatform/cloud-armor/google": sourceRegistry,
		"terraform-google-modules/log-export/google//modules/storage": sourceRegistry,
		"app.terraform.io/acme/net/google":                            sourceRegistry,
		"github.com/acme/infra":                                       sourceRemote, // two parts after a reserved host: go-getter's
		"github.com/acme/infra//modules/x":                            sourceRemote,
		"git::ssh://git@github.com/acme/infra.git//modules/x?ref=abc": sourceRemote,
		"git@github.com:acme/infra.git":                               sourceRemote,
		"https://example.com/mod.zip":                                 sourceRemote,
		"git::https://github.com/acme/infra.git":                      sourceRemote,
		"s3::https://s3.amazonaws.com/b/k.zip":                        sourceUnsupported,
		"gcs::https://www.googleapis.com/storage/v1/b/k":              sourceUnsupported,
		"hg::http://example.com/repo":                                 sourceUnsupported,
		"var.src":                                                     sourceNonLiteral,
		"local.src":                                                   sourceNonLiteral,
	}
	for source, want := range cases {
		got, _ := classify(source)
		assert.Equal(t, want, got, source)
	}
}

func TestSelectVersion(t *testing.T) {
	var vs []*version.Version
	for _, s := range []string{"9.1.0-rc1", "9.0.0", "8.1.1", "8.1.0", "8.0.0", "7.9.0"} {
		vs = append(vs, version.Must(version.NewVersion(s)))
	}
	pick := func(c string) string {
		v, err := selectVersion(vs, c)
		if err != nil {
			return err.Error()
		}
		return v.Original()
	}
	assert.Equal(t, "8.1.1", pick("~> 8.0"))
	assert.Equal(t, "8.0.0", pick("= 8.0.0"))
	assert.Equal(t, "9.0.0", pick(""), "no constraint is the newest release, never a prerelease")
	assert.Equal(t, "9.0.0", pick(">= 8.1"))
	assert.Equal(t, "9.1.0-rc1", pick("= 9.1.0-rc1"), "a prerelease is chosen only when named")
	assert.Contains(t, pick("~> 10.0"), ErrRegistryNoVersion.Error())
}

func TestGitRepoKey(t *testing.T) {
	cases := map[string]string{
		"ssh://git@github.com/acme/infra.git":  "github.com/acme/infra",
		"https://github.com/acme/infra.git":    "github.com/acme/infra",
		"https://github.com/Acme/infra":        "github.com/Acme/infra",
		"git@github.com:acme/infra.git":        "github.com/acme/infra",
		"ssh://git@github.com:2222/acme/infra": "github.com/acme/infra",
	}
	for remote, want := range cases {
		assert.Equal(t, want, RepoKeyOf(remote), remote)
	}
}

// fakeRegistry serves the module registry protocol for one package, in
// either download shape, and counts bearer tokens it saw.
type fakeRegistry struct {
	srv      *httptest.Server
	location string
	versions []string
	shape    string // "header" or "body"
	tokens   []string
}

const fakePkg = "acme/net/google"

// fakeHost is the registry host name the fakes stand in for.
const fakeHost = "example.test"

func newFakeRegistry(t *testing.T, versions []string, location, shape string) *fakeRegistry {
	t.Helper()
	pkg := fakePkg
	f := &fakeRegistry{versions: versions, location: location, shape: shape}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"modules.v1": "/api/modules/"}`))
	})
	mux.HandleFunc("/api/modules/"+pkg+"/versions", func(w http.ResponseWriter, r *http.Request) {
		f.tokens = append(f.tokens, r.Header.Get("Authorization"))
		var vs []map[string]string
		for _, v := range f.versions {
			vs = append(vs, map[string]string{"version": v})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"modules": []any{map[string]any{"versions": vs}}})
	})
	mux.HandleFunc("/api/modules/"+pkg+"/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/download") {
			http.NotFound(w, r)
			return
		}
		switch f.shape {
		case "header":
			w.Header().Set("X-Terraform-Get", f.location)
			w.WriteHeader(http.StatusNoContent)
		default:
			_ = json.NewEncoder(w).Encode(map[string]string{"location": f.location})
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// seed points a registryClient at the fake for fakeHost, skipping discovery
// over https.
func (f *fakeRegistry) seed(r *registryClient) {
	u, _ := url.Parse(f.srv.URL + "/api/modules/")
	r.services[fakeHost] = u
}

type staticCreds map[string]string

func (s staticCreds) Lookup(_ context.Context, rawURL string) (*Credential, error) {
	if tok, ok := s[hostOf(rawURL)]; ok {
		return &Credential{Token: tok}, nil
	}
	return nil, nil
}

func TestRegistryClient(t *testing.T) {
	ctx := context.Background()
	for _, shape := range []string{"header", "body"} {
		t.Run(shape, func(t *testing.T) {
			fake := newFakeRegistry(t, []string{"1.0.0", "1.2.0", "1.1.0"}, "git::https://example.invalid/acme/net?ref=abc", shape)
			r := newRegistryClient(Options{Credentials: staticCreds{"example.test": "tok"}, AllowInsecureHTTP: true})
			fake.seed(r)

			m := mustParse(t, "example.test/acme/net/google")
			vs, err := r.Versions(ctx, m.Package)
			require.NoError(t, err)
			assert.Equal(t, "1.2.0", vs[0].Original(), "newest first")
			assert.Equal(t, []string{"Bearer tok"}, fake.tokens)

			loc, err := r.Location(ctx, m.Package, vs[0])
			require.NoError(t, err)
			assert.Equal(t, "git::https://example.invalid/acme/net?ref=abc", loc)

			_, err = r.Versions(ctx, m.Package)
			require.NoError(t, err)
			assert.Len(t, fake.tokens, 1, "versions are cached per package")
		})
	}

	t.Run("relative location", func(t *testing.T) {
		fake := newFakeRegistry(t, []string{"1.0.0"}, "/archives/net-1.0.0.tgz", "header")
		r := newRegistryClient(Options{})
		fake.seed(r)
		m := mustParse(t, "example.test/acme/net/google")
		loc, err := r.Location(ctx, m.Package, version.Must(version.NewVersion("1.0.0")))
		require.NoError(t, err)
		assert.Equal(t, fake.srv.URL+"/archives/net-1.0.0.tgz", loc)
	})

	t.Run("default host", func(t *testing.T) {
		m := mustParse(t, "GoogleCloudPlatform/cloud-armor/google")
		assert.Equal(t, DefaultRegistryHost, registryHost(m.Package))
		assert.Equal(t, "registry.opentofu.org/GoogleCloudPlatform/cloud-armor/google", registryAddress(m.Package))
	})
}

// --- The walk, end to end ---------------------------------------------------

// testGit is the smallest GitTransport: clone with the git binary, check out
// the ref, report HEAD. gitcmd and gitgo are the real ones and have their
// own tests; the walk's tests only need a clone to happen.
type testGit struct{}

func (testGit) Clone(ctx context.Context, u *url.URL, ref, dst string, _ *Credential) (string, error) {
	remote := *u
	remote.RawQuery = ""
	run := func(dir string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("git %v: %s", args, out)
		}
		return strings.TrimSpace(string(out)), nil
	}
	if _, err := run(".", "clone", "-q", remote.String(), dst); err != nil {
		return "", err
	}
	if ref != "" {
		if _, err := run(dst, "checkout", "-q", ref); err != nil {
			return "", err
		}
	}
	return run(dst, "rev-parse", "HEAD")
}

// gitRepo makes a repository with the given files committed, and returns
// its path and HEAD.
func gitRepo(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")
	return dir, run("rev-parse", "HEAD")
}

// tgz builds a gzipped tar of files under one top-level directory.
func tgz(t *testing.T, top string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: top + "/" + name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}))
		_, _ = tw.Write([]byte(data))
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func closeInStage(t *testing.T, root string, f *fetcher) (stage string, vendored []Vendored) {
	t.Helper()
	stage = t.TempDir()
	require.NoError(t, copyTree(root, stage, root, false))
	vendored, err := closeTerraform(context.Background(), root, stage, f)
	require.NoError(t, err)
	return stage, vendored
}

func readStage(t *testing.T, stage, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stage, filepath.FromSlash(rel)))
	require.NoError(t, err, rel)
	return string(b)
}

func TestCloseRegistryModule(t *testing.T) {
	// The registry says the module lives in a git repository; the module's
	// own tree has a submodule at modules/sub that calls ../../shared, and
	// carries a lock file that must not travel.
	upstream, sha := gitRepo(t, map[string]string{
		"main.tf":                `module "inner" { source = "./modules/sub" }`,
		"modules/sub/main.tf":    `module "shared" { source = "../../shared" }`,
		"shared/main.tf":         `# shared`,
		".terraform.lock.hcl":    `# lock`,
		"examples/basic/main.tf": `# example`,
	})
	fake := newFakeRegistry(t, []string{"1.0.0", "1.2.0"}, "git::file://"+upstream+"?ref="+sha, "header")

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(strings.Join([]string{
		`module "a" {`,
		`  source  = "example.test/acme/net/google"`,
		`  version = "~> 1.0"`,
		`}`,
		`module "b" {`,
		`  source  = "example.test/acme/net/google//modules/sub"`,
		`  version = "~> 1.0"`,
		`}`,
	}, "\n")), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".terraform.lock.hcl"), []byte("# root lock"), 0o644))

	f := newFetcher(t.TempDir(), Options{Git: testGit{}})
	fake.seed(f.registry)
	stage, vendored := closeInStage(t, root, f)

	prefix := "vendor/example.test/acme/net/google/1.2.0"
	assert.Equal(t, []Vendored{
		{Caller: ".", Source: "example.test/acme/net/google", Into: prefix},
	}, vendored, "the root brought the whole tree; //modules/sub was already inside it")
	assert.Equal(t, []Pin{{Source: "example.test/acme/net/google", Constraint: "~> 1.0", Resolved: "1.2.0"}}, f.pins)

	main := readStage(t, stage, "main.tf")
	assert.Contains(t, main, `source  = "./`+prefix+`"`)
	assert.Contains(t, main, `source  = "./`+prefix+`/modules/sub"`)
	assert.Contains(t, readStage(t, stage, prefix+"/modules/sub/main.tf"), `"../../shared"`, "an in-tree relative call needs no rewrite")
	assert.Equal(t, "# root lock", readStage(t, stage, ".terraform.lock.hcl"))
	_, err := os.Stat(filepath.Join(stage, prefix, ".terraform.lock.hcl"))
	assert.True(t, os.IsNotExist(err), "the vendored lock file is dropped")
	_, err = os.Stat(filepath.Join(stage, prefix, ".git"))
	assert.True(t, os.IsNotExist(err))
	assert.FileExists(t, filepath.Join(stage, prefix, "examples/basic/main.tf"), "a registry root is its repository, whole")
}

func TestCloseRegistrySubdirBringsWhatItReaches(t *testing.T) {
	upstream, sha := gitRepo(t, map[string]string{
		"README.md":                  `big`,
		"modules/sub/main.tf":        `module "shared" { source = "../../shared" }`,
		"shared/main.tf":             `# shared`,
		"shared/.terraform.lock.hcl": `# lock`,
		"other/main.tf":              `# never called`,
	})
	fake := newFakeRegistry(t, []string{"1.0.0"}, "git::file://"+upstream+"?ref="+sha, "body")
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "b" { source = "example.test/acme/net/google//modules/sub" }`), 0o644))

	f := newFetcher(t.TempDir(), Options{Git: testGit{}})
	fake.seed(f.registry)
	stage, vendored := closeInStage(t, root, f)

	prefix := "vendor/example.test/acme/net/google/1.0.0"
	assert.Equal(t, []Vendored{
		{Caller: ".", Source: "example.test/acme/net/google//modules/sub", Into: prefix + "/modules/sub"},
		{Caller: prefix + "/modules/sub", Source: "../../shared", Into: prefix + "/shared"},
	}, vendored)
	assert.NoFileExists(t, filepath.Join(stage, prefix, "README.md"), "only what the call names and reaches")
	assert.NoFileExists(t, filepath.Join(stage, prefix, "other/main.tf"))
	assert.NoFileExists(t, filepath.Join(stage, prefix, "shared/.terraform.lock.hcl"))
	assert.Equal(t, []Pin{{Source: "example.test/acme/net/google", Constraint: "", Resolved: "1.0.0"}}, f.pins)
}

func TestCloseGitCloneAndDedup(t *testing.T) {
	upstream, sha := gitRepo(t, map[string]string{
		"modules/a/main.tf": `# a`,
		"modules/b/main.tf": `module "a" { source = "../a" }`,
	})
	root := t.TempDir()
	src := "git::file://" + upstream
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(strings.Join([]string{
		`module "a" { source = "` + src + `//modules/a" }`,
		`module "b" { source = "` + src + `//modules/b" }`,
	}, "\n")), 0o644))

	f := newFetcher(t.TempDir(), Options{Git: testGit{}})
	stage, vendored := closeInStage(t, root, f)
	prefix := "vendor/file" + filepath.ToSlash(upstream) + "/" + sha[:12]
	assert.Equal(t, []Vendored{
		{Caller: ".", Source: src + "//modules/a", Into: prefix + "/modules/a"},
		{Caller: ".", Source: src + "//modules/b", Into: prefix + "/modules/b"},
	}, vendored, "one clone, two placements, and b's ../a was already there")
	assert.Equal(t, []Pin{{Source: src, Constraint: "", Resolved: sha}}, f.pins, "one pin for one tree")
	assert.Contains(t, readStage(t, stage, prefix+"/modules/b/main.tf"), `"../a"`)
}

func TestCloseFetchedTreeCannotEscape(t *testing.T) {
	upstream, sha := gitRepo(t, map[string]string{
		"modules/a/main.tf": `module "out" { source = "../../../elsewhere" }`,
	})
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(
		`module "a" { source = "git::file://`+upstream+`//modules/a?ref=`+sha+`" }`), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(filepath.Dir(upstream), "elsewhere"), 0o755))

	f := newFetcher(t.TempDir(), Options{Git: testGit{}})
	stage := t.TempDir()
	require.NoError(t, copyTree(root, stage, root, false))
	_, err := closeTerraform(context.Background(), root, stage, f)
	assert.ErrorIs(t, err, ErrFetchedEscapes)

	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(
		`module "a" { source = "git::file://`+upstream+`//modules/nope?ref=`+sha+`" }`), 0o644))
	_, err = closeTerraform(context.Background(), root, stage, newFetcher(t.TempDir(), Options{Git: testGit{}}))
	assert.ErrorIs(t, err, ErrSubdirMissing)
}

func TestCloseHTTPArchive(t *testing.T) {
	archive := tgz(t, "net-1.0.0", map[string]string{"main.tf": `# net`, ".terraform.lock.hcl": `# lock`})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/archives/net-1.0.0.tgz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)

	root := t.TempDir()
	src := srv.URL + "/archives/net-1.0.0.tgz"
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "n" { source = "`+src+`" }`), 0o644))

	f := newFetcher(t.TempDir(), Options{Git: testGit{}})
	stage, vendored := closeInStage(t, root, f)
	require.Len(t, f.pins, 1)
	pin := f.pins[0]
	assert.Equal(t, src, pin.Source)
	assert.True(t, strings.HasPrefix(pin.Resolved, "sha256:"), pin.Resolved)
	digest := strings.TrimPrefix(pin.Resolved, "sha256:")
	host, _ := url.Parse(srv.URL)
	prefix := fmt.Sprintf("vendor/%s/archives/net-1.0.0/%s", host.Hostname(), digest[:12])
	assert.Equal(t, []Vendored{{Caller: ".", Source: src, Into: prefix}}, vendored)
	assert.Equal(t, "# net", readStage(t, stage, prefix+"/main.tf"), "the single top-level directory is the tree")
	assert.NoFileExists(t, filepath.Join(stage, prefix, ".terraform.lock.hcl"))

	// Basic auth reaches the archive host.
	var seen string
	authed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_, _ = w.Write(archive)
	}))
	t.Cleanup(authed.Close)
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "n" { source = "`+authed.URL+`/net-1.0.0.tgz" }`), 0o644))
	creds := staticCredentials{authed.URL: {Basic: &BasicAuth{Username: "u", Password: "p"}}}
	_, _ = closeInStage(t, root, newFetcher(t.TempDir(), Options{Credentials: creds, Git: testGit{}, AllowInsecureHTTP: true}))
	assert.True(t, strings.HasPrefix(seen, "Basic "), seen)

	// A wrong checksum refuses; a right one passes.
	bad := src + "?checksum=sha256:" + strings.Repeat("0", 64)
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "n" { source = "`+bad+`" }`), 0o644))
	_, err := closeTerraform(context.Background(), root, t.TempDir(), newFetcher(t.TempDir(), Options{Git: testGit{}}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum")
}

func mustParse(t *testing.T, s string) tfaddr.Module {
	t.Helper()
	kind, m := classify(s)
	require.Equal(t, sourceRegistry, kind, s)
	return m
}

// Service discovery, against a registry that speaks https the way a real
// one must: the client trusts the test server's certificate for it.
func TestRegistryDiscovery(t *testing.T) {
	ctx := context.Background()
	serve := func(t *testing.T, status int, body string) (*registryClient, string) {
		t.Helper()
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		})
		srv := httptest.NewTLSServer(mux)
		t.Cleanup(srv.Close)
		r := newRegistryClient(Options{})
		r.client = srv.Client()
		return r, srv.Listener.Addr().String()
	}

	r, host := serve(t, http.StatusOK, `{"modules.v1": "/v1/modules/"}`)
	base, err := r.modulesBase(ctx, host)
	require.NoError(t, err)
	assert.Equal(t, "https://"+host+"/v1/modules/", base.String(), "relative to the discovery document")
	_, err = r.modulesBase(ctx, host)
	require.NoError(t, err, "cached")

	r, host = serve(t, http.StatusOK, `{"modules.v1": "https://modules.example.test/api"}`)
	base, err = r.modulesBase(ctx, host)
	require.NoError(t, err)
	assert.Equal(t, "https://modules.example.test/api/", base.String(), "absolute, with the trailing slash the protocol joins on")

	r, host = serve(t, http.StatusOK, `{"modules.v1": "http://modules.example.test/api"}`)
	_, err = r.modulesBase(ctx, host)
	assert.ErrorIs(t, err, ErrInsecureHTTP, "a cleartext modules service is refused")

	r, host = serve(t, http.StatusOK, `{"providers.v1": "/v1/providers/"}`)
	_, err = r.modulesBase(ctx, host)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not host a module registry")

	r, host = serve(t, http.StatusUnauthorized, ``)
	_, err = r.modulesBase(ctx, host)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TF_TOKEN_", "a refusal says how to present a token")

	r, host = serve(t, http.StatusBadGateway, ``)
	_, err = r.modulesBase(ctx, host)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestRegistryVersionsBodyIsBounded(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/modules/"+fakePkg+"/versions", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"modules":[{"versions":[`))
		junk := []byte(`{"version":"1.0.0"},`)
		for n := 0; n < maxRegistryBody+1; n += len(junk) {
			_, _ = w.Write(junk)
		}
		_, _ = w.Write([]byte(`{"version":"1.0.0"}]}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r := newRegistryClient(Options{})
	u, _ := url.Parse(srv.URL + "/api/modules/")
	r.services[fakeHost] = u
	_, err := r.Versions(context.Background(), mustParse(t, "example.test/acme/net/google").Package)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "versions")
}

// A registry's download answer names bytes on the network; a local path
// from it is refused whether or not a boundary is set.
func TestRegistryMayNotAnswerWithALocalPath(t *testing.T) {
	local := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(local, "main.tf"), []byte(""), 0o644))
	fake := newFakeRegistry(t, []string{"1.0.0"}, "file::"+local, "body")
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "b" { source = "example.test/acme/net/google" }`), 0o644))
	f := newFetcher(t.TempDir(), Options{Git: testGit{}})
	fake.seed(f.registry)
	stage := t.TempDir()
	require.NoError(t, copyTree(root, stage, root, false))
	_, err := closeTerraform(context.Background(), root, stage, f)
	assert.ErrorIs(t, err, ErrRegistryLocalLocation)
}

// --- What a fetch hands back is hostile until proven otherwise ------------

// untar writes a raw tar (no gzip, the shape Untar reads) with entries in
// the order given.
func untar(t *testing.T, entries ...entry) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: typ, Linkname: e.link, Size: int64(len(e.data))}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if typ == tar.TypeReg {
			_, err := tw.Write([]byte(e.data))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	return bytes.NewReader(buf.Bytes())
}

// A symlink to somewhere outside, then a file through it: the classic.
// Neither the link nor the file may land outside dst.
func TestUntarDoesNotWriteThroughALink(t *testing.T) {
	outside := t.TempDir()
	dst := t.TempDir()
	err := Untar(untar(t,
		entry{name: "esc", typ: tar.TypeSymlink, link: outside},
		entry{name: "esc/file", data: "pwn"},
	), dst)
	assert.ErrorIs(t, err, ErrBadPath)
	assert.NoFileExists(t, filepath.Join(outside, "file"))

	// A relative link that climbs out is the same thing spelled differently.
	err = Untar(untar(t,
		entry{name: "a/esc", typ: tar.TypeSymlink, link: "../../" + filepath.Base(outside)},
		entry{name: "a/esc/file", data: "pwn"},
	), t.TempDir())
	assert.ErrorIs(t, err, ErrBadPath)
	assert.NoFileExists(t, filepath.Join(outside, "file"))

	// Even a link that passes the lexical check cannot be traversed by a
	// later entry: os.Root refuses the path component.
	dst = t.TempDir()
	err = Untar(untar(t,
		entry{name: "a/link", typ: tar.TypeSymlink, link: "../b"},
		entry{name: "b/ok", data: "1"},
		entry{name: "a/link/through", data: "2"},
	), dst)
	require.NoError(t, err, "a link inside the tree is fine")
	assert.FileExists(t, filepath.Join(dst, "b", "through"), "resolved inside the root, so it is inside")
	assert.NoFileExists(t, filepath.Join(filepath.Dir(dst), "b"))
}

func TestUntarRefusesEscapingNamesAndKeepsOddOnes(t *testing.T) {
	dst := t.TempDir()
	require.NoError(t, Untar(untar(t, entry{name: "..foo", data: "x"}, entry{name: "./a/./b", data: "y"}), dst))
	assert.FileExists(t, filepath.Join(dst, "..foo"), "a name that merely starts with dots is a name")
	assert.FileExists(t, filepath.Join(dst, "a", "b"))

	for _, name := range []string{"../x", "a/../../x", "/etc/x"} {
		err := Untar(untar(t, entry{name: name, data: "x"}), t.TempDir())
		assert.ErrorIs(t, err, ErrBadPath, name)
	}
	err := Untar(untar(t, entry{name: "dev", typ: tar.TypeChar}), t.TempDir())
	assert.ErrorIs(t, err, ErrEntryKind)
}

func TestUntarIsBounded(t *testing.T) {
	// A header may claim any size; the budget is checked before a byte is
	// read, so a bomb costs nothing.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644, Size: MaxUncompressed + 1}))
	err := Untar(bytes.NewReader(buf.Bytes()), t.TempDir())
	assert.ErrorIs(t, err, ErrTooLarge)

	buf.Reset()
	tw = tar.NewWriter(&buf)
	for i := 0; i <= maxEntries; i++ {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: "d/" + strings.Repeat("x", 3) + string(rune('a'+i%26)), Typeflag: tar.TypeDir, Mode: 0o755}))
	}
	require.NoError(t, tw.Close())
	err = Untar(bytes.NewReader(buf.Bytes()), t.TempDir())
	assert.ErrorIs(t, err, ErrTooManyEntries)
}

// `//subdir` may only name a directory inside the fetched tree. `..` is
// refused before the fetch, whoever wrote it: the call, or the registry's
// download answer.
func TestPackRefusesASubdirThatClimbs(t *testing.T) {
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "main.tf"), []byte(""), 0o644))
	for _, subdir := range []string{"..", "../..", "a/../..", "/etc"} {
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "x" { source = "file::`+src+`//`+subdir+`" }`), 0o644))
		_, err := PackContext(context.Background(), root, Options{})
		assert.ErrorIs(t, err, ErrFetchedEscapes, subdir)
	}

	// The registry's answer carries its own subdirectory; it gets the same
	// treatment as one the author wrote.
	upstream, sha := gitRepo(t, map[string]string{"main.tf": `# root`})
	fake := newFakeRegistry(t, []string{"1.0.0"}, "git::file://"+upstream+"//..?ref="+sha, "body")
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "b" { source = "example.test/acme/net/google" }`), 0o644))
	f := newFetcher(t.TempDir(), Options{Git: testGit{}})
	fake.seed(f.registry)
	stage := t.TempDir()
	require.NoError(t, copyTree(root, stage, root, false))
	_, err := closeTerraform(context.Background(), root, stage, f)
	assert.ErrorIs(t, err, ErrFetchedEscapes)
}

// A ref reaches a transport that may run git; one shaped like an option
// stops at the source, before any transport sees it.
func TestPackRefusesARefShapedLikeAnOption(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(
		`module "a" { source = "git::https://example.test/acme/x.git?ref=--upload-pack=touch%20pwned" }`), 0o644))
	_, err := PackContext(context.Background(), root, Options{Git: testGit{}})
	assert.ErrorIs(t, err, ErrRefInvalid)
}

// shortGit is a transport that answers with something that is not a commit.
type shortGit struct{ answer string }

func (g shortGit) Clone(_ context.Context, _ *url.URL, _, dst string, _ *Credential) (string, error) {
	return g.answer, os.MkdirAll(dst, 0o755)
}

func TestFetchGitRequiresAFullCommitHash(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "a" { source = "git::https://example.test/acme/x.git" }`), 0o644))
	for _, bad := range []string{"main", "abc123def456", "error: not found", "ABCDEF0123456789ABCDEF0123456789ABCDEF01"} {
		_, err := PackContext(context.Background(), root, Options{Git: shortGit{bad}})
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "not a commit", bad)
	}
	assert.True(t, isCommitHash("0123456789abcdef0123456789abcdef01234567"))
	assert.True(t, isCommitHash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
}

func TestArchiveDownloadIsBounded(t *testing.T) {
	// A server that never stops talking: the download stops at the cap.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := bytes.Repeat([]byte("x"), 1<<20)
		for i := 0; i < int(MaxUncompressed>>20)+2; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "a" { source = "`+srv.URL+`/net.tgz" }`), 0o644))
	_, err := Pack(root)
	assert.ErrorIs(t, err, ErrTooLarge)
}
