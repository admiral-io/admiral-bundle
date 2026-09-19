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
			r := newRegistryClient(staticCreds{"example.test": "tok"})
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
		r := newRegistryClient(nil)
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
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
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
	require.NoError(t, copyTree(root, stage, false))
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

	f := newFetcher(t.TempDir(), nil, testGit{})
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

	f := newFetcher(t.TempDir(), nil, testGit{})
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

	f := newFetcher(t.TempDir(), nil, testGit{})
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

	f := newFetcher(t.TempDir(), nil, testGit{})
	stage := t.TempDir()
	require.NoError(t, copyTree(root, stage, false))
	_, err := closeTerraform(context.Background(), root, stage, f)
	assert.ErrorIs(t, err, ErrFetchedEscapes)

	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(
		`module "a" { source = "git::file://`+upstream+`//modules/nope?ref=`+sha+`" }`), 0o644))
	_, err = closeTerraform(context.Background(), root, stage, newFetcher(t.TempDir(), nil, testGit{}))
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

	f := newFetcher(t.TempDir(), nil, testGit{})
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
	_, _ = closeInStage(t, root, newFetcher(t.TempDir(), creds, testGit{}))
	assert.True(t, strings.HasPrefix(seen, "Basic "), seen)

	// A wrong checksum refuses; a right one passes.
	bad := src + "?checksum=sha256:" + strings.Repeat("0", 64)
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "n" { source = "`+bad+`" }`), 0o644))
	_, err := closeTerraform(context.Background(), root, t.TempDir(), newFetcher(t.TempDir(), nil, testGit{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum")
}

func mustParse(t *testing.T, s string) tfaddr.Module {
	t.Helper()
	kind, m := classify(s)
	require.Equal(t, sourceRegistry, kind, s)
	return m
}
