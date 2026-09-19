package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A repository with a component that calls out of its own directory, twice
// removed: the component calls ../../modules/net, which calls ../sub.
func repo(t *testing.T) (root string) {
	t.Helper()
	base := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(base, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
	write("infra/cloud-sql/main.tf", `# The database.
module "net" {
  source = "../../modules/net" # shared
  cidr   = "10.0.0.0/16"
}
module "local" {
  source = "./local"
}
variable "name" { type = string }
`)
	write("infra/cloud-sql/local/main.tf", `variable "x" {}`)
	write("infra/cloud-sql/.terraform/providers/junk", "binary")
	write("infra/cloud-sql/.git/HEAD", "ref")
	write("modules/net/main.tf", `module "sub" { source = "../sub" }`+"\n"+`variable "cidr" {}`)
	write("modules/sub/main.tf", `output "x" { value = 1 }`)
	return filepath.Join(base, "infra", "cloud-sql")
}

func entries(t *testing.T, data []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		b, err := io.ReadAll(tr)
		require.NoError(t, err)
		out[hdr.Name] = string(b)
	}
	return out
}

func TestPackVendorsEscapesAndRewritesTheCalls(t *testing.T) {
	root := repo(t)
	before, err := os.ReadFile(filepath.Join(root, "main.tf"))
	require.NoError(t, err)

	p, err := Pack(root)
	require.NoError(t, err)
	assert.Equal(t, KindTerraform, p.Kind)

	files := entries(t, p.Bytes)
	assert.ElementsMatch(t, []string{
		"main.tf", "local/main.tf",
		"vendor/modules/net/main.tf", "vendor/modules/sub/main.tf",
	}, keys(files), ".git and .terraform are not packed")

	// The escaping call was rewritten to its vendored location, and nothing
	// else in the file moved: not the comment, not the other attributes, not
	// the in-tree call.
	assert.Contains(t, files["main.tf"], `source = "./vendor/modules/net" # shared`)
	assert.Contains(t, files["main.tf"], `cidr   = "10.0.0.0/16"`)
	assert.Contains(t, files["main.tf"], `source = "./local"`)
	assert.Contains(t, files["main.tf"], "# The database.")

	// The vendored module's own escape was vendored and rewritten too,
	// relative to where the copy now sits.
	assert.Contains(t, files["vendor/modules/net/main.tf"], `source = "../sub"`)

	assert.Equal(t, []Vendored{
		{Caller: ".", Source: "../../modules/net", Into: "vendor/modules/net"},
		{Caller: "vendor/modules/net", Source: "../sub", Into: "vendor/modules/sub"},
	}, p.Vendored)

	after, err := os.ReadFile(filepath.Join(root, "main.tf"))
	require.NoError(t, err)
	assert.Equal(t, before, after, "the working copy is never touched")
}

func TestPackRefusesWhatItCannotClose(t *testing.T) {
	root := t.TempDir()
	write := func(data string) {
		require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(data), 0o644))
	}

	write(`module "m" { source = "s3::https://s3.amazonaws.com/bucket/mod.zip" }`)
	_, err := Pack(root)
	assert.ErrorIs(t, err, ErrSourceUnsupported)

	write(`module "m" { source = "../nope" }`)
	_, err = Pack(root)
	assert.ErrorIs(t, err, ErrSourceDirMissing)

	write(`variable "s" { type = string }` + "\n" + `module "m" { source = var.s }`)
	_, err = Pack(root)
	assert.ErrorIs(t, err, ErrSourceNonLiteral)

	require.NoError(t, os.Remove(filepath.Join(root, "main.tf")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "README.md"), []byte("x"), 0o644))
	_, err = Pack(root)
	assert.ErrorIs(t, err, ErrUnknownKind)
}

func TestPackHelmAndManifestsAreLeftAlone(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "templates"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Chart.yaml"), []byte("name: api\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "templates", "d.yaml"), []byte("kind: X\n"), 0o644))
	p, err := Pack(root)
	require.NoError(t, err)
	assert.Equal(t, KindHelm, p.Kind)
	assert.Equal(t, 2, p.Files)
	assert.Empty(t, p.Vendored)
	assert.True(t, strings.HasPrefix(string(p.Bytes[:2]), "\x1f\x8b"), "gzip")
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Two calls reach the same outside directory, once as a whole and once by a
// subdirectory, and the whole got a numeric suffix because the root already
// had a vendor/modules. The subdirectory call must point where the copy
// actually is.
func TestPackPointsAtWhereAPlacedAncestorPutIt(t *testing.T) {
	base := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(base, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
	write("infra/x/main.tf", `module "all" { source = "../../modules" }`+"\n"+`module "net" { source = "../../modules/net" }`)
	write("infra/x/vendor/modules/keep.txt", "")
	write("modules/main.tf", "")
	write("modules/net/main.tf", "")

	p, err := Pack(filepath.Join(base, "infra", "x"))
	require.NoError(t, err)
	assert.Equal(t, []Vendored{{Caller: ".", Source: "../../modules", Into: "vendor/modules-2"}}, p.Vendored, "one copy")
	assert.Contains(t, entries(t, p.Bytes)["main.tf"], `"./vendor/modules-2/net"`)
	n, err := Normalize(bytes.NewReader(p.Bytes))
	require.NoError(t, err)
	_, err = Close(n.Files)
	require.NoError(t, err)
}

// A cycle of local calls is read once per module and ends; and a context
// canceled mid-walk ends it too.
func TestPackEndsOnACycle(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "a" { source = "./a" }`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a", "main.tf"), []byte(`module "up" { source = "../" }`), 0o644))
	done := make(chan error, 1)
	go func() { _, err := Pack(root); done <- err }()
	select {
	case err := <-done:
		require.NoError(t, err, "a cycle is the runtime's problem, not a hang")
	case <-time.After(10 * time.Second):
		t.Fatal("Pack did not return")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := PackContext(ctx, root, Options{})
	assert.ErrorIs(t, err, context.Canceled)
}

// A module call in a JSON file is read like any other and refused with the
// reason when it would have to be rewritten.
func TestPackNamesWhyAJSONCallCannotBeRewritten(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf.json"), []byte(`{"module":{"net":{"source":"../net"}}}`), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(filepath.Dir(root), "net"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(root), "net", "main.tf"), []byte(""), 0o644))
	_, err := Pack(root)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSourceUnsupported)
	assert.Contains(t, err.Error(), "JSON")
}

func TestPackedTreeHasOnlyRegularFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(""), 0o644))
	require.NoError(t, os.Symlink("main.tf", filepath.Join(root, "alias.tf")))
	p, err := Pack(root)
	require.NoError(t, err)
	gz, err := gzip.NewReader(bytes.NewReader(p.Bytes))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		assert.Equal(t, byte(tar.TypeReg), hdr.Typeflag, hdr.Name)
	}
}

// --- Symlinks and the boundary ----------------------------------------------

// A link in a fetched tree pointing out of it is the same escape with no
// `..` to see: it must be caught on the way to the subdir, on the way to a
// relative source, and while copying.
func TestPackRefusesALinkOutOfAFetchedTree(t *testing.T) {
	secret := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(secret, "inner"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(secret, "inner", "token"), []byte("hunter2"), 0o600))

	tree := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tree, "main.tf"), []byte(""), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "mod"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "mod", "main.tf"), []byte(""), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "caller"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "caller", "main.tf"), []byte(`module "in" { source = "../esc/inner" }`), 0o644))
	require.NoError(t, os.Symlink(secret, filepath.Join(tree, "esc")))
	require.NoError(t, os.Symlink(filepath.Join(secret, "inner", "token"), filepath.Join(tree, "mod", "token")))

	pack := func(source string) error {
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "x" { source = "file::`+tree+source+`" }`), 0o644))
		_, err := PackContext(context.Background(), root, Options{})
		return err
	}
	assert.ErrorIs(t, pack("//esc/inner"), ErrFetchedEscapes, "the subdir is reached through the link")
	assert.ErrorIs(t, pack("//esc"), ErrFetchedEscapes, "the subdir is the link")
	assert.ErrorIs(t, pack("//caller"), ErrFetchedEscapes, "a relative source, lexically inside the tree, goes through the link")
	assert.ErrorIs(t, pack("//mod"), ErrLinkEscapes, "a file link inside the copied directory points out")
	assert.ErrorIs(t, pack(""), ErrLinkEscapes, "the whole tree: the copy meets the link first")
}

// A symlink inside the root that stays inside the root becomes a copy: the
// module walk, the packed tree and the server's closure walk then all see
// the same directory. Pack -> Normalize -> Close is the round trip that was
// once refused with ErrSourceMissing.
func TestPackDereferencesLinksThatStayInside(t *testing.T) {
	root := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
	write("main.tf", `module "net" { source = "./modules/net" }`)
	write("shared/net/main.tf", `variable "cidr" {}`)
	write("common/providers.tf", `terraform {
  required_providers {
    google = { source = "hashicorp/google" }
  }
}`)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "modules"), 0o755))
	require.NoError(t, os.Symlink("../shared/net", filepath.Join(root, "modules", "net")))
	require.NoError(t, os.Symlink("common/providers.tf", filepath.Join(root, "providers.tf")))

	p, err := Pack(root)
	require.NoError(t, err)
	got := entries(t, p.Bytes)
	assert.Equal(t, `variable "cidr" {}`, got["modules/net/main.tf"], "the link is a copy")
	assert.Contains(t, got["providers.tf"], "hashicorp/google", "a file link is a copy too")

	gz, err := gzip.NewReader(bytes.NewReader(p.Bytes))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		assert.NotEqual(t, byte(tar.TypeSymlink), hdr.Typeflag, "%s: the bundle carries no links", hdr.Name)
	}

	n, err := Normalize(bytes.NewReader(p.Bytes))
	require.NoError(t, err)
	c, err := Close(n.Files)
	require.NoError(t, err)
	assert.Equal(t, []string{".", "modules/net"}, c.Modules)

	report, err := Inspect(n.Files, KindTerraform)
	require.NoError(t, err)
	assert.NotEmpty(t, report.Findings, "the unbounded provider in the linked file is read")
}

func TestPackRefusesALinkOutOfTheRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(""), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(base, "outside.tf"), []byte(""), 0o644))
	require.NoError(t, os.Symlink("../outside.tf", filepath.Join(root, "providers.tf")))
	_, err := Pack(root)
	assert.ErrorIs(t, err, ErrLinkEscapes)

	// A link back up its own path would copy forever.
	root = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(""), 0o644))
	require.NoError(t, os.Symlink(".", filepath.Join(root, "loop")))
	_, err = Pack(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle")
}

func TestBoundaryBoundsLocalSources(t *testing.T) {
	repo := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(repo, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
	write("roots/x/main.tf", `module "net" { source = "../../modules/net" }`)
	write("modules/net/main.tf", ``)
	root := filepath.Join(repo, "roots", "x")

	p, err := PackContext(context.Background(), root, Options{Boundary: repo})
	require.NoError(t, err, "an escape that stays in the repository is vendored")
	assert.Contains(t, entries(t, p.Bytes), "vendor/modules/net/main.tf")

	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "main.tf"), []byte(""), 0o644))
	write("roots/y/main.tf", `module "out" { source = "`+relPath(t, filepath.Join(repo, "roots", "y"), outside)+`" }`)
	_, err = PackContext(context.Background(), filepath.Join(repo, "roots", "y"), Options{Boundary: repo})
	assert.ErrorIs(t, err, ErrOutsideBoundary, "one that leaves it is refused")
	_, err = PackContext(context.Background(), filepath.Join(repo, "roots", "y"), Options{})
	require.NoError(t, err, "no boundary, no limit: a developer's own machine")

	// A link inside the boundary pointing out of it is the same escape.
	require.NoError(t, os.Symlink(outside, filepath.Join(repo, "modules", "esc")))
	write("roots/z/main.tf", `module "esc" { source = "../../modules/esc" }`)
	_, err = PackContext(context.Background(), filepath.Join(repo, "roots", "z"), Options{Boundary: repo})
	assert.ErrorIs(t, err, ErrOutsideBoundary)

	// file:: sources and file:// chart dependencies are local sources too.
	write("roots/f/main.tf", `module "out" { source = "file::`+outside+`" }`)
	_, err = PackContext(context.Background(), filepath.Join(repo, "roots", "f"), Options{Boundary: repo})
	assert.ErrorIs(t, err, ErrOutsideBoundary)

	lib := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(lib, "Chart.yaml"), []byte("apiVersion: v2\nname: lib\nversion: 0.1.0\n"), 0o644))
	write("charts/app/Chart.yaml", "apiVersion: v2\nname: app\nversion: 0.1.0\ndependencies:\n  - name: lib\n    version: 0.1.0\n    repository: file://"+relPath(t, filepath.Join(repo, "charts", "app"), lib)+"\n")
	write("charts/app/Chart.lock", "dependencies:\n- name: lib\n  repository: file://"+relPath(t, filepath.Join(repo, "charts", "app"), lib)+"\n  version: 0.1.0\n")
	_, err = PackContext(context.Background(), filepath.Join(repo, "charts", "app"), Options{Boundary: repo})
	assert.ErrorIs(t, err, ErrOutsideBoundary)
}

func relPath(t *testing.T, from, to string) string {
	t.Helper()
	rel, err := filepath.Rel(from, to)
	require.NoError(t, err)
	return filepath.ToSlash(rel)
}

func TestPackReportsWhatIsWrongWithTheRoot(t *testing.T) {
	_, err := Pack(filepath.Join(t.TempDir(), "nope"))
	assert.True(t, errors.Is(err, os.ErrNotExist), "%v", err)
	f := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(f, nil, 0o644))
	_, err = Pack(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}
