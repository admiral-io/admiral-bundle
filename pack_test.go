package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	assert.ErrorIs(t, err, ErrMissing)

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
