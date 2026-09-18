package bundle

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tf(files map[string]string) []File {
	out := make([]File, 0, len(files))
	for p, d := range files {
		out = append(out, File{Path: p, Mode: 0o644, Data: []byte(d)})
	}
	return out
}

// A tree whose every source is a relative path to a directory that is here
// is closed, however deep the calls go.
func TestCloseAcceptsAClosedTree(t *testing.T) {
	c, err := Close(tf(map[string]string{
		"main.tf":                  `module "net" { source = "./modules/net" }` + "\n" + `module "db" { source = "./vendor/cloud-sql" }`,
		"modules/net/main.tf":      `module "sub" { source = "../sub" }`,
		"modules/sub/main.tf":      `variable "x" {}`,
		"vendor/cloud-sql/main.tf": `module "net" { source = "../../modules/net" }`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{".", "modules/net", "modules/sub", "vendor/cloud-sql"}, c.Modules)
	require.Len(t, c.Calls, 4)
	assert.Contains(t, c.Calls, Call{Caller: "modules/net", Name: "sub", Source: "../sub", Dir: "modules/sub"})
	assert.Contains(t, c.Calls, Call{Caller: "vendor/cloud-sql", Name: "net", Source: "../../modules/net", Dir: "modules/net"})
}

func TestCloseRefusesWhatIsNotHere(t *testing.T) {
	cases := map[string]struct {
		source string
		want   error
	}{
		"escapes":       {"../modules/net", ErrSourceEscapes},
		"nested-escape": {"./modules/../../x", ErrSourceEscapes},
		"missing":       {"./modules/nope", ErrSourceMissing},
		// Every address form OpenTofu resolves through the registry or
		// go-getter is remote; the rule is the prefix, not the scheme.
		"registry":         {"hashicorp/consul/aws", ErrSourceRemote},
		"registry-subdir":  {"terraform-google-modules/sql-db/google//modules/mysql", ErrSourceRemote},
		"private-registry": {"app.terraform.io/acme/net/google", ErrSourceRemote},
		"git-forced":       {"git::https://github.com/acme/modules.git//net?ref=v1", ErrSourceRemote},
		"git-ssh":          {"git::ssh://git@github.com/acme/modules.git", ErrSourceRemote},
		"github-shorthand": {"github.com/acme/modules", ErrSourceRemote},
		"bitbucket":        {"bitbucket.org/acme/modules", ErrSourceRemote},
		"https-archive":    {"https://example.com/modules/net.zip", ErrSourceRemote},
		"s3":               {"s3::https://s3.amazonaws.com/bucket/net.zip", ErrSourceRemote},
		"gcs":              {"gcs::https://www.googleapis.com/storage/v1/bucket/net.zip", ErrSourceRemote},
		"hg":               {"hg::https://example.com/modules", ErrSourceRemote},
		"bare-path":        {"modules/net", ErrSourceRemote}, // read as a registry address, not a directory
		"absolute-path":    {"/opt/modules/net", ErrSourceRemote},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Close(tf(map[string]string{
				"main.tf":             `module "m" { source = "` + c.source + `" }`,
				"modules/net/main.tf": `variable "x" {}`,
			}))
			assert.ErrorIs(t, err, c.want)
			assert.Contains(t, err.Error(), `module "m" in the root module`)
		})
	}

	// The refusal names where it happened, deep in the tree too.
	_, err := Close(tf(map[string]string{
		"main.tf":             `module "net" { source = "./modules/net" }`,
		"modules/net/main.tf": `module "ext" { source = "hashicorp/consul/aws" }`,
	}))
	assert.ErrorIs(t, err, ErrSourceRemote)
	assert.Contains(t, err.Error(), `module "ext" in modules/net`)
}

func TestCloseChart(t *testing.T) {
	chart := "apiVersion: v2\nname: api\nversion: 1.0.0\ndependencies:\n  - name: postgresql\n    version: 16.7.27\n    repository: https://charts.bitnami.com/bitnami\n"
	assert.ErrorIs(t, CloseChart(tf(map[string]string{"Chart.yaml": chart})), ErrChartDependencyMissing)
	assert.NoError(t, CloseChart(tf(map[string]string{"Chart.yaml": chart, "charts/postgresql-16.7.27.tgz": "x"})))
	assert.NoError(t, CloseChart(tf(map[string]string{"Chart.yaml": chart, "charts/postgresql/Chart.yaml": "name: postgresql"})))
	assert.NoError(t, CloseChart(tf(map[string]string{"Chart.yaml": "apiVersion: v2\nname: api\nversion: 1.0.0\n"})), "no dependencies, nothing to vendor")
}

func TestNormalizeStripsTerraformCaches(t *testing.T) {
	n, err := Normalize(bytes.NewReader(targz(t,
		entry{name: "main.tf", data: "x"},
		entry{name: ".terraform/providers/registry/x", data: "binary"},
		entry{name: "vendor/a/.terraform/modules/m/main.tf", data: "y"},
		entry{name: "vendor/a/.git/HEAD", data: "ref"},
		entry{name: ".terraform.lock.hcl", data: "lock"},
	)))
	require.NoError(t, err)
	var paths []string
	for _, f := range n.Files {
		paths = append(paths, f.Path)
	}
	assert.Equal(t, []string{".terraform.lock.hcl", "main.tf"}, paths, "the lock file stays; the caches do not")
}
