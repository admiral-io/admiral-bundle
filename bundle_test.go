package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type entry struct {
	name, link string
	data       string
	mode       int64
	typ        byte
}

// targz builds an archive the way an arbitrary client might: in the order
// given, with real timestamps and ownership, and a named gzip header.
func targz(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Name = "whatever.tar"
	gz.ModTime = time.Now()
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o664
		}
		hdr := &tar.Header{
			Name: e.name, Mode: mode, Typeflag: typ, Linkname: e.link,
			Size: int64(len(e.data)), ModTime: time.Now(), Uid: 501, Gid: 20, Uname: "someone",
		}
		if typ == tar.TypeSymlink || typ == tar.TypeDir {
			hdr.Size = 0
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if typ == tar.TypeReg {
			_, err := tw.Write([]byte(e.data))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// The whole point of normalization: the same tree is the same bytes, however
// it was packed.
func TestNormalizeIsAFunctionOfTheTreeAlone(t *testing.T) {
	a := targz(t,
		entry{name: "./main.tf", data: "resource {}", mode: 0o600},
		entry{name: "modules/", typ: tar.TypeDir},
		entry{name: "modules/a.tf", data: "x"},
		entry{name: ".git/HEAD", data: "ref: refs/heads/main"},
		entry{name: ".git/objects/", typ: tar.TypeDir},
	)
	time.Sleep(5 * time.Millisecond) // a different clock for every timestamp
	b := targz(t,
		entry{name: "modules/a.tf", data: "x", mode: 0o644},
		entry{name: "main.tf", data: "resource {}", mode: 0o444},
	)

	na, err := Normalize(bytes.NewReader(a))
	require.NoError(t, err)
	nb, err := Normalize(bytes.NewReader(b))
	require.NoError(t, err)

	assert.Equal(t, na.Bytes, nb.Bytes, "order, timestamps, ownership, non-execute mode bits and .git do not change the bytes")
	require.Len(t, na.Files, 2)
	assert.Equal(t, "main.tf", na.Files[0].Path)
	assert.Equal(t, "modules/a.tf", na.Files[1].Path)
	assert.EqualValues(t, 0o644, na.Files[0].Mode)

	// And the output reads back as itself.
	again, err := Normalize(bytes.NewReader(na.Bytes))
	require.NoError(t, err)
	assert.Equal(t, na.Bytes, again.Bytes, "normalization is idempotent")
}

func TestNormalizeKeepsTheExecuteBitAndSymlinks(t *testing.T) {
	n, err := Normalize(bytes.NewReader(targz(t,
		entry{name: "run.sh", data: "#!/bin/sh", mode: 0o700},
		entry{name: "link", link: "run.sh", typ: tar.TypeSymlink},
	)))
	require.NoError(t, err)
	require.Len(t, n.Files, 2)
	assert.EqualValues(t, 0o755, n.Files[1].Mode)
	assert.Equal(t, "run.sh", n.Files[0].Link)
}

func TestNormalizeRefusesWhatEscapesTheRoot(t *testing.T) {
	for name, entries := range map[string][]entry{
		"dotdot":        {{name: "../etc/passwd", data: "x"}},
		"absolute":      {{name: "/etc/passwd", data: "x"}},
		"drive":         {{name: `C:\x`, data: "x"}},
		"symlink-out":   {{name: "l", link: "../../x", typ: tar.TypeSymlink}},
		"symlink-abs":   {{name: "l", link: "/etc/passwd", typ: tar.TypeSymlink}},
		"nested-dotdot": {{name: "a/../../x", data: "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Normalize(bytes.NewReader(targz(t, entries...)))
			assert.ErrorIs(t, err, ErrBadPath)
		})
	}

	_, err := Normalize(bytes.NewReader([]byte("not a tarball")))
	assert.ErrorIs(t, err, ErrNotTarGz)

	_, err = Normalize(bytes.NewReader(targz(t, entry{name: ".git/config", data: "x"})))
	assert.ErrorIs(t, err, ErrEmpty, "a bundle that is only .git has nothing to publish")

	_, err = Normalize(bytes.NewReader(targz(t, entry{name: "dev", typ: tar.TypeChar})))
	assert.ErrorIs(t, err, ErrEntryKind)
}

func TestDetect(t *testing.T) {
	kind, err := Detect([]File{{Path: "main.tf"}, {Path: "values.yaml"}})
	require.NoError(t, err)
	assert.Equal(t, KindTerraform, kind)

	kind, err = Detect([]File{{Path: "Chart.yaml"}, {Path: "templates/deploy.yaml"}})
	require.NoError(t, err)
	assert.Equal(t, KindHelm, kind, "a chart wins over its YAML")

	kind, err = Detect([]File{{Path: "deploy.yaml"}, {Path: "svc.yml"}})
	require.NoError(t, err)
	assert.Equal(t, KindManifests, kind)

	_, err = Detect([]File{{Path: "README.md"}, {Path: "nested/main.tf"}})
	assert.ErrorIs(t, err, ErrUnknownKind, "only the root decides")
}

const module = `
terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.5" }
    aws    = { source = "hashicorp/aws" }
  }
}
provider "null" {}

variable "name" {
  type        = string
  description = "The instance name."
}
variable "tier" {
  type    = string
  default = "db-f1-micro"
}
variable "password" {
  type      = string
  sensitive = true
}
output "connection_name" {
  description = "Use this to connect."
  value       = "x"
}
output "root_password" {
  value     = var.password
  sensitive = true
}
module "vendored" {
  source = "./modules/net"
}
`

func TestInspectTerraform(t *testing.T) {
	files := []File{
		{Path: "main.tf", Data: []byte(module)},
		{Path: "modules/net/main.tf", Data: []byte(`variable "cidr" {}`)},
	}
	r, err := Inspect(files, "")
	require.NoError(t, err)
	assert.Equal(t, KindTerraform, r.Kind)

	require.Len(t, r.Contract.Inputs, 3)
	assert.Equal(t, Input{Name: "name", Type: "string", Description: "The instance name.", Required: true}, r.Contract.Inputs[0])
	assert.Equal(t, Input{Name: "password", Type: "string", Required: true, Sensitive: true}, r.Contract.Inputs[1])
	assert.Equal(t, Input{Name: "tier", Type: "string", Default: "db-f1-micro"}, r.Contract.Inputs[2])

	require.Len(t, r.Contract.Outputs, 2)
	assert.Equal(t, Output{Name: "connection_name", Description: "Use this to connect."}, r.Contract.Outputs[0])
	assert.Equal(t, Output{Name: "root_password", Sensitive: true}, r.Contract.Outputs[1])

	codes := map[string]string{}
	for _, f := range r.Findings {
		assert.Equal(t, SeverityInfo, f.Severity)
		codes[f.Source+"/"+f.Code] += " " + f.Message
	}
	assert.Contains(t, codes["provider-constraint/missing"], `"aws"`)
	assert.Contains(t, codes["provider-constraint/unbounded"], `"google"`)
	assert.NotContains(t, codes["provider-constraint/unbounded"], `"random"`, "a pessimistic constraint is bounded")
	assert.Contains(t, codes["provider-constraint/undeclared"], `"null"`)
	assert.Contains(t, codes["core-constraint/missing"], "required_version", "the fixture pins no core version")
}

func TestInspectTerraformRefusesANonLiteralSource(t *testing.T) {
	files := []File{{Path: "main.tf", Data: []byte(`
variable "src" { type = string }
module "m" { source = var.src }
`)}}
	_, err := Inspect(files, KindTerraform)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-literal source")
}

func TestInspectHelm(t *testing.T) {
	files := []File{
		{Path: "Chart.yaml", Data: []byte("apiVersion: v2\nname: api\nversion: 1.0.0\n")},
		{Path: "values.yaml", Data: []byte("replicas: 2\nimage:\n  repository: ghcr.io/acme/api\n  tag: latest\ndebug: false\n")},
		{Path: "templates/deploy.yaml", Data: []byte("kind: Deployment\nspec:\n  image: busybox:1.36\n  image: {{ .Values.image.repository }}\n")},
	}
	r, err := Inspect(files, "")
	require.NoError(t, err)
	assert.Equal(t, KindHelm, r.Kind)
	require.Len(t, r.Contract.Inputs, 3)
	assert.Equal(t, "debug", r.Contract.Inputs[0].Name)
	assert.Equal(t, "bool", r.Contract.Inputs[0].Type)
	assert.Equal(t, "object", r.Contract.Inputs[1].Type)
	assert.Equal(t, "number", r.Contract.Inputs[2].Type)
	assert.Empty(t, r.Contract.Outputs)
	require.Len(t, r.Findings, 1, "the templated image reference is not a finding; the literal one is")
	assert.Equal(t, "busybox:1.36", r.Findings[0].Message)

	_, err = Inspect([]File{{Path: "Chart.yaml", Data: []byte("version: 1\n")}}, "")
	assert.Error(t, err, "a chart without a name")
}
