package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
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

func TestNormalizeKeepsTheExecuteBit(t *testing.T) {
	n, err := Normalize(bytes.NewReader(targz(t,
		entry{name: "run.sh", data: "#!/bin/sh", mode: 0o700},
		entry{name: "main.tf", data: "", mode: 0o600},
	)))
	require.NoError(t, err)
	require.Len(t, n.Files, 2)
	assert.EqualValues(t, 0o644, n.Files[0].Mode)
	assert.EqualValues(t, 0o755, n.Files[1].Mode)
}

// The same rule Pack applies on the client, applied to what arrives: a link
// inside the tree is a copy of its target, whatever produced the archive.
func TestNormalizeResolvesLinksIntoCopies(t *testing.T) {
	n, err := Normalize(bytes.NewReader(targz(t,
		// The link comes before its target in the stream.
		entry{name: "link.sh", link: "run.sh", typ: tar.TypeSymlink},
		entry{name: "run.sh", data: "#!/bin/sh", mode: 0o700},
		entry{name: "main.tf", data: `module "net" { source = "./modules/net" }`},
		entry{name: "shared/net/main.tf", data: `variable "cidr" {}`},
		entry{name: "shared/net/versions.tf", link: "../../versions.tf", typ: tar.TypeSymlink},
		entry{name: "versions.tf", data: "terraform {}"},
		entry{name: "modules/net", link: "../shared/net", typ: tar.TypeSymlink},
		// A link through a link: the directory link on the way is followed.
		entry{name: "modules/alias.tf", link: "net/main.tf", typ: tar.TypeSymlink},
	)))
	require.NoError(t, err)
	got := map[string]File{}
	for _, f := range n.Files {
		got[f.Path] = f
	}
	assert.Equal(t, "#!/bin/sh", string(got["link.sh"].Data))
	assert.EqualValues(t, 0o755, got["link.sh"].Mode, "the copy takes the target's mode")
	assert.Equal(t, `variable "cidr" {}`, string(got["modules/net/main.tf"].Data))
	assert.Equal(t, "terraform {}", string(got["modules/net/versions.tf"].Data), "a link inside a linked directory")
	assert.Equal(t, `variable "cidr" {}`, string(got["modules/alias.tf"].Data))
	assert.Len(t, n.Files, 9)

	// The output has no link entries.
	gz, err := gzip.NewReader(bytes.NewReader(n.Bytes))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		assert.Equal(t, byte(tar.TypeReg), hdr.Typeflag, hdr.Name)
	}

	// And Close reads the copy as the module it is.
	c, err := Close(n.Files)
	require.NoError(t, err)
	assert.Equal(t, []string{".", "modules/net"}, c.Modules)
}

// Copies share bytes, so a link bomb costs entries, not memory; the entry
// cap is what stops it.
func TestNormalizeBoundsLinkExpansion(t *testing.T) {
	// 2^18 empty files from 18 directory links, each doubling the last.
	es := []entry{{name: "d0/x", data: ""}, {name: "d0/y", data: ""}}
	for i := 1; i <= 17; i++ {
		es = append(es,
			entry{name: fmt.Sprintf("d%d/a", i), link: fmt.Sprintf("../d%d", i-1), typ: tar.TypeSymlink},
			entry{name: fmt.Sprintf("d%d/b", i), link: fmt.Sprintf("../d%d", i-1), typ: tar.TypeSymlink},
		)
	}
	_, err := Normalize(bytes.NewReader(targz(t, es...)))
	assert.ErrorIs(t, err, ErrTooManyEntries)
}

func TestNormalizeRefusesLinksItCannotResolve(t *testing.T) {
	for name, entries := range map[string][]entry{
		"dangling":    {{name: "main.tf", data: ""}, {name: "l", link: "gone", typ: tar.TypeSymlink}},
		"self":        {{name: "main.tf", data: ""}, {name: "l", link: "l", typ: tar.TypeSymlink}},
		"pair":        {{name: "main.tf", data: ""}, {name: "a", link: "b", typ: tar.TypeSymlink}, {name: "b", link: "a", typ: tar.TypeSymlink}},
		"up-own-path": {{name: "main.tf", data: ""}, {name: "d/l", link: "..", typ: tar.TypeSymlink}},
		"to-root":     {{name: "main.tf", data: ""}, {name: "l", link: ".", typ: tar.TypeSymlink}},
		"file-twice":  {{name: "d/x", data: ""}, {name: "l", link: "d", typ: tar.TypeSymlink}, {name: "l/x", data: ""}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Normalize(bytes.NewReader(targz(t, entries...)))
			assert.ErrorIs(t, err, ErrBadPath)
		})
	}
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
	nullable := true // Terraform's default when a variable does not say
	assert.Equal(t, Input{Name: "name", Type: "string", Description: "The instance name.", Required: true, Nullable: &nullable}, r.Contract.Inputs[0])
	assert.Equal(t, Input{Name: "password", Type: "string", Required: true, Sensitive: true, Nullable: &nullable}, r.Contract.Inputs[1])
	assert.Equal(t, Input{Name: "tier", Type: "string", Default: "db-f1-micro", Nullable: &nullable}, r.Contract.Inputs[2])

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

// What a variable block says beyond name, type and default: whether it
// accepts null, whether it is ephemeral, its validations and its deprecation.
func TestInspectTerraformReadsWhatTheStaticWalkLeavesOut(t *testing.T) {
	files := []File{{Path: "variables.tf", Data: []byte(`
variable "region" {
  type     = string
  nullable = false

  validation {
    condition     = contains(["us-east1", "europe-west1"], var.region)
    error_message = "Region must be us-east1 or europe-west1."
  }
  validation {
    condition     = length(var.region) > 0
    error_message = "Region ${var.region} is empty."
  }
}

variable "token" {
  type      = string
  ephemeral = true
}

variable "legacy_tier" {
  type       = string
  default    = "small"
  deprecated = "Use tier instead."
}

variable "computed" {
  type     = string
  nullable = var.region != ""
}
`)}, {Path: "more.tf.json", Data: []byte(`{"variable": {"from_json": {"type": "string", "nullable": false}}}`)}}

	r, err := Inspect(files, KindTerraform)
	require.NoError(t, err)
	byName := map[string]Input{}
	for _, in := range r.Contract.Inputs {
		byName[in.Name] = in
	}

	region := byName["region"]
	require.NotNil(t, region.Nullable)
	assert.False(t, *region.Nullable)
	assert.Equal(t, []Validation{
		{Condition: `contains(["us-east1", "europe-west1"], var.region)`, ErrorMessage: "Region must be us-east1 or europe-west1."},
		{Condition: `length(var.region) > 0`, ErrorMessage: `"Region ${var.region} is empty."`},
	}, region.Validations, "conditions as written; a plain message as its reader sees it, an interpolated one as written")

	token := byName["token"]
	assert.True(t, token.Ephemeral)
	assert.True(t, token.Sensitive, "an ephemeral value is never displayed either")

	assert.Equal(t, "Use tier instead.", byName["legacy_tier"].Deprecated)

	computed := byName["computed"]
	require.NotNil(t, computed.Nullable)
	assert.True(t, *computed.Nullable, "a non-literal nullable is not guessed; the default stands")

	fromJSON := byName["from_json"]
	require.NotNil(t, fromJSON.Nullable)
	assert.False(t, *fromJSON.Nullable, ".tf.json is read too")
}

// values.schema.json is authoritative where it speaks, and can declare an
// input values.yaml leaves out.
func TestInspectHelmReadsTheValuesSchema(t *testing.T) {
	files := []File{
		{Path: "Chart.yaml", Data: []byte("apiVersion: v2\nname: api\nversion: 1.0.0\n")},
		{Path: "values.yaml", Data: []byte("replicas: 2\ndebug: false\n")},
		{Path: "values.schema.json", Data: []byte(`{
  "type": "object",
  "required": ["replicas", "hostname"],
  "properties": {
    "replicas": {"type": "integer", "minimum": 1, "description": "Pod count."},
    "hostname": {"type": ["string", "null"], "format": "hostname"},
    "legacy":   {"type": "boolean", "deprecated": true}
  }
}`)},
	}
	r, err := Inspect(files, "")
	require.NoError(t, err)
	byName := map[string]Input{}
	var order []string
	for _, in := range r.Contract.Inputs {
		byName[in.Name] = in
		order = append(order, in.Name)
	}
	assert.Equal(t, []string{"debug", "hostname", "legacy", "replicas"}, order, "sorted, schema-only inputs included")

	replicas := byName["replicas"]
	assert.True(t, replicas.Required)
	assert.Equal(t, "number", replicas.Type)
	assert.Equal(t, "Pod count.", replicas.Description)
	assert.EqualValues(t, 2, replicas.Default, "the default still comes from values.yaml")
	require.NotNil(t, replicas.Nullable)
	assert.False(t, *replicas.Nullable)
	assert.JSONEq(t, `{"type": "integer", "minimum": 1, "description": "Pod count."}`, string(replicas.Schema))

	hostname := byName["hostname"]
	assert.True(t, hostname.Required)
	assert.Equal(t, "string", hostname.Type)
	require.NotNil(t, hostname.Nullable)
	assert.True(t, *hostname.Nullable)
	assert.Nil(t, hostname.Default)

	assert.Equal(t, "deprecated", byName["legacy"].Deprecated)

	debug := byName["debug"]
	assert.Nil(t, debug.Nullable, "no schema for it, so nothing is claimed")
	assert.Nil(t, debug.Schema)
	assert.False(t, debug.Required)

	files[2].Data = []byte("{not json")
	_, err = Inspect(files, "")
	assert.ErrorContains(t, err, "values.schema.json")
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

// A tar whose links to directories multiply what is under them is stopped
// by entries as it expands, not only by bytes after.
func TestNormalizeStopsLinkExpansionEarly(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, typ byte, link string, data string) {
		hdr := &tar.Header{Name: name, Typeflag: typ, Linkname: link, Mode: 0o644, Size: int64(len(data))}
		require.NoError(t, tw.WriteHeader(hdr))
		if typ == tar.TypeReg {
			_, _ = tw.Write([]byte(data))
		}
	}
	// d0 holds 64 files; d1 holds 64 links to d0; d2 holds 64 links to d1;
	// d3 holds 64 links to d2: 64^4 entries once resolved.
	for i := 0; i < 64; i++ {
		add(fmt.Sprintf("d0/f%d", i), tar.TypeReg, "", "x")
	}
	for level := 1; level <= 3; level++ {
		for i := 0; i < 64; i++ {
			add(fmt.Sprintf("d%d/l%d", level, i), tar.TypeSymlink, fmt.Sprintf("../d%d", level-1), "")
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	assert.Less(t, buf.Len(), 1<<16, "small on the wire")

	done := make(chan error, 1)
	go func() { _, err := Normalize(bytes.NewReader(buf.Bytes())); done <- err }()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, ErrTooManyEntries)
	case <-time.After(30 * time.Second):
		t.Fatal("Normalize did not return")
	}
}

func TestNormalizeBoundsEntries(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := 0; i <= maxEntries; i++ {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("f%d", i), Typeflag: tar.TypeReg, Mode: 0o644}))
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	_, err := Normalize(bytes.NewReader(buf.Bytes()))
	assert.ErrorIs(t, err, ErrTooManyEntries)
}
