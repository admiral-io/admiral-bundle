package bundle

// Pack is the client's half of the closure step: it turns a directory into
// the gzipped tar `admiral component publish` uploads, closing it on the way.
// Every Terraform module the tree calls by a local path that escapes the root
// is copied into vendor/ and the call rewritten to point there, recursively,
// until nothing points outside. The developer's machine is where the sources
// are, so this is where local escapes can be resolved; the server's Close
// refuses anything still open. Remote sources (registry addresses, git URLs)
// are not vendored here yet and are reported as such.
//
// The working copy is never touched. Everything happens in a staging copy,
// which is what gets packed.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/hashicorp/terraform-config-inspect/tfconfig"
	"github.com/zclconf/go-cty/cty"
)

// vendorDir is where escaping sources land inside the bundle.
const vendorDir = "vendor"

var (
	ErrRemoteSource = errors.New("module source is a remote address; vendor it into the tree before publishing (remote sources are not fetched by the CLI yet)")
	ErrMissing      = errors.New("module source directory does not exist")
)

// Vendored is one escaping source the packer brought into the bundle.
type Vendored struct {
	// Caller is the bundle directory of the module making the call.
	Caller string
	// Source is the call as written, e.g. `../modules/net`.
	Source string
	// Into is the bundle directory it now lives at, e.g. `vendor/modules/net`.
	Into string
}

// Packed is a bundle ready to upload.
type Packed struct {
	Kind     Kind
	Bytes    []byte
	Files    int
	Vendored []Vendored
}

// Pack stages, closes and packs the component at root.
func Pack(root string) (*Packed, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(rootAbs); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}

	kind, err := DetectDir(rootAbs)
	if err != nil {
		return nil, err
	}

	stage, err := os.MkdirTemp("", "admiral-publish-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)

	if err := copyTree(rootAbs, stage); err != nil {
		return nil, fmt.Errorf("stage %s: %w", root, err)
	}

	var vendored []Vendored
	if kind == KindTerraform {
		vendored, err = closeTerraform(rootAbs, stage)
		if err != nil {
			return nil, err
		}
	}

	data, count, err := packTree(stage)
	if err != nil {
		return nil, err
	}
	return &Packed{Kind: kind, Bytes: data, Files: count, Vendored: vendored}, nil
}

// DetectDir is Detect over a directory on disk, for the client before it
// packs: a Chart.yaml is a chart, any .tf file is a module, otherwise YAML
// documents are raw manifests.
func DetectDir(root string) (Kind, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	var tf, yamls bool
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch name := e.Name(); {
		case name == "Chart.yaml":
			return KindHelm, nil
		case strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tf.json"):
			tf = true
		case strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
			yamls = true
		}
	}
	switch {
	case tf:
		return KindTerraform, nil
	case yamls:
		return KindManifests, nil
	default:
		return "", ErrUnknownKind
	}
}

// --- Closure ----------------------------------------------------------------

// closeTerraform walks module calls from the root and vendors every local
// source that escapes it. Each module directory is known by two paths: where
// it really is (abs), which is what its own relative sources resolve
// against, and where it sits in the bundle (rel), which is what the rewritten
// sources point at.
func closeTerraform(rootAbs, stage string) ([]Vendored, error) {
	type module struct{ abs, rel string }
	placed := map[string]string{rootAbs: "."} // abs -> bundle dir
	used := map[string]bool{".": true}
	queue := []module{{rootAbs, "."}}
	var out []Vendored

	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]

		mod, diags := tfconfig.LoadModule(m.abs)
		for _, d := range diags {
			if d.Severity == tfconfig.DiagError {
				return nil, fmt.Errorf("%s: %s: %s", displayDir(m.rel), d.Summary, d.Detail)
			}
		}

		for _, name := range sortedKeys(mod.ModuleCalls) {
			call := mod.ModuleCalls[name]
			if !isLocalSource(call.Source) {
				if strings.HasPrefix(call.Source, "var.") || strings.HasPrefix(call.Source, "local.") {
					return nil, fmt.Errorf("module %q in %s has a non-literal source %q; the registry needs sources it can read", name, displayDir(m.rel), call.Source)
				}
				return nil, fmt.Errorf("%w: module %q in %s has source %q", ErrRemoteSource, name, displayDir(m.rel), call.Source)
			}

			targetAbs := filepath.Clean(filepath.Join(m.abs, filepath.FromSlash(call.Source)))
			if info, err := os.Stat(targetAbs); err != nil || !info.IsDir() {
				return nil, fmt.Errorf("%w: module %q in %s has source %q", ErrMissing, name, displayDir(m.rel), call.Source)
			}

			targetRel, known := placed[targetAbs]
			switch {
			case known:
				// Already in the bundle, by being inside the root or by an
				// earlier vendoring.
			case inside(rootAbs, targetAbs):
				r, _ := filepath.Rel(rootAbs, targetAbs)
				targetRel = filepath.ToSlash(r)
				placed[targetAbs] = targetRel
			default:
				targetRel = vendorPath(rootAbs, targetAbs, stage, used)
				if err := copyTree(targetAbs, filepath.Join(stage, filepath.FromSlash(targetRel))); err != nil {
					return nil, fmt.Errorf("vendor %s: %w", call.Source, err)
				}
				placed[targetAbs] = targetRel
				out = append(out, Vendored{Caller: m.rel, Source: call.Source, Into: targetRel})
			}

			// The call must now point at the bundle location, from the
			// caller's bundle location. Unchanged when the source was already
			// inside the root and nothing moved.
			want := relativeSource(m.rel, targetRel)
			if path.Clean(call.Source) != path.Clean(want) {
				if err := rewriteSource(stageFile(stage, m, call.Pos.Filename), name, want); err != nil {
					return nil, err
				}
			}
			queue = append(queue, module{targetAbs, targetRel})
		}
	}
	return out, nil
}

// vendorPath picks a bundle directory for an outside source: its path
// relative to the root with the `..` segments dropped, under vendor/, so
// `../../modules/net` becomes `vendor/modules/net`. Two different outside
// directories that flatten to the same name, or a name the tree already
// has, get a numeric suffix.
func vendorPath(rootAbs, targetAbs, stage string, used map[string]bool) string {
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		rel = filepath.Base(targetAbs)
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	var keep []string
	for _, p := range parts {
		if p != ".." && p != "." && p != "" {
			keep = append(keep, p)
		}
	}
	if len(keep) == 0 {
		keep = []string{filepath.Base(targetAbs)}
	}
	base := path.Join(vendorDir, path.Join(keep...))
	candidate := base
	taken := func(c string) bool {
		if used[c] {
			return true
		}
		_, err := os.Stat(filepath.Join(stage, filepath.FromSlash(c)))
		return err == nil
	}
	for i := 2; taken(candidate); i++ {
		candidate = fmt.Sprintf("%s-%d", base, i)
	}
	used[candidate] = true
	return candidate
}

// relativeSource is the `./`-prefixed relative path from one bundle dir to
// another, the form Terraform reads as local.
func relativeSource(from, to string) string {
	rel, err := filepath.Rel(filepath.FromSlash(from), filepath.FromSlash(to))
	if err != nil {
		return "./" + to
	}
	rel = filepath.ToSlash(rel)
	if !strings.HasPrefix(rel, "../") && rel != ".." {
		rel = "./" + rel
	}
	return rel
}

// stageFile maps a file the walk read from the real module directory to its
// copy in the staging tree, where the rewrite happens.
func stageFile(stage string, m struct{ abs, rel string }, filename string) string {
	base := filepath.Base(filename)
	return filepath.Join(stage, filepath.FromSlash(m.rel), base)
}

// rewriteSource sets the source attribute of one module block in a file,
// preserving everything else byte for byte. hclwrite edits the syntax tree,
// so comments, spacing and every other block stay as they were.
func rewriteSource(file, moduleName, source string) error {
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	f, diags := hclwrite.ParseConfig(src, file, hclPos())
	if diags.HasErrors() {
		return fmt.Errorf("parse %s: %s", file, diags.Error())
	}
	var found bool
	for _, block := range f.Body().Blocks() {
		if block.Type() != "module" || len(block.Labels()) != 1 || block.Labels()[0] != moduleName {
			continue
		}
		block.Body().SetAttributeValue("source", cty.StringVal(source))
		found = true
	}
	if !found {
		return fmt.Errorf("module %q not found in %s", moduleName, file)
	}
	return os.WriteFile(file, f.Bytes(), 0o644)
}

func inside(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// --- Files ------------------------------------------------------------------

// copyTree copies src to dst, skipping ignored directories, keeping symlinks
// as symlinks and the execute bit as the one mode bit that matters.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() && rel != "." && isIgnored(d.Name()) {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			info, err := d.Info()
			if err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if info.Mode()&0o111 != 0 {
				mode = 0o755
			}
			return copyFile(p, target, mode)
		}
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		// A write error and a close error can both carry the reason; keep
		// both rather than let the second hide the first.
		return errors.Join(err, out.Close())
	}
	return out.Close()
}

// packTree writes the staged tree as a gzipped tar with paths relative to
// the root. The server normalizes ordering and timestamps; this only has to
// be a faithful tar.
func packTree(stage string) ([]byte, int, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	count := 0

	var paths []string
	err := filepath.WalkDir(stage, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	sort.Strings(paths)

	for _, p := range paths {
		rel, _ := filepath.Rel(stage, p)
		name := filepath.ToSlash(rel)
		info, err := os.Lstat(p)
		if err != nil {
			return nil, 0, err
		}
		hdr := &tar.Header{Name: name, ModTime: time.Time{}, Format: tar.FormatPAX}
		if info.Mode()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return nil, 0, err
			}
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = filepath.ToSlash(link)
			hdr.Mode = 0o777
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = info.Size()
			hdr.Mode = int64(info.Mode().Perm())
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, 0, err
		}
		if hdr.Typeflag == tar.TypeReg {
			f, err := os.Open(p)
			if err != nil {
				return nil, 0, err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			if err != nil {
				return nil, 0, err
			}
		}
		count++
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	if err := gz.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), count, nil
}

func hclPos() hcl.Pos { return hcl.Pos{Line: 1, Column: 1} }
