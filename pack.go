// Pack turns a directory into the gzipped tar `admiral component publish`
// uploads, closing it on the way: every Terraform module the tree
// calls from outside the root is brought into vendor/ and the call rewritten
// to point there, recursively, until nothing points outside. A local path
// that escapes the root is copied; a registry address, a git URL or an
// archive is resolved and fetched (fetch.go), and what it resolved to is
// recorded as a pin on the revision's provenance.
//
// This is the client's half of the registry design's closure step. The
// developer's machine is where the sources and the credentials are, so this
// is where a tree can be closed; the server walks the uploaded bundle and
// refuses anything still open.
//
// The working copy is never touched. Everything happens in a staging copy,
// which is what gets packed.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
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
	// ErrMissing is a local module source whose directory does not exist.
	ErrMissing = errors.New("module source directory does not exist")
)

// Vendored is one escaping source the packer brought into the bundle.
type Vendored struct {
	// Caller is the bundle directory of the module making the call.
	Caller string
	// Source is the call as written: `../modules/net`,
	// `GoogleCloudPlatform/cloud-armor/google`, `git::ssh://…?ref=…`.
	Source string
	// Into is the bundle directory it now lives at, e.g. `vendor/modules/net`
	// or `vendor/registry.opentofu.org/GoogleCloudPlatform/cloud-armor/google/8.1.0`.
	Into string
}

// Packed is a bundle ready to upload.
type Packed struct {
	Kind     Kind
	Bytes    []byte
	Files    int
	Vendored []Vendored
	// Pins is what the closure step resolved from a constraint to an exact
	// version: a chart's dependencies today, a module's remote sources when
	// those are fetched. Recorded on the revision's provenance.
	Pins []Pin
	// Version is the version the component declares for itself, when its
	// format has one: a chart's Chart.yaml version. Terraform has no such
	// field, and the string is empty.
	Version string
}

// Options is what a Pack may be given: the credentials remote fetches
// present, and the transport git sources are cloned with. Without a
// transport a git source is refused; without credentials every fetch is
// anonymous.
type Options struct {
	Credentials Credentials
	Git         GitTransport
}

// Pack stages, closes and packs the component at root, anonymously and
// without git.
func Pack(root string) (*Packed, error) {
	return PackContext(context.Background(), root, Options{})
}

// PackContext is Pack with a context and options.
func PackContext(ctx context.Context, root string, opts Options) (*Packed, error) {
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

	if err := copyTree(rootAbs, stage, false); err != nil {
		return nil, fmt.Errorf("stage %s: %w", root, err)
	}

	var (
		vendored []Vendored
		pins     []Pin
		version  string
	)
	switch kind {
	case KindTerraform:
		scratch, err := os.MkdirTemp("", "admiral-fetch-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(scratch)
		f := newFetcher(scratch, opts.Credentials, opts.Git)
		vendored, err = closeTerraform(ctx, rootAbs, stage, f)
		if err != nil {
			return nil, err
		}
		pins = f.pins
	case KindHelm:
		vendored, pins, version, err = closeHelm(ctx, rootAbs, stage, newHelmFetcher(opts.Credentials))
		if err != nil {
			return nil, err
		}
	}

	data, count, err := packTree(stage)
	if err != nil {
		return nil, err
	}
	return &Packed{Kind: kind, Bytes: data, Files: count, Vendored: vendored, Pins: pins, Version: version}, nil
}

// DetectDir is Detect for a directory on disk: a Chart.yaml is a chart, any
// .tf file is a module, otherwise YAML documents are raw manifests.
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

// closeTerraform walks module calls from the root and brings every source
// that is not already in the bundle into it. Each module directory is known
// by two paths: where it really is (abs), which is what its own relative
// sources resolve against, and where it sits in the bundle (rel), which is
// what the rewritten sources point at. A module that came from a fetched
// tree also knows that tree, because its relative sources may only reach
// within it.
func closeTerraform(ctx context.Context, rootAbs, stage string, f *fetcher) ([]Vendored, error) {
	type module struct {
		abs, rel string
		tree     *fetched
	}
	placed := map[string]string{rootAbs: "."} // abs -> bundle dir
	used := map[string]bool{".": true}
	queue := []module{{rootAbs, ".", nil}}
	var out []Vendored

	// place records that a directory on disk now lives in the bundle,
	// copying it there unless a placed ancestor already brought it along.
	place := func(m module, source, targetAbs, targetRel string) error {
		if _, ok := placedUnder(placed, targetAbs); ok {
			placed[targetAbs] = targetRel
			return nil
		}
		if err := copyTree(targetAbs, filepath.Join(stage, filepath.FromSlash(targetRel)), true); err != nil {
			return fmt.Errorf("vendor %s: %w", source, err)
		}
		placed[targetAbs] = targetRel
		out = append(out, Vendored{Caller: m.rel, Source: source, Into: targetRel})
		return nil
	}

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
			where := fmt.Sprintf("module %q in %s", name, displayDir(m.rel))

			var (
				targetAbs, targetRel string
				tree                 = m.tree
			)
			kind, _ := classify(call.Source)
			switch kind {
			case sourceLocal:
				targetAbs = filepath.Clean(filepath.Join(m.abs, filepath.FromSlash(call.Source)))
				// Inside a fetched tree, a relative source may reach
				// anywhere in that tree and nowhere else.
				if m.tree != nil && !inside(m.tree.abs, targetAbs) {
					return nil, fmt.Errorf("%w: %s has source %q", ErrFetchedEscapes, where, call.Source)
				}
				if info, err := os.Stat(targetAbs); err != nil || !info.IsDir() {
					return nil, fmt.Errorf("%w: %s has source %q", ErrMissing, where, call.Source)
				}
				rel, known := placed[targetAbs]
				switch {
				case known:
					targetRel = rel
				case m.tree != nil:
					r, _ := filepath.Rel(m.tree.abs, targetAbs)
					targetRel = path.Join(m.tree.prefix, filepath.ToSlash(r))
					if err := place(m, call.Source, targetAbs, targetRel); err != nil {
						return nil, err
					}
				case inside(rootAbs, targetAbs):
					r, _ := filepath.Rel(rootAbs, targetAbs)
					targetRel = filepath.ToSlash(r)
					placed[targetAbs] = targetRel
				default:
					targetRel = vendorPath(rootAbs, targetAbs, stage, used)
					if err := place(m, call.Source, targetAbs, targetRel); err != nil {
						return nil, err
					}
				}
			case sourceNonLiteral:
				return nil, fmt.Errorf("%w: %s has source %q", ErrSourceNonLiteral, where, call.Source)
			case sourceUnsupported:
				return nil, fmt.Errorf("%w: %s has source %q", ErrSourceUnsupported, where, call.Source)
			default:
				t, subdir, err := f.resolve(ctx, call)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", where, err)
				}
				tree = t
				targetAbs = filepath.Join(t.abs, filepath.FromSlash(subdir))
				if info, err := os.Stat(targetAbs); err != nil || !info.IsDir() {
					return nil, fmt.Errorf("%w: %s has source %q (%s)", ErrSubdirMissing, where, call.Source, subdir)
				}
				rel, known := placed[targetAbs]
				if known {
					targetRel = rel
				} else {
					targetRel = path.Join(t.prefix, subdir)
					if err := place(m, call.Source, targetAbs, targetRel); err != nil {
						return nil, err
					}
				}
			}

			// The call must now point at the bundle location, from the
			// caller's bundle location. Unchanged when the source was already
			// inside the root and nothing moved.
			want := relativeSource(m.rel, targetRel)
			if kind != sourceLocal || path.Clean(call.Source) != path.Clean(want) {
				if err := rewriteSource(stageFile(stage, m.rel, call.Pos.Filename), name, want); err != nil {
					return nil, err
				}
			}
			queue = append(queue, module{targetAbs, targetRel, tree})
		}
	}
	return out, nil
}

// placedUnder finds the bundle directory of a path that a placed directory
// already contains, so a subdirectory of a copied tree is not copied twice.
func placedUnder(placed map[string]string, targetAbs string) (string, bool) {
	best, bestRel := "", ""
	for abs, rel := range placed {
		if inside(abs, targetAbs) && len(abs) > len(best) {
			best, bestRel = abs, rel
		}
	}
	if best == "" {
		return "", false
	}
	r, _ := filepath.Rel(best, targetAbs)
	return path.Join(bestRel, filepath.ToSlash(r)), true
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
func stageFile(stage, rel, filename string) string {
	return filepath.Join(stage, filepath.FromSlash(rel), filepath.Base(filename))
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

// ignored is what a working copy carries that a bundle never should.
func ignored(name string) bool {
	return name == ".git" || name == ".terraform" || name == ".terragrunt-cache"
}

// copyTree copies src to dst, skipping ignored directories, keeping symlinks
// as symlinks and the execute bit as the one mode bit that matters. A
// vendored copy also drops `.terraform.lock.hcl`: tofu reads only the root's,
// and an upstream re-running init would move the digest for no change in
// what the module does.
func copyTree(src, dst string, vendored bool) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() && rel != "." && ignored(d.Name()) {
			return filepath.SkipDir
		}
		if vendored && !d.IsDir() && d.Name() == ".terraform.lock.hcl" {
			return nil
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
