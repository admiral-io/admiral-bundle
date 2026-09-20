package bundle

// Pack turns a directory into the gzipped tar a registry stores, closing it
// on the way: every Terraform module the tree calls from outside the root is
// brought into vendor/ and the call rewritten to point there, recursively,
// until nothing points outside. A local path that escapes the root is
// copied; a registry address, a git URL or an archive is resolved and
// fetched (fetch.go), and what it resolved to is recorded as a Pin.
//
// This is the client's half of the closure step. The developer's machine is
// where the sources and the credentials are, so this is where a tree can be
// closed; the registry walks the uploaded bundle and refuses anything still
// open.
//
// The working copy is never touched. Everything happens in a staging copy,
// which is what gets packed.

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
	// ErrSourceDirMissing is a local module source, or a file:// chart
	// dependency, whose directory does not exist on disk. ErrSourceMissing
	// is the server's word for one absent from a bundle.
	ErrSourceDirMissing = errors.New("source directory does not exist")
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
	// Kind is what Detect said the component is.
	Kind Kind
	// Bytes is the gzipped tar.
	Bytes []byte
	// Files is how many regular files and symlinks the tar holds.
	Files int
	// Vendored is every outside source brought into the tree, in walk order.
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
// anonymous. The rest is what a server sets when the tree it packs was
// written by someone else.
type Options struct {
	Credentials Credentials
	// Git is the transport git sources are cloned with; nil is Git{}, go-git
	// with the host's known_hosts and ssh agent.
	Git GitTransport
	// Boundary is a directory that local sources and `file://` sources may
	// not escape: a module call `../../..` or a chart dependency
	// `file://../..` resolving outside it is refused rather than vendored.
	// Empty means the host, which is right on a developer's own machine and
	// wrong anywhere a tree someone else wrote is packed: a pull request, an
	// upload. The repository top is the natural value.
	Boundary string
	// AllowInsecureHTTP lets a credential be presented over cleartext http.
	// Off, a credential rides https or the fetch is refused; a redirect
	// from https to http is refused either way.
	AllowInsecureHTTP bool
	// Dial replaces the dialer every HTTP fetch uses: the module registry,
	// archives, chart repositories and OCI registries. DialPublic refuses
	// loopback, private and link-local destinations after name resolution,
	// which is what a server fetching on someone else's behalf wants. Git
	// transports have their own network and are not covered.
	Dial Dialer
}

// git is the transport: what was given, else go-git with the host's own
// known_hosts and ssh agent.
func (o Options) git() GitTransport {
	if o.Git != nil {
		return o.Git
	}
	return &Git{Credentials: o.Credentials}
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
	info, err := os.Stat(rootAbs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
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

	if err := copyTree(rootAbs, stage, rootAbs, false); err != nil {
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
		f := newFetcher(scratch, opts)
		vendored, err = closeTerraform(ctx, rootAbs, stage, f)
		if err != nil {
			return nil, err
		}
		pins = f.pins
	case KindHelm:
		vendored, pins, version, err = closeHelm(ctx, rootAbs, stage, newHelmFetcher(opts))
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
	if err := withinBoundary(f.boundary, rootAbs); err != nil {
		return nil, err
	}
	type module struct {
		abs, rel string
		tree     *fetched
	}
	placed := map[string]string{rootAbs: "."} // abs -> bundle dir
	used := map[string]bool{".": true}
	queue := []module{{rootAbs, ".", nil}}
	walked := map[string]bool{} // module dirs whose own calls have been read
	var out []Vendored

	// place records that a directory on disk now lives in the bundle and
	// returns where: under a placed ancestor that already brought it along,
	// or at targetRel, copied there. Links inside the copy may resolve
	// anywhere in boundary (the fetched tree, or the escaping directory
	// itself) and nowhere else. Whatever computed targetRel, the copy lands
	// inside the stage or not at all.
	place := func(m module, source, targetAbs, targetRel, boundary string) (string, error) {
		if rel, ok := placedUnder(placed, targetAbs); ok {
			placed[targetAbs] = rel
			return rel, nil
		}
		dst := filepath.Join(stage, filepath.FromSlash(targetRel))
		if !inside(stage, dst) {
			return "", fmt.Errorf("%w: %s at %q", ErrVendorEscapes, redactSource(source), targetRel)
		}
		if err := copyTree(targetAbs, dst, boundary, true); err != nil {
			return "", fmt.Errorf("vendor %s: %w", redactSource(source), err)
		}
		placed[targetAbs] = targetRel
		out = append(out, Vendored{Caller: m.rel, Source: redactSource(source), Into: targetRel})
		return targetRel, nil
	}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m := queue[0]
		queue = queue[1:]
		// A module is read once, however many calls reach it; a cycle of
		// local calls would otherwise never end.
		if walked[m.abs] {
			continue
		}
		walked[m.abs] = true

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
				err                  error
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
					return nil, fmt.Errorf("%w: %s has source %q", ErrSourceDirMissing, where, call.Source)
				}
				// Lexically inside is not enough: a link on the way may
				// point out of the tree.
				if m.tree != nil {
					if err := resolvesInside(m.tree.abs, targetAbs); err != nil {
						return nil, fmt.Errorf("%w: %s has source %q", err, where, call.Source)
					}
				}
				rel, known := placed[targetAbs]
				switch {
				case known:
					targetRel = rel
				case m.tree != nil:
					r, _ := filepath.Rel(m.tree.abs, targetAbs)
					targetRel = path.Join(m.tree.prefix, filepath.ToSlash(r))
					if targetRel, err = place(m, call.Source, targetAbs, targetRel, m.tree.abs); err != nil {
						return nil, err
					}
				case inside(rootAbs, targetAbs):
					r, _ := filepath.Rel(rootAbs, targetAbs)
					targetRel = filepath.ToSlash(r)
					placed[targetAbs] = targetRel
				default:
					// A local escape from the root reaches the host; the
					// boundary, when set, says how far.
					if err := withinBoundary(f.boundary, targetAbs); err != nil {
						return nil, fmt.Errorf("%w: %s has source %q", err, where, call.Source)
					}
					// A vendor path is picked only when a placed ancestor
					// has not already decided where this directory lives.
					if rel, ok := placedUnder(placed, targetAbs); ok {
						targetRel = rel
					} else {
						targetRel = vendorPath(rootAbs, targetAbs, stage, used)
					}
					if targetRel, err = place(m, call.Source, targetAbs, targetRel, targetAbs); err != nil {
						return nil, err
					}
				}
			case sourceNonLiteral:
				return nil, fmt.Errorf("%w: %s has source %q", ErrSourceNonLiteral, where, call.Source)
			case sourceUnsupported:
				return nil, fmt.Errorf("%w: %s has source %q", ErrSourceUnsupported, where, call.Source)
			default:
				var t *fetched
				var subdir string
				if t, subdir, err = f.resolve(ctx, call); err != nil {
					return nil, fmt.Errorf("%s: %w", where, err)
				}
				tree = t
				targetAbs = filepath.Join(t.abs, filepath.FromSlash(subdir))
				if info, err := os.Stat(targetAbs); err != nil || !info.IsDir() {
					return nil, fmt.Errorf("%w: %s has source %q (%s)", ErrSubdirMissing, where, call.Source, subdir)
				}
				// The subdir was cleaned before the fetch; what remains is a
				// link on the way to it pointing out of the tree.
				if err := resolvesInside(t.abs, targetAbs); err != nil {
					return nil, fmt.Errorf("%w: %s has source %q (%s)", err, where, call.Source, subdir)
				}
				rel, known := placed[targetAbs]
				if known {
					targetRel = rel
				} else {
					targetRel = path.Join(t.prefix, subdir)
					if targetRel, err = place(m, call.Source, targetAbs, targetRel, t.abs); err != nil {
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
	if strings.HasSuffix(file, ".json") {
		// hclwrite edits native syntax only; a call in JSON has nowhere
		// to be rewritten, and a rewritten file would no longer be what
		// the author committed anyway.
		return fmt.Errorf("%w: module %q in %s; JSON module calls are read but cannot be rewritten, declare it in HCL", ErrSourceUnsupported, moduleName, filepath.Base(file))
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	f, diags := hclwrite.ParseConfig(src, file, hcl.InitialPos)
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

// inside reports whether p is root or under it, lexically. Both must be
// spelled from the same base; a link on the way is not seen, which is what
// resolvesInside is for.
func inside(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolvesInside is inside after every link on both paths is followed: a
// directory reached through `esc -> /` sits lexically inside the tree and
// really does not.
func resolvesInside(root, p string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	realP, err := filepath.EvalSymlinks(p)
	if err != nil {
		return err
	}
	if !inside(realRoot, realP) {
		return ErrFetchedEscapes
	}
	return nil
}

// --- Files ------------------------------------------------------------------

// ignored is what a working copy carries that a bundle never should.
func ignored(name string) bool {
	return name == ".git" || name == ".terraform" || name == ".terragrunt-cache"
}

// copyTree copies src to dst, skipping ignored directories and keeping the
// execute bit as the one mode bit that matters. A symlink is not carried: one
// whose target resolves inside boundary is replaced by a copy of the target,
// one that resolves outside is refused, and a link to a directory already
// being copied is a cycle and refused too. A vendored copy also drops
// `.terraform.lock.hcl`: tofu reads only the root's, and an upstream
// re-running init would move the digest for no change in what the module
// does.
func copyTree(src, dst, boundary string, vendored bool) error {
	realBoundary, err := filepath.EvalSymlinks(boundary)
	if err != nil {
		return err
	}
	c := &copier{boundary: realBoundary, vendored: vendored, active: map[string]bool{}}
	return c.dir(src, dst)
}

// copier is one copyTree in progress.
type copier struct {
	boundary string
	vendored bool
	// active is every real directory on the current path from the copy's
	// root, so a link back up is caught before it recurses forever.
	active map[string]bool
}

func (c *copier) dir(src, dst string) error {
	realSrc, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	if !inside(c.boundary, realSrc) {
		return fmt.Errorf("%w: %s -> %s", ErrLinkEscapes, src, realSrc)
	}
	if c.active[realSrc] {
		return fmt.Errorf("symlink cycle: %s -> %s", src, realSrc)
	}
	c.active[realSrc] = true
	defer delete(c.active, realSrc)

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(src, e.Name())
		target := filepath.Join(dst, e.Name())
		switch {
		case e.IsDir():
			if ignored(e.Name()) {
				continue
			}
			if err := c.dir(p, target); err != nil {
				return err
			}
		case e.Type()&fs.ModeSymlink != 0:
			realTarget, err := filepath.EvalSymlinks(p)
			if err != nil {
				return fmt.Errorf("symlink %s: %w", p, err)
			}
			if !inside(c.boundary, realTarget) {
				return fmt.Errorf("%w: %s -> %s", ErrLinkEscapes, p, realTarget)
			}
			info, err := os.Stat(realTarget)
			if err != nil {
				return err
			}
			switch {
			case info.IsDir():
				if ignored(e.Name()) {
					continue
				}
				if err := c.dir(p, target); err != nil {
					return err
				}
			case info.Mode().IsRegular():
				if c.vendored && e.Name() == ".terraform.lock.hcl" {
					continue
				}
				if err := copyFile(realTarget, target, fileMode(info)); err != nil {
					return err
				}
			}
		case e.Type().IsRegular():
			if c.vendored && e.Name() == ".terraform.lock.hcl" {
				continue
			}
			info, err := e.Info()
			if err != nil {
				return err
			}
			if err := copyFile(p, target, fileMode(info)); err != nil {
				return err
			}
		}
	}
	return nil
}

// fileMode keeps the execute bit and nothing else.
func fileMode(info fs.FileInfo) os.FileMode {
	if info.Mode()&0o111 != 0 {
		return 0o755
	}
	return 0o644
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
		// The stage holds regular files only: copyTree resolved every link.
		info, err := os.Lstat(p)
		if err != nil {
			return nil, 0, err
		}
		if !info.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("%w: %s", ErrEntryKind, name)
		}
		hdr := &tar.Header{
			Name: name, ModTime: time.Time{}, Format: tar.FormatPAX,
			Typeflag: tar.TypeReg, Size: info.Size(), Mode: int64(info.Mode().Perm()),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, 0, err
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, 0, err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		if err != nil {
			return nil, 0, err
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
