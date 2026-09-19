package bundle

// The read side: what happens to a bundle's bytes between arrival and
// storage, with no database and no object store in sight.
//
// Normalize reads the gzipped tar a client sent and produces the canonical
// form that is digested: `.git` stripped, entries sorted, ownership and
// timestamps zeroed. Publishing the same tree twice yields the same digest,
// which is what makes a repeat publish a no-op. Inspect reads the normalized
// tree and says what it is (Terraform, Helm, manifests) and what it takes and
// gives, and notices what the publish gate should say about it.
//
// Close walks the module tree and refuses anything that is not inside the
// bundle. Vendoring itself happens where the sources can be reached, which
// is what Pack does before upload.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// MaxUncompressed bounds what a bundle may expand to. The wire cap is on the
// compressed bytes; this is the gzip-bomb guard, so it is not configurable.
const MaxUncompressed = 512 << 20

var (
	// ErrNotTarGz is input that does not begin as a gzip stream.
	ErrNotTarGz = errors.New("bundle is not a gzipped tar")
	// ErrBadPath is an entry whose name is absolute, contains `..`, or is a
	// symlink resolving outside the root.
	ErrBadPath = errors.New("bundle entry has an unsafe path")
	// ErrTooLarge is a bundle that expands past MaxUncompressed.
	ErrTooLarge = errors.New("bundle expands past the size limit")
	// ErrEmpty is a bundle with no regular files in it.
	ErrEmpty = errors.New("bundle contains no files")
	// ErrEntryKind is a tar entry of a type a source tree never has: a
	// device, a fifo, a hard link.
	ErrEntryKind = errors.New("bundle entry is not a file, directory or symlink")
)

// File is one entry in a normalized bundle.
type File struct {
	// Path relative to the component root, forward slashes, no leading `./`.
	Path string
	// Mode is either 0644 or 0755 after normalization: the only bit that
	// survives is execute, because it is the only bit a tool reads.
	Mode int64
	// Data is the file's contents.
	Data []byte
}

// Normalized is the canonical form of a bundle: the bytes that are digested
// and stored, and the tree they encode.
type Normalized struct {
	// Bytes is the canonical gzipped tar.
	Bytes []byte
	// Files is every entry, in the order it was written, directories omitted.
	Files []File
}

// Normalize canonicalizes a gzipped tar. It strips `.git` and `.terraform`
// directories at any depth, refuses paths that escape the root, drops ownership, timestamps and
// every mode bit but execute, sorts entries, and writes the result with a
// fixed gzip header so the output is a function of the tree alone.
//
// A symlink is never carried: one that resolves inside the tree becomes a
// copy of its target, one that escapes is refused. Pack already applies
// that rule on the client; applying it again here means Close and Inspect
// read the same tree whatever produced the archive.
//
// Directories are implied by their files and not written: a tool that needs
// them recreates them, and writing them would make an empty directory change
// the digest of a bundle that ships no bytes differently.
//
// The whole tree is held in memory: every file's bytes in Files, allocated
// once at their exact size, plus the canonical archive in Bytes. The ceiling
// is MaxUncompressed plus what it compresses to. A caller that keeps a
// Normalized around after storing Bytes may nil out Files[i].Data; Inspect,
// Close and CloseChart read only the files they name.
func Normalize(r io.Reader) (*Normalized, error) {
	files, err := readTree(r)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, ErrEmpty
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	// A fixed header: gzip otherwise records the current time and, through
	// some writers, a file name, either of which would make identical trees
	// digest differently.
	gz.Header = gzip.Header{ModTime: time.Time{}, OS: 255}
	tw := tar.NewWriter(gz)
	for _, f := range files {
		hdr := &tar.Header{
			Name:     f.Path,
			Mode:     f.Mode,
			Size:     int64(len(f.Data)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Time{},
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return &Normalized{Bytes: buf.Bytes(), Files: files}, nil
}

// readTree reads every entry worth keeping out of a gzipped tar.
func readTree(r io.Reader) ([]File, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotTarGz, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var (
		files []File
		links = make(map[string]string)
		seen  = make(map[string]bool)
		total int64
	)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotTarGz, err)
		}

		name, ok := cleanPath(hdr.Name)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrBadPath, hdr.Name)
		}
		if name == "" || isIgnored(name) {
			continue
		}
		if len(files)+len(links) >= maxEntries {
			return nil, fmt.Errorf("%w: more than %d", ErrTooManyEntries, maxEntries)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			if hdr.Size < 0 {
				return nil, fmt.Errorf("%w: %s has a negative size", ErrNotTarGz, name)
			}
			total += hdr.Size
			if total > MaxUncompressed {
				return nil, ErrTooLarge
			}
			// Exactly the declared size, allocated once: the tar reader ends
			// the entry there, so a short read is a truncated stream.
			data := make([]byte, hdr.Size)
			if _, err := io.ReadFull(tr, data); err != nil {
				return nil, fmt.Errorf("%w: %s is not the size its header claims", ErrNotTarGz, name)
			}
			if seen[name] {
				return nil, fmt.Errorf("%w: %q appears twice", ErrBadPath, name)
			}
			seen[name] = true
			files = append(files, File{Path: name, Mode: normalizeMode(hdr.Mode), Data: data})
		case tar.TypeSymlink:
			// A link that escapes the root is the classic archive attack and
			// is refused here; one that stays inside is resolved once the
			// whole tar is read, since its target may come later.
			if !linkStaysInside(name, hdr.Linkname) {
				return nil, fmt.Errorf("%w: symlink %q escapes the bundle", ErrBadPath, name)
			}
			if seen[name] {
				return nil, fmt.Errorf("%w: %q appears twice", ErrBadPath, name)
			}
			seen[name] = true
			links[name] = hdr.Linkname
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		default:
			return nil, fmt.Errorf("%w: %q", ErrEntryKind, name)
		}
	}
	if len(links) == 0 {
		return files, nil
	}
	return resolveLinks(files, links)
}

// maxLinkDepth bounds how many links one path may pass through, as the
// kernel's MAXSYMLINKS does; past it the chain is taken for a cycle.
const maxLinkDepth = 40

// resolveLinks replaces every symlink with a copy of what it points to,
// so the bundle carries no links: the same rule Pack applies on the client,
// applied again to what arrives. A link to a file becomes that file at the
// link's path; a link to a directory becomes every file under it, links
// inside resolved the same way. A link with nothing at its target, a chain
// that loops, and a directory link that reaches back up its own path are
// refused. Copies share the target's bytes; the total is re-checked against
// MaxUncompressed, because the archive the copies encode to does not share
// them, and the count against maxEntries, because empty files cost nothing
// in bytes.
func resolveLinks(files []File, links map[string]string) ([]File, error) {
	t := &linkTree{files: make(map[string]File, len(files)), links: links}
	for _, f := range files {
		t.files[f.Path] = f
		t.paths = append(t.paths, f.Path)
	}
	sort.Strings(t.paths)
	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	sort.Strings(names)
	t.names = names
	for _, name := range names {
		target, err := t.real(name, 0)
		if err != nil {
			return nil, err
		}
		if err := t.expand(name, target, map[string]bool{}, &files); err != nil {
			return nil, err
		}
	}
	seen := make(map[string]bool, len(files))
	var total int64
	for _, f := range files {
		if seen[f.Path] {
			return nil, fmt.Errorf("%w: %q appears twice", ErrBadPath, f.Path)
		}
		seen[f.Path] = true
		if total += int64(len(f.Data)); total > MaxUncompressed {
			return nil, ErrTooLarge
		}
	}
	return files, nil
}

// linkTree is the tar as read: regular files by path, and symlinks by
// path with the target as written. paths and names are the same keys
// sorted, so what sits under a directory is a range found by search rather
// than a scan of everything, once per link.
type linkTree struct {
	files map[string]File
	links map[string]string
	paths []string
	names []string
}

// under is the sorted keys that start with prefix.
func under(sorted []string, prefix string) []string {
	if prefix == "" {
		return sorted
	}
	i := sort.SearchStrings(sorted, prefix)
	j := i
	for j < len(sorted) && strings.HasPrefix(sorted[j], prefix) {
		j++
	}
	return sorted[i:j]
}

// real follows every link on p, component by component, and returns the
// path with none left on it.
func (t *linkTree) real(p string, depth int) (string, error) {
	if depth > maxLinkDepth {
		return "", fmt.Errorf("%w: symlink %q loops", ErrBadPath, p)
	}
	parts := strings.Split(p, "/")
	for i := range parts {
		cur := path.Join(parts[:i+1]...)
		target, ok := t.links[cur]
		if !ok {
			continue
		}
		// linkStaysInside held for every link when it was read, and a
		// cleaned join of inside paths stays inside.
		resolved := path.Join(path.Dir(cur), target)
		return t.real(path.Join(append([]string{resolved}, parts[i+1:]...)...), depth+1)
	}
	return p, nil
}

// expand appends what sits at src (a real path) to out under the name dst.
// active is every directory on the current expansion, so a link back into
// one is a cycle.
func (t *linkTree) expand(dst, src string, active map[string]bool, out *[]File) error {
	if len(*out) >= maxEntries {
		// Links to directories multiply what is under them; the count is
		// checked as it grows, since a copy shares its target's bytes and
		// costs only an entry.
		return fmt.Errorf("%w: more than %d after resolving symlinks", ErrTooManyEntries, maxEntries)
	}
	if f, ok := t.files[src]; ok {
		*out = append(*out, File{Path: dst, Mode: f.Mode, Data: f.Data})
		return nil
	}
	if active[src] {
		return fmt.Errorf("%w: symlink %q loops", ErrBadPath, dst)
	}
	active[src] = true
	defer delete(active, src)

	prefix := src + "/"
	if src == "." {
		prefix = ""
	}
	found := false
	for _, p := range under(t.paths, prefix) {
		if len(*out) >= maxEntries {
			return fmt.Errorf("%w: more than %d after resolving symlinks", ErrTooManyEntries, maxEntries)
		}
		f := t.files[p]
		*out = append(*out, File{Path: path.Join(dst, p[len(prefix):]), Mode: f.Mode, Data: f.Data})
		found = true
	}
	for _, l := range under(t.names, prefix) {
		found = true
		target, err := t.real(l, 0)
		if err != nil {
			return err
		}
		if err := t.expand(path.Join(dst, l[len(prefix):]), target, active, out); err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("%w: symlink %q points at nothing in the bundle", ErrBadPath, dst)
	}
	return nil
}

// cleanPath makes an entry name relative to the root and refuses anything
// that would not stay there. Reports false for absolute paths, `..`, and
// Windows drive letters.
func cleanPath(name string) (string, bool) {
	name = strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
		return "", false
	}
	cleaned := path.Clean(name)
	if cleaned == "." {
		return "", true
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

// isIgnored is what a working copy carries that a bundle never should: git
// metadata, and the .terraform directory, which holds a provider cache and
// a module cache that would both be stale the moment they were digested.
// At any depth, because vendored modules carry their own.
func isIgnored(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if part == ".git" || part == ".terraform" || part == ".terragrunt-cache" {
			return true
		}
	}
	return false
}

// linkStaysInside reports whether a symlink at name, following target,
// resolves to somewhere under the root.
func linkStaysInside(name, target string) bool {
	if strings.HasPrefix(target, "/") {
		return false
	}
	resolved := path.Join(path.Dir(name), target)
	return resolved != ".." && !strings.HasPrefix(resolved, "../")
}

// normalizeMode keeps exactly one bit: executable or not.
func normalizeMode(mode int64) int64 {
	if mode&0o111 != 0 {
		return 0o755
	}
	return 0o644
}
