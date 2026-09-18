// Package bundle is what happens to a component's bytes between a directory
// on a developer's machine and a digest in the registry, with no database and
// no object store in sight. It is one module, go.admiral.io/bundle, imported
// by both halves of the publish path so that "closed" has exactly one
// definition: the CLI (local mode, the developer's ambient credentials) and
// admiral-platform (remote mode, credentials registered with Admiral).
//
// The client's half: Pack turns a directory into the gzipped tar `admiral
// component publish` uploads, vendoring every local module source that
// escapes the root into vendor/ and rewriting the call, recursively, until
// nothing points outside. Describe records where the tree came from.
//
// The server's half: Normalize reads a gzipped tar and produces the canonical
// form that is digested, `.git` and `.terraform` stripped, entries sorted,
// ownership and timestamps zeroed, so publishing the same tree twice yields
// the same digest. Inspect says what the tree is (Terraform, Helm, manifests),
// what it takes and gives, and what the publish gate should say about it.
// Close walks the module tree and refuses anything that is not inside the
// bundle, classifying sources by the rule OpenTofu itself applies. No binary
// is consulted anywhere in this package.
//
// Remote sources (registry addresses, git URLs, archives) are the next thing
// this module learns: a fetcher in front of Close on both halves, resolving
// each to an exact version, vendoring it, and recording the pin.
package bundle

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
	ErrNotTarGz  = errors.New("bundle is not a gzipped tar")
	ErrBadPath   = errors.New("bundle entry has an unsafe path")
	ErrTooLarge  = errors.New("bundle expands past the size limit")
	ErrEmpty     = errors.New("bundle contains no files")
	ErrEntryKind = errors.New("bundle entry is not a file, directory or symlink")
)

// File is one entry in a normalized bundle.
type File struct {
	// Path relative to the component root, forward slashes, no leading `./`.
	Path string
	// Mode is either 0644 or 0755 after normalization: the only bit that
	// survives is execute, because it is the only bit a tool reads.
	Mode int64
	// Link is the target for a symlink; empty otherwise.
	Link string
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
// Directories are implied by their files and not written: a tool that needs
// them recreates them, and writing them would make an empty directory change
// the digest of a bundle that ships no bytes differently.
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
			Name:    f.Path,
			Mode:    f.Mode,
			Size:    int64(len(f.Data)),
			ModTime: time.Time{},
			Format:  tar.FormatPAX,
		}
		if f.Link != "" {
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = f.Link
			hdr.Size = 0
		} else {
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if f.Link == "" {
			if _, err := tw.Write(f.Data); err != nil {
				return nil, err
			}
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

		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			total += hdr.Size
			if total > MaxUncompressed {
				return nil, ErrTooLarge
			}
			data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", name, err)
			}
			if int64(len(data)) != hdr.Size {
				return nil, fmt.Errorf("%w: %s is not the size its header claims", ErrNotTarGz, name)
			}
			if seen[name] {
				return nil, fmt.Errorf("%w: %q appears twice", ErrBadPath, name)
			}
			seen[name] = true
			files = append(files, File{Path: name, Mode: normalizeMode(hdr.Mode), Data: data})
		case tar.TypeSymlink:
			// A link is kept as a link; a link that escapes the root is the
			// classic archive attack and is refused.
			if !linkStaysInside(name, hdr.Linkname) {
				return nil, fmt.Errorf("%w: symlink %q escapes the bundle", ErrBadPath, name)
			}
			if seen[name] {
				return nil, fmt.Errorf("%w: %q appears twice", ErrBadPath, name)
			}
			seen[name] = true
			files = append(files, File{Path: name, Mode: 0o777, Link: hdr.Linkname})
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		default:
			return nil, fmt.Errorf("%w: %q", ErrEntryKind, name)
		}
	}
	return files, nil
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
