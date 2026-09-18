package bundle

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-config-inspect/tfconfig"
	"gopkg.in/yaml.v3"
)

// The closure walk: is every module this bundle calls inside the bundle?
//
// Section 7 of the design. In local mode the CLI vendors local escapes and
// remote sources on the developer's machine, where the filesystem and the
// credentials are, and uploads a closed tree. The server cannot vendor what
// it cannot reach, so its half of the job is to refuse, precisely, anything
// that is not closed: a source that escapes the root, a remote address, a
// local directory that is not there.
//
// No binary is consulted. The walk reads module blocks through
// terraform-config-inspect and classifies sources by the rule OpenTofu's own
// addrs.ParseModuleSource applies: a source is local if and only if it begins
// with `./` or `../`, and everything else is a registry or go-getter address
// the runner would have to fetch. Two prefixes are not worth a dependency on
// go-getter, and never worth a subprocess: `tofu get` was tried as a second
// opinion and enforces required_version, which refused a module pinned above
// the server's binary for the wrong reason.
//
// Remote-mode publishing, where the server fetches and vendors against
// registered credentials, adds a fetcher in front of this walk. It does not
// change what closed means.

var (
	// ErrSourceEscapes is a local source that resolves outside the bundle:
	// `../modules/net` from the root. The CLI vendors these before upload.
	ErrSourceEscapes = errors.New("module source escapes the bundle")
	// ErrSourceRemote is a source the runner would have to fetch: a registry
	// address, a git URL, an archive. It must be vendored into the bundle.
	ErrSourceRemote = errors.New("module source is not vendored into the bundle")
	// ErrSourceMissing is a local source whose directory is not in the bundle.
	ErrSourceMissing = errors.New("module source directory is not in the bundle")
	// ErrChartDependencyMissing is a Chart.yaml dependency with nothing under
	// charts/ to satisfy it: `helm dependency build` was not run.
	ErrChartDependencyMissing = errors.New("chart dependency is not vendored under charts/")
)

// Call is one module call the walk found, for provenance and for the CLI's
// benefit when it reports what it vendored.
type Call struct {
	// Caller is the directory of the module making the call; "." is the root.
	Caller string
	Name   string
	Source string
	// Dir is the bundle directory the source resolved to.
	Dir string
}

// Closure is what the walk established: every module directory reachable
// from the root, and every call between them.
type Closure struct {
	Modules []string
	Calls   []Call
}

// Close walks module calls from the root and refuses the first one that is
// not inside the bundle. A closed tree is one where every source is a
// relative path to a directory that is here.
func Close(files []File) (*Closure, error) {
	fsys := mapFS(files)
	dirs := dirSet(files)

	out := &Closure{}
	seen := map[string]bool{}
	queue := []string{"."}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		out.Modules = append(out.Modules, dir)

		mod, diags := tfconfig.LoadModuleFromFilesystem(tfconfig.WrapFS(fsys), dir)
		for _, d := range diags {
			if d.Severity == tfconfig.DiagError {
				return nil, fmt.Errorf("terraform: %s: %s: %s", dir, d.Summary, d.Detail)
			}
		}
		for _, name := range sortedKeys(mod.ModuleCalls) {
			call := mod.ModuleCalls[name]
			target, err := resolveSource(dir, call.Source, dirs)
			if err != nil {
				return nil, fmt.Errorf("%w: module %q in %s has source %q", err, name, displayDir(dir), call.Source)
			}
			out.Calls = append(out.Calls, Call{Caller: dir, Name: name, Source: call.Source, Dir: target})
			queue = append(queue, target)
		}
	}
	sort.Strings(out.Modules)
	return out, nil
}

// resolveSource classifies a source the way OpenTofu does: only `./` and
// `../` are local paths; everything else is an address the runner would
// fetch. A local path must stay inside the bundle and must exist.
func resolveSource(caller, source string, dirs map[string]bool) (string, error) {
	if !isLocalSource(source) {
		return "", ErrSourceRemote
	}
	target := path.Join(caller, source)
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", ErrSourceEscapes
	}
	if !dirs[target] {
		return "", ErrSourceMissing
	}
	return target, nil
}

func isLocalSource(source string) bool {
	return source == "." || source == ".." ||
		strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")
}

// dirSet is every directory the tree implies, root included.
func dirSet(files []File) map[string]bool {
	dirs := map[string]bool{".": true}
	for _, f := range files {
		for d := path.Dir(f.Path); d != "." && d != "/"; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	return dirs
}

func displayDir(dir string) string {
	if dir == "." {
		return "the root module"
	}
	return dir
}

// CloseChart checks a Helm chart's declared dependencies are vendored. The
// closure step for a chart is `helm dependency build`, which fills charts/;
// a chart that skipped it would fetch at render time, which is what a closed
// bundle exists to prevent.
func CloseChart(files []File) error {
	data, ok := lookup(files, "Chart.yaml")
	if !ok {
		return errors.New("helm: Chart.yaml is missing")
	}
	var chart struct {
		Dependencies []struct {
			Name       string `yaml:"name"`
			Version    string `yaml:"version"`
			Repository string `yaml:"repository"`
		} `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(data, &chart); err != nil {
		return fmt.Errorf("helm: Chart.yaml: %w", err)
	}
	present := map[string]bool{}
	for _, f := range files {
		if !strings.HasPrefix(f.Path, "charts/") {
			continue
		}
		rest := strings.TrimPrefix(f.Path, "charts/")
		// charts/<name>-<version>.tgz, or an unpacked charts/<name>/Chart.yaml.
		if strings.HasSuffix(rest, ".tgz") && !strings.Contains(rest, "/") {
			present[strings.TrimSuffix(rest, ".tgz")] = true
		} else if strings.HasSuffix(rest, "/Chart.yaml") && strings.Count(rest, "/") == 1 {
			present[strings.TrimSuffix(rest, "/Chart.yaml")] = true
		}
	}
	for _, dep := range chart.Dependencies {
		if present[dep.Name] || present[dep.Name+"-"+dep.Version] {
			continue
		}
		return fmt.Errorf("%w: %s %s from %s; run `helm dependency build` before publishing", ErrChartDependencyMissing, dep.Name, dep.Version, dep.Repository)
	}
	return nil
}
