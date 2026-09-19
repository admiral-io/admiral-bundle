package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// The closure step for a chart is what `helm dependency build` does: put
// every declared dependency under charts/, so the bundle renders without
// fetching. This speaks the Helm repository protocol itself rather than
// linking the Helm SDK, which would cost the binary thirty megabytes and
// fourteen Kubernetes modules for one HTTP GET and a checksum: read the
// repository's index.yaml, take the entry at the version Chart.lock pinned,
// download it, verify the index's digest, write charts/<name>-<version>.tgz.
//
// Chart.lock is required when there are dependencies. Without it a version
// range could resolve differently tomorrow, and the point of a published
// revision is that it cannot. What got resolved is recorded as a pin.
//
// An oci:// dependency is pulled through oci.go. A private repository gets
// its credential from the same lookup every fetch uses; the ambient
// lookup reads what `helm repo add --username` stored. Not here: repository
// aliases (@name, which need a repositories.yaml; say the URL).

var (
	// ErrChartLockMissing is a chart with dependencies and no Chart.lock.
	ErrChartLockMissing = errors.New("the chart has dependencies but no Chart.lock; run `helm dependency update` and commit the lock")
	// ErrChartLockStale is a Chart.lock that does not match Chart.yaml.
	ErrChartLockStale = errors.New("the Chart.lock does not match Chart.yaml; run `helm dependency update`")
	// ErrChartDependencyUnsupported is a dependency repository this cannot fetch.
	ErrChartDependencyUnsupported = errors.New("chart dependency repository is not supported yet")
)

// Pin is one dependency the packer resolved: what was asked for and what it
// became. A registry records it alongside the revision.
type Pin struct {
	// Source is the dependency as declared: a chart's repository and name,
	// a module's registry address, git URL or archive URL.
	Source string
	// Constraint is what was asked for: a chart's version range from
	// Chart.yaml, a module's version constraint, a git ref, an archive
	// checksum. Empty when nothing was asked.
	Constraint string
	// Resolved is what it became: the exact chart or module version, the
	// commit, or the archive's `sha256:` digest.
	Resolved string
}

type chartDependency struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Repository string `yaml:"repository"`
	Alias      string `yaml:"alias"`
}

type chartMetadata struct {
	Version      string            `yaml:"version"`
	Dependencies []chartDependency `yaml:"dependencies"`
}

type chartLock struct {
	Dependencies []chartDependency `yaml:"dependencies"`
}

// repoIndex is the part of a Helm repository's index.yaml this reads.
type repoIndex struct {
	Entries map[string][]repoEntry `yaml:"entries"`
}

type repoEntry struct {
	Version string   `yaml:"version"`
	URLs    []string `yaml:"urls"`
	Digest  string   `yaml:"digest"`
}

// helmFetcher is the network the closure step is allowed: HTTP GET against a
// chart repository, and an OCI pull.
type helmFetcher struct {
	client   *http.Client
	creds    Credentials
	oci      *ociClient
	insecure bool
	boundary string
}

func newHelmFetcher(opts Options) *helmFetcher {
	return &helmFetcher{
		client:   newHTTPClient(2*time.Minute, opts.Dial),
		creds:    opts.Credentials,
		oci:      newOCIClient(opts),
		insecure: opts.AllowInsecureHTTP,
		boundary: opts.Boundary,
	}
}

// closeHelm vendors the chart's dependencies into stage/charts and returns
// what it pinned. A dependency already under charts/ in the working copy
// (someone ran `helm dependency build`) is kept as it is. A dependency that
// arrives as a directory, copied from a `file://` path or already unpacked
// under charts/, is closed in turn, because its own Chart.yaml may declare
// dependencies too; a packaged .tgz carries its own inside.
func closeHelm(ctx context.Context, rootAbs, stage string, f *helmFetcher) (vendored []Vendored, pins []Pin, version string, err error) {
	meta, err := readChartMetadata(rootAbs)
	if err != nil {
		return nil, nil, "", err
	}
	vendored, pins, err = closeChart(ctx, rootAbs, stage, ".", f, 0)
	return vendored, pins, meta.Version, err
}

// maxChartDepth bounds the nesting of directory dependencies. Helm itself
// stops nowhere; a wrapper of a wrapper of a wrapper is already unusual.
const maxChartDepth = 10

// closeChart closes one chart: the one at srcDir on disk, staged at
// stageDir, known in the bundle as caller.
func closeChart(ctx context.Context, srcDir, stageDir, caller string, f *helmFetcher, depth int) (vendored []Vendored, pins []Pin, err error) {
	if depth > maxChartDepth {
		return nil, nil, fmt.Errorf("%s: chart dependencies nest deeper than %d", caller, maxChartDepth)
	}
	meta, err := readChartMetadata(srcDir)
	if err != nil {
		return nil, nil, err
	}
	if len(meta.Dependencies) == 0 {
		return nil, nil, nil
	}
	lock, err := readChartLock(srcDir)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", caller, err)
	}
	if err := lockMatches(meta, lock); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", caller, err)
	}

	chartsDir := filepath.Join(stageDir, "charts")
	for _, locked := range lock.Dependencies {
		declared := findDependency(meta.Dependencies, locked)
		pin := Pin{
			Source:     dependencySource(locked),
			Constraint: declared.Version,
			Resolved:   locked.Version,
		}
		into, depSrc, err := vendorChartDependency(ctx, srcDir, chartsDir, locked, f)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: dependency %q: %w", caller, locked.Name, err)
		}
		pins = append(pins, pin)
		if into != "" {
			vendored = append(vendored, Vendored{Caller: caller, Source: pin.Source + " " + locked.Version, Into: path.Join(caller, into)})
		}
		// A directory dependency is a chart with dependencies of its own.
		if depSrc != "" {
			sub := path.Join("charts", locked.Name)
			v, p, err := closeChart(ctx, depSrc, filepath.Join(chartsDir, locked.Name), path.Join(caller, sub), f, depth+1)
			if err != nil {
				return nil, nil, err
			}
			vendored = append(vendored, v...)
			pins = append(pins, p...)
		}
	}
	return vendored, pins, nil
}

// vendorChartDependency puts one dependency under chartsDir and returns the
// path it landed at relative to the chart, or "" when it was already there,
// and, when the dependency is a directory rather than a .tgz, where that
// directory is on disk, so the caller can close it in turn.
func vendorChartDependency(ctx context.Context, chartDir, chartsDir string, dep chartDependency, f *helmFetcher) (into, dir string, err error) {
	tgz := fmt.Sprintf("%s-%s.tgz", dep.Name, dep.Version)
	if _, err := os.Stat(filepath.Join(chartsDir, tgz)); err == nil {
		return "", "", nil
	}
	if _, err := os.Stat(filepath.Join(chartsDir, dep.Name, "Chart.yaml")); err == nil {
		// Unpacked under charts/ by the author; the staged copy is what is
		// closed, and it came from the same place in the working copy.
		return "", filepath.Join(chartDir, "charts", dep.Name), nil
	}

	switch {
	case dep.Repository == "":
		// No repository means "already under charts/", and it is not.
		return "", "", fmt.Errorf("%w: %s is declared without a repository and is not under charts/", ErrChartDependencyMissingLocal, dep.Name)
	case strings.HasPrefix(dep.Repository, "file://"):
		src := filepath.Join(chartDir, filepath.FromSlash(strings.TrimPrefix(dep.Repository, "file://")))
		if info, err := os.Stat(src); err != nil || !info.IsDir() {
			return "", "", fmt.Errorf("%w: %s does not exist", ErrSourceDirMissing, dep.Repository)
		}
		if err := withinBoundary(f.boundary, src); err != nil {
			return "", "", fmt.Errorf("%s: %w", dep.Repository, err)
		}
		if err := copyTree(src, filepath.Join(chartsDir, dep.Name), src, true); err != nil {
			return "", "", err
		}
		return path.Join("charts", dep.Name), src, nil
	case strings.HasPrefix(dep.Repository, "oci://"):
		data, _, err := f.oci.pullChart(ctx, dep.Repository, dep.Name, dep.Version)
		if err != nil {
			return "", "", err
		}
		if err := os.MkdirAll(chartsDir, 0o755); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(filepath.Join(chartsDir, tgz), data, 0o644); err != nil {
			return "", "", err
		}
		return path.Join("charts", tgz), "", nil
	case strings.HasPrefix(dep.Repository, "@") || strings.HasPrefix(dep.Repository, "alias:"):
		return "", "", fmt.Errorf("%w: %s is a repository alias; declare the repository's URL", ErrChartDependencyUnsupported, dep.Repository)
	case strings.HasPrefix(dep.Repository, "http://") || strings.HasPrefix(dep.Repository, "https://"):
		data, err := f.fetchChart(ctx, dep)
		if err != nil {
			return "", "", err
		}
		if err := os.MkdirAll(chartsDir, 0o755); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(filepath.Join(chartsDir, tgz), data, 0o644); err != nil {
			return "", "", err
		}
		return path.Join("charts", tgz), "", nil
	default:
		return "", "", fmt.Errorf("%w: %s", ErrChartDependencyUnsupported, redactSource(dep.Repository))
	}
}

// ErrChartDependencyMissingLocal is a dependency with no repository that is
// not under charts/ either.
var ErrChartDependencyMissingLocal = errors.New("chart dependency is not under charts/")

// fetchChart resolves a dependency through its repository's index and
// downloads the archive the index names, verifying the index's digest.
func (f *helmFetcher) fetchChart(ctx context.Context, dep chartDependency) ([]byte, error) {
	repoURL := strings.TrimSuffix(dep.Repository, "/")
	index, err := f.fetchIndex(ctx, repoURL)
	if err != nil {
		return nil, err
	}
	entry, ok := findEntry(index, dep.Name, dep.Version)
	if !ok {
		return nil, fmt.Errorf("%s %s is not in the index at %s", dep.Name, dep.Version, redactSource(repoURL))
	}
	if len(entry.URLs) == 0 {
		return nil, fmt.Errorf("the index at %s has no download URL for %s %s", redactSource(repoURL), dep.Name, dep.Version)
	}
	chartURL, err := resolveChartURL(repoURL, entry.URLs[0])
	if err != nil {
		return nil, err
	}
	data, err := f.get(ctx, chartURL)
	if err != nil {
		return nil, err
	}
	if entry.Digest != "" {
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != strings.TrimPrefix(entry.Digest, "sha256:") {
			return nil, fmt.Errorf("%s from %s does not match the index's digest (%s, got sha256:%s)", dep.Name, redactSource(chartURL), entry.Digest, got)
		}
	}
	return data, nil
}

func (f *helmFetcher) fetchIndex(ctx context.Context, repoURL string) (*repoIndex, error) {
	data, err := f.get(ctx, repoURL+"/index.yaml")
	if err != nil {
		return nil, err
	}
	var index repoIndex
	if err := yaml.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("%s/index.yaml: %w", redactSource(repoURL), err)
	}
	return &index, nil
}

// maxChartBytes bounds one download; the registry caps a whole bundle at 64
// MiB, so a single subchart past this is wrong before it is uploaded.
const maxChartBytes = 64 << 20

func (f *helmFetcher) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "admiral-cli")
	if f.creds != nil {
		cred, err := f.creds.Lookup(ctx, rawURL)
		if err != nil {
			return nil, err
		}
		if err := cred.authorize(req, f.insecure); err != nil {
			return nil, err
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	shown := redactSource(rawURL)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", shown, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxChartBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", shown, err)
	}
	if len(data) > maxChartBytes {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", shown, maxChartBytes)
	}
	return data, nil
}

// resolveChartURL is the index's rule: an absolute URL is used as given, a
// relative one is relative to the repository.
func resolveChartURL(repoURL, ref string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("index URL %q: %w", ref, err)
	}
	if u.IsAbs() {
		return ref, nil
	}
	base, err := url.Parse(repoURL + "/")
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}

func findEntry(index *repoIndex, name, version string) (repoEntry, bool) {
	for _, e := range index.Entries[name] {
		if e.Version == version {
			return e, true
		}
	}
	return repoEntry{}, false
}

func readChartMetadata(rootAbs string) (*chartMetadata, error) {
	data, err := os.ReadFile(filepath.Join(rootAbs, "Chart.yaml"))
	if err != nil {
		return nil, err
	}
	var meta chartMetadata
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("reading Chart.yaml: %w", err)
	}
	return &meta, nil
}

func readChartLock(rootAbs string) (*chartLock, error) {
	data, err := os.ReadFile(filepath.Join(rootAbs, "Chart.lock"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrChartLockMissing
	}
	if err != nil {
		return nil, err
	}
	var lock chartLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("reading Chart.lock: %w", err)
	}
	return &lock, nil
}

// lockMatches checks the lock names exactly the dependencies Chart.yaml
// declares, by name and repository. Helm hashes the declaration into the
// lock's digest; comparing the two lists says the same thing in plain terms.
func lockMatches(meta *chartMetadata, lock *chartLock) error {
	if len(meta.Dependencies) != len(lock.Dependencies) {
		return fmt.Errorf("%w: Chart.yaml declares %d dependencies, Chart.lock has %d", ErrChartLockStale, len(meta.Dependencies), len(lock.Dependencies))
	}
	for _, locked := range lock.Dependencies {
		if findDependency(meta.Dependencies, locked) == nil {
			return fmt.Errorf("%w: %s from %s is in Chart.lock but not in Chart.yaml", ErrChartLockStale, locked.Name, locked.Repository)
		}
	}
	return nil
}

func findDependency(declared []chartDependency, locked chartDependency) *chartDependency {
	for i := range declared {
		d := &declared[i]
		if d.Name == locked.Name && strings.TrimSuffix(d.Repository, "/") == strings.TrimSuffix(locked.Repository, "/") {
			return d
		}
	}
	return nil
}

// dependencySource names a dependency the way it was declared: its
// repository and chart, `https://openfga.github.io/helm-charts/openfga`.
func dependencySource(dep chartDependency) string {
	if dep.Repository == "" {
		return dep.Name
	}
	return redactSource(strings.TrimSuffix(dep.Repository, "/")) + "/" + dep.Name
}
