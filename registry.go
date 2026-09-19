package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	tfaddr "github.com/hashicorp/terraform-registry-address"
)

// The module registry protocol, the three requests of it a publish needs:
// service discovery (`/.well-known/terraform.json` names where modules.v1
// lives), the version list, and the download endpoint, which does not serve
// bytes but says where they are: a go-getter address in the `X-Terraform-Get`
// header (registry.terraform.io) or in a JSON body (registry.opentofu.org).
// The bytes themselves come through the fetcher like any other remote
// source. Speaking the protocol directly is a few dozen lines; the
// alternative, tofu's own registry client, is internal to tofu.

// DefaultRegistryHost answers an address written without a host, the way the
// runtime (OpenTofu, D17) would answer it.
const DefaultRegistryHost = "registry.opentofu.org"

var (
	// ErrRegistryNoVersion is a constraint no published version satisfies.
	ErrRegistryNoVersion = errors.New("no version of the module satisfies the constraint")
	// ErrRegistryNotFound is a module the registry does not have.
	ErrRegistryNotFound = errors.New("module not found in the registry")
)

// registryClient speaks the module registry protocol to any host.
type registryClient struct {
	client *http.Client
	creds  Credentials
	// services caches discovery per host: the absolute base URL of modules.v1.
	services map[string]*url.URL
	// versions caches the version list per package.
	versions map[string][]*version.Version
}

func newRegistryClient(creds Credentials) *registryClient {
	return &registryClient{
		client:   &http.Client{Timeout: time.Minute},
		creds:    creds,
		services: map[string]*url.URL{},
		versions: map[string][]*version.Version{},
	}
}

// registryHost is the host a parsed address resolves against: what it says,
// or the default when it says nothing.
func registryHost(pkg tfaddr.ModulePackage) string {
	if pkg.Host == tfaddr.DefaultModuleRegistryHost {
		return DefaultRegistryHost
	}
	return pkg.Host.String()
}

// registryAddress is the host-qualified address recorded in a pin.
func registryAddress(pkg tfaddr.ModulePackage) string {
	return registryHost(pkg) + "/" + pkg.ForRegistryProtocol()
}

// Versions lists what the registry has for the package, newest first.
func (r *registryClient) Versions(ctx context.Context, pkg tfaddr.ModulePackage) ([]*version.Version, error) {
	addr := registryAddress(pkg)
	if vs, ok := r.versions[addr]; ok {
		return vs, nil
	}
	base, err := r.modulesBase(ctx, registryHost(pkg))
	if err != nil {
		return nil, err
	}
	u := base.JoinPath(pkg.ForRegistryProtocol(), "versions")
	resp, err := r.get(ctx, registryHost(pkg), u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrRegistryNotFound, addr)
	default:
		return nil, registryError(addr, resp)
	}
	var body struct {
		Modules []struct {
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"modules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("%s: versions: %w", addr, err)
	}
	var vs []*version.Version
	for _, m := range body.Modules {
		for _, v := range m.Versions {
			parsed, err := version.NewVersion(v.Version)
			if err != nil {
				continue // a registry may list what tofu could not parse either
			}
			vs = append(vs, parsed)
		}
	}
	sort.Sort(sort.Reverse(version.Collection(vs)))
	r.versions[addr] = vs
	return vs, nil
}

// Location asks where one version's bytes are: a go-getter address.
func (r *registryClient) Location(ctx context.Context, pkg tfaddr.ModulePackage, v *version.Version) (string, error) {
	addr := registryAddress(pkg)
	base, err := r.modulesBase(ctx, registryHost(pkg))
	if err != nil {
		return "", err
	}
	u := base.JoinPath(pkg.ForRegistryProtocol(), v.Original(), "download")
	resp, err := r.get(ctx, registryHost(pkg), u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var location string
	switch resp.StatusCode {
	case http.StatusNoContent:
		location = resp.Header.Get("X-Terraform-Get")
	case http.StatusOK:
		var body struct {
			Location string `json:"location"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
			return "", fmt.Errorf("%s %s: download: %w", addr, v, err)
		}
		location = body.Location
	case http.StatusNotFound:
		return "", fmt.Errorf("%w: %s %s", ErrRegistryNotFound, addr, v)
	default:
		return "", registryError(addr, resp)
	}
	if location == "" {
		return "", fmt.Errorf("%s %s: the registry did not say where the bytes are", addr, v)
	}
	// A relative location is relative to the download URL, as tofu reads it.
	if strings.HasPrefix(location, "/") || strings.HasPrefix(location, "./") || strings.HasPrefix(location, "../") {
		rel, err := url.Parse(location)
		if err != nil {
			return "", fmt.Errorf("%s %s: download location %q: %w", addr, v, location, err)
		}
		location = u.ResolveReference(rel).String()
	}
	return location, nil
}

// modulesBase discovers, once per host, where the modules service lives.
func (r *registryClient) modulesBase(ctx context.Context, host string) (*url.URL, error) {
	if base, ok := r.services[host]; ok {
		return base, nil
	}
	disco := &url.URL{Scheme: "https", Host: host, Path: "/.well-known/terraform.json"}
	resp, err := r.get(ctx, host, disco)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, registryError(host, resp)
	}
	var services map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&services); err != nil {
		return nil, fmt.Errorf("%s: service discovery: %w", host, err)
	}
	raw, _ := services["modules.v1"].(string)
	if raw == "" {
		return nil, fmt.Errorf("%s does not host a module registry (no modules.v1 in service discovery)", host)
	}
	rel, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: service discovery: modules.v1 %q: %w", host, raw, err)
	}
	base := disco.ResolveReference(rel)
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	r.services[host] = base
	return base, nil
}

// get fetches u on behalf of a registry host. The credential is the host's,
// the one the address named, as tofu resolves it, not the service URL's.
func (r *registryClient) get(ctx context.Context, host string, u *url.URL) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "admiral-cli")
	if r.creds != nil {
		cred, err := r.creds.Lookup(ctx, "https://"+host+"/")
		if err != nil {
			return nil, err
		}
		if err := cred.authorize(req); err != nil {
			return nil, err
		}
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry %s: %w", u.Host, err)
	}
	return resp, nil
}

func registryError(what string, resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s: registry refused the request (%s); a private registry needs a token, TF_TOKEN_<host> or a credentials block in ~/.tofurc", what, resp.Status)
	}
	return fmt.Errorf("%s: registry answered %s", what, resp.Status)
}

// selectVersion picks the newest version satisfying the constraint, the way
// tofu's installer does: a prerelease is chosen only when the constraint
// names one, and no constraint means the newest release.
func selectVersion(versions []*version.Version, constraint string) (*version.Version, error) {
	var check func(*version.Version) bool
	if strings.TrimSpace(constraint) == "" {
		check = func(v *version.Version) bool { return v.Prerelease() == "" }
	} else {
		c, err := version.NewConstraint(constraint)
		if err != nil {
			return nil, fmt.Errorf("version constraint %q: %w", constraint, err)
		}
		check = c.Check
	}
	for _, v := range versions { // newest first
		if check(v) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("%w: %q over %d published versions", ErrRegistryNoVersion, constraint, len(versions))
}
