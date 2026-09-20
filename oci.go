package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

// OCI is the other place a chart lives: `oci://ghcr.io/org/charts/foo`
// at a tag that is the chart's version. Pulling one is a manifest and a
// single layer, the chart's own tgz, found by its media type. oras-go speaks
// the distribution protocol: the WWW-Authenticate bearer exchange, the token
// service, and docker's credential store with its helpers, which is where
// `docker login`, `helm registry login` and `gcloud auth configure-docker`
// all put what they know. The registry's credential seam is asked first; the
// docker store answers when it says nothing.

// helmChartLayer is the media type of a chart's content layer in an OCI
// manifest, per the Helm OCI spec.
const helmChartLayer = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

// ErrOCINotAChart is an OCI artifact whose manifest carries no chart layer.
var ErrOCINotAChart = errors.New("OCI artifact is not a Helm chart")

// ociClient pulls charts from OCI registries.
type ociClient struct {
	creds Credentials
	// docker is the machine's docker credential store, consulted after creds.
	docker credentials.Store
	cache  auth.Cache
	http   *http.Client
}

func newOCIClient(opts Options) *ociClient {
	c := &ociClient{creds: opts.Credentials, cache: auth.NewCache(), http: newHTTPClient(2*time.Minute, opts.Dial)}
	if store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{}); err == nil {
		c.docker = store
	}
	return c
}

// ociReference is `host/path` for an `oci://host/path` repository.
func ociReference(repository string) (string, error) {
	ref := strings.TrimSuffix(strings.TrimPrefix(repository, "oci://"), "/")
	if ref == "" || !strings.Contains(ref, "/") {
		return "", fmt.Errorf("%q is not an OCI repository (want oci://host/path)", repository)
	}
	return ref, nil
}

// repository opens host/path with the credential the seam gives for it, or
// what docker has for the host.
func (c *ociClient) repository(ref string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("oci://%s: %w", ref, err)
	}
	client := &auth.Client{
		Client:     c.http,
		Cache:      c.cache,
		Credential: c.credentialFor(ref),
	}
	client.SetUserAgent("admiral-cli")
	repo.Client = client
	if strings.HasPrefix(ref, "localhost:") || strings.HasPrefix(ref, "127.0.0.1:") {
		repo.PlainHTTP = true
	}
	return repo, nil
}

// credentialFor answers oras's credential callback: the seam by the
// repository's URL, then docker's store by host.
func (c *ociClient) credentialFor(ref string) auth.CredentialFunc {
	return func(ctx context.Context, host string) (auth.Credential, error) {
		if c.creds != nil {
			cred, err := c.creds.Lookup(ctx, "oci://"+ref)
			if err != nil {
				return auth.EmptyCredential, err
			}
			switch {
			case cred == nil:
			case cred.SSHKey != nil:
				return auth.EmptyCredential, fmt.Errorf("%w: %s to oci://%s", ErrCredentialFamily, cred.family(), host)
			case cred.Basic != nil:
				return auth.Credential{Username: cred.Basic.Username, Password: cred.Basic.Password}, nil
			case cred.Token != "":
				return auth.Credential{AccessToken: cred.Token}, nil
			}
		}
		if c.docker != nil {
			// docker's store keys Docker Hub by its legacy name.
			if host == "registry-1.docker.io" || host == "docker.io" {
				host = "https://index.docker.io/v1/"
			}
			return c.docker.Get(ctx, host)
		}
		return auth.EmptyCredential, nil
	}
}

// pullChart fetches the chart at oci://<repository>/<name>:<version> and
// returns its tgz and the manifest digest it was resolved to.
func (c *ociClient) pullChart(ctx context.Context, repository, name, version string) ([]byte, string, error) {
	base, err := ociReference(repository)
	if err != nil {
		return nil, "", err
	}
	ref := base + "/" + name
	repo, err := c.repository(ref)
	if err != nil {
		return nil, "", err
	}
	desc, manifest, err := repo.FetchReference(ctx, version)
	if err != nil {
		return nil, "", fmt.Errorf("oci://%s:%s: %w", ref, version, err)
	}
	defer manifest.Close()
	body, err := content.ReadAll(manifest, desc)
	if err != nil {
		return nil, "", fmt.Errorf("oci://%s:%s: manifest: %w", ref, version, err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, "", fmt.Errorf("oci://%s:%s: manifest: %w", ref, version, err)
	}
	var layer *ocispec.Descriptor
	for i := range m.Layers {
		if m.Layers[i].MediaType == helmChartLayer {
			layer = &m.Layers[i]
			break
		}
	}
	if layer == nil {
		return nil, "", fmt.Errorf("%w: oci://%s:%s has no %s layer", ErrOCINotAChart, ref, version, helmChartLayer)
	}
	if layer.Size > maxChartBytes {
		return nil, "", fmt.Errorf("oci://%s:%s: chart layer is %d bytes, over %d", ref, version, layer.Size, maxChartBytes)
	}
	// FetchAll verifies the layer's size and digest against the descriptor.
	data, err := content.FetchAll(ctx, repo.Blobs(), *layer)
	if err != nil {
		return nil, "", fmt.Errorf("oci://%s:%s: chart layer: %w", ref, version, err)
	}
	return data, desc.Digest.String(), nil
}

// Pulled is a chart brought down from an OCI registry to publish: the
// directory its tgz unpacked to, and what to say about where it came from.
type Pulled struct {
	// Dir is the artifact, ready to Pack.
	Dir string
	// Boundary is the fetched tree Dir sits in; Pack with Options.Boundary
	// set to it, so relative calls reach siblings and nothing else.
	Boundary string
	// Name is the artifact's own name: the chart's, the module's, the
	// repository's, the directory's.
	Name string
	// Version is the artifact's version when it has one: a chart's, a
	// module's as resolved. Empty for a git tree or an archive.
	Version string
	// Provenance says where it came from and what that resolved to.
	Provenance Provenance
	// Cleanup removes everything Pull made.
	Cleanup func()
}

// ParseOCIChartReference splits `oci://host/path/name:tag` into the
// repository (`oci://host/path`), the chart name and the tag. The tag is the
// chart's version, and it is required: a pull-publish names one thing.
func ParseOCIChartReference(reference string) (repository, name, tag string, err error) {
	if !strings.HasPrefix(reference, "oci://") {
		return "", "", "", fmt.Errorf("%q is not an OCI reference (want oci://host/path/name:version)", reference)
	}
	rest := strings.TrimPrefix(reference, "oci://")
	slash := strings.LastIndex(rest, "/")
	if slash < 0 {
		return "", "", "", fmt.Errorf("%q has no chart name (want oci://host/path/name:version)", reference)
	}
	name, tag, ok := strings.Cut(rest[slash+1:], ":")
	if !ok || name == "" || tag == "" {
		return "", "", "", fmt.Errorf("%q has no version (want oci://host/path/name:version)", reference)
	}
	return "oci://" + rest[:slash], name, tag, nil
}

// PullChart is Pull for an `oci://host/path/name:version` reference.
func PullChart(ctx context.Context, reference string, creds Credentials) (*Pulled, error) {
	repository, name, tag, err := ParseOCIChartReference(reference)
	if err != nil {
		return nil, err
	}
	return Pull(ctx, Source{OCIChart: &OCIChartSource{Reference: repository + "/" + name, Version: tag}}, Options{Credentials: creds})
}
