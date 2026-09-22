# Admiral bundle

[![Go Reference](https://pkg.go.dev/badge/go.admiral.io/bundle.svg)](https://pkg.go.dev/go.admiral.io/bundle)

Package `bundle` turns a directory into the gzipped tar a component registry
stores, and reads one back. It is the packaging format behind
[Admiral](https://admiral.io)'s component registry: what
[`admiral component publish`](https://admiral.io/docs/reference/cli) uploads
and what the platform stores, inspects and deploys.

A *component* is a Terraform module, a Helm chart, or a set of raw Kubernetes
manifests. A *bundle* is that component packed as a tar, **closed** over
everything it reaches: every module call resolves to a directory inside the
tar, every chart dependency is under `charts/`, and nothing has to be fetched
to render or plan it. Publishing the same tree twice produces the same bytes,
so a repeat publish is a no-op.

```
go get go.admiral.io/bundle
```

## Building a bundle

`Pack` runs where the sources and credentials are: a developer's machine or
CI. It copies the component into a staging directory, closes it, and packs
the result. The working copy is never modified.

```go
packed, err := bundle.Pack("./infra/network")
if err != nil {
    return err
}
// packed.Kind     — bundle.KindTerraform, KindHelm or KindManifests
// packed.Bytes    — the gzipped tar, ready to upload
// packed.Vendored — every outside source that was brought into the tree
// packed.Pins     — every constraint that was resolved to an exact version
```

### Terraform

Every `module` call whose source is not already inside the root is brought
into `vendor/` and the call rewritten to point there, recursively, until
nothing points outside:

| Source as written                          | What happens                                                        |
| ------------------------------------------ | ------------------------------------------------------------------- |
| `../modules/net`                           | Copied to `vendor/modules/net`                                      |
| `GoogleCloudPlatform/cloud-armor/google`   | Resolved against the module registry, downloaded, pinned to a version |
| `git::ssh://git@github.com/org/repo//sub?ref=v1` | Cloned through a `GitTransport`, pinned to a commit           |
| `https://host/module.zip`                  | Downloaded, unpacked, pinned to a digest                            |

Rewrites are done with `hclwrite`, so comments, spacing and every other
attribute in the file stay byte-for-byte as they were. Two calls that resolve
to the same thing share one vendored copy.

Git sources are cloned in process with [go-git](https://github.com/go-git/go-git):
no `git` binary is required, and the behavior is the same on every platform
and in a server image that carries none.

```go
packed, err := bundle.PackContext(ctx, root, bundle.Options{
    Credentials: bundle.NewAmbientCredentials(),
    // A source naming the repository being published is read from its
    // object store rather than cloned: a root pinning its own sibling
    // modules at a SHA needs no credential at all.
    Git: &bundle.Git{Repo: bundle.OpenRepo(root)},
})
```

Without `Options.Git`, git sources still clone with `bundle.Git{}`: the
host's `~/.ssh/known_hosts` and ssh agent for ssh, and for https whatever the
`Credentials` lookup answers. `AmbientCredentials` reads `~/.netrc` and
`~/.git-credentials` for that; git's own credential helpers are the `git`
binary's and are not consulted. A server sets `HostKeyCallback` to the host
keys it trusts.

### Helm

The closure step for a chart is what `helm dependency build` does: every
dependency declared in `Chart.yaml` lands under `charts/` as a `.tgz`.
`Chart.lock` is required when there are dependencies, and each dependency is
pinned to the version the lock names. Dependencies are fetched from HTTP
repositories (index.yaml + digest check) and from OCI registries. Anything
already under `charts/` in the working copy is kept as-is.

`PullChart` fetches a chart straight from an OCI registry to publish it
without a local checkout:

```go
pulled, err := bundle.PullChart(ctx, "oci://ghcr.io/org/charts/app:1.4.0", creds)
if err != nil {
    return err
}
defer pulled.Cleanup()
packed, err := bundle.Pack(pulled.Dir)
```

### Credentials

Every remote fetch asks one `Credentials` lookup what it may present to a
URL. A credential is a bearer token, basic auth, or an SSH private key; each
fetch takes the family its protocol speaks and refuses the others by name.

`AmbientCredentials` reads what a machine already has: `TF_TOKEN_<host>`, the
`credentials` blocks of `~/.tofurc` / `~/.terraformrc`, the file `tofu login`
writes, and the username/password `helm repo add` stored. OCI pulls also
consult the Docker credential store, so `docker login`, `helm registry login`
and `gcloud auth configure-docker` all work. Implement the interface yourself
to answer from anywhere else:

```go
type Credentials interface {
    Lookup(ctx context.Context, rawURL string) (*Credential, error)
}
```

A nil credential is an anonymous fetch.

## Reading a bundle

The read side runs on what arrives at a registry, and trusts nothing.

```go
n, err := bundle.Normalize(upload)      // canonical bytes; equal trees digest equal
kind, err := bundle.Detect(n.Files)     // Terraform, Helm or manifests
report, err := bundle.Inspect(n.Files, kind)
closure, err := bundle.Close(n.Files)   // refuses the first call that is not inside
```

- **`Normalize`** strips `.git` and `.terraform`, sorts entries, zeroes
  ownership and timestamps, keeps only the execute bit, and writes a fixed
  gzip header, so the output is a function of the tree alone. Paths that
  escape the root and symlinks that resolve outside it are refused; a
  symlink that stays inside becomes a copy of its target, so the canonical
  form carries no links.
- **`Detect`** reads the kind from the root: `Chart.yaml` is a chart, any
  `.tf` file is a module, otherwise YAML documents are manifests.
- **`Inspect`** reports the component's contract (inputs and outputs) and
  findings from a static walk: missing or unbounded provider constraints,
  a missing `required_version`, images a chart references. Nothing is
  executed.
- **`Close`** walks module calls and certifies that every source is a relative
  path to a directory in the bundle. **`CloseChart`** does the same for a
  chart's dependencies.

## Safety

Bundles and the trees they are built from are read as hostile:

- Archives are capped in uncompressed size (`MaxUncompressed`) and entry
  count, as a decompression-bomb guard.
- `Untar` creates every entry through an `*os.Root`, so no path may traverse
  a symlink out of the destination.
- A symlink inside a copied tree is replaced by a copy of its target; a link
  that resolves outside the tree is refused. `Normalize` applies the same
  rule to what arrives, so `Close` and `Inspect` read the same tree whatever
  produced the archive.
- No fetch runs a binary. Keys and tokens are presented to go-git in memory
  and never appear on a command line, in a file, or in a URL.
- Sources and URLs are redacted wherever they are recorded or printed: the
  query string is dropped and a password in the userinfo is masked.

Three `Options` are for a server packing a tree it did not write:

- `Boundary`: a directory local sources, `file::` sources and `file://` chart
  dependencies may not resolve outside, links followed. The repository top
  is the natural value. Empty means the host, which is right on a
  developer's own machine.
- `AllowInsecureHTTP`: off, a credential rides https or the fetch is refused,
  and a redirect from https to http is refused either way.
- `Dial`: the dialer every connection uses, git over http(s) and ssh
  included. `DialPublic` refuses loopback, private, link-local and other
  non-public destinations at connect time, on the address actually being
  dialed, so an untrusted tree cannot point a fetch at a metadata service
  or an internal host, and a name that resolves differently for the check
  and the connection gains nothing. Under a dialer a `file://` repository
  is refused too, because nothing dials it. `Pull` never reads a directory
  off the machine it runs on.

`Git` never forwards the credential a clone was handed to that repository's
submodules; each is looked up by its own URL through `Git.Credentials`,
which `Options.git()` fills from `Options.Credentials`.

## Provenance

`Describe` reads git for a directory and returns the origin remote, HEAD, the
component's path within the repository, and whether the working copy is
dirty. A directory outside a repository, or a machine without git, yields an
empty `Provenance` and no error.

## Part of Admiral

This module is the open-source packaging layer of
[Admiral](https://admiral.io), a deployment platform for applications and the
infrastructure they run on. Where it fits:

- [Applications & Components](https://admiral.io/docs/concepts/applications-and-components)
  — what a component is and how it is owned per environment.
- [Sources & Catalog](https://admiral.io/docs/concepts/sources-and-catalog)
  — the git, Helm, OCI, HTTP and Terraform sources a bundle closes over.
- [CLI reference](https://admiral.io/docs/reference/cli) — the `admiral`
  command that builds and publishes bundles, from
  [admiral-io/admiral-cli](https://github.com/admiral-io/admiral-cli).
- [Documentation](https://admiral.io/docs) — everything else.

## Development

```
make test     # go test ./...
make lint     # golangci-lint
make verify   # fmt, lint and test
```

Requires Go 1.26 or later.

## License

[Apache 2.0](LICENSE)
