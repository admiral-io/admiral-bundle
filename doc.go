// Package bundle is the component bundle: how a directory becomes the
// gzipped tar a registry stores, and how a registry reads one back.
//
// The build side, run where the sources and the credentials are (a
// developer's machine, CI, or the platform in remote mode): Pack stages a
// component, closes it over everything it reaches, and packs it. A
// Terraform module's calls are brought into vendor/ and rewritten, local
// escapes copied, registry addresses resolved against the registry, git
// URLs cloned through a GitTransport, archives downloaded; a chart's
// dependencies land under charts/ from HTTP repositories and OCI registries.
// Each resolution is a Pin. Credentials come through one prefix-keyed
// Lookup; AmbientCredentials reads what a machine already has.
//
// The read side, run by the registry on what arrives: Normalize
// canonicalizes the tar so equal trees digest equal, Detect and Inspect
// read the kind and the contract, and Close certifies that every module
// call resolves inside the bundle, refusing anything still open.
//
// One git transport differs by host and lives in a subpackage: gitcmd runs
// the developer's git binary, gitgo clones in-process for a server image
// that has none.
package bundle
