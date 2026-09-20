// Package bundle is the component bundle: how a directory becomes the
// gzipped tar a registry stores, and how a registry reads one back. It is
// the packaging format of Admiral's component registry; see
// https://admiral.io/docs for the platform it serves.
//
// The build side runs where the sources and the credentials are: Pack
// closes a component over everything it reaches and packs it; Pull brings
// down an artifact that is somebody else's to pack the same way. What each
// resolution came to is a Pin, and what a fetch may present comes through
// the Credentials seam.
//
// The read side runs in the registry on what arrives: Normalize
// canonicalizes the tar so equal trees digest equal, Detect and Inspect
// read the kind and the contract, and Close refuses anything not closed.
//
// Git is go-git in process, so no binary is required on either side.
package bundle
