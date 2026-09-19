package bundle_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"

	"go.admiral.io/bundle"
	"go.admiral.io/bundle/gitcmd"
)

// Pack a component anonymously, with no git transport: local escapes and
// registry addresses are vendored, a git source is refused.
func ExamplePack() {
	packed, err := bundle.Pack("./infra/network")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(packed.Kind, packed.Files, "files")
	for _, v := range packed.Vendored {
		fmt.Printf("%s: %s -> %s\n", v.Caller, v.Source, v.Into)
	}
	for _, p := range packed.Pins {
		fmt.Printf("%s %s => %s\n", p.Source, p.Constraint, p.Resolved)
	}
}

// Pack with the machine's credentials and its git binary, so private
// registries, private chart repositories and git sources all resolve the way
// they would for the developer running it.
func ExamplePackContext() {
	ctx := context.Background()
	root := "./infra/network"

	packed, err := bundle.PackContext(ctx, root, bundle.Options{
		Credentials: bundle.NewAmbientCredentials(),
		Git: &gitcmd.Transport{
			// A source that names the repository being published is read
			// from its object store rather than cloned.
			Repo: gitcmd.DescribeRepo(ctx, root),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("network.tgz", packed.Bytes, 0o644); err != nil {
		log.Fatal(err)
	}
}

// The read side, as a registry runs it on an upload: canonicalize, detect,
// inspect, and refuse anything that is not closed.
func ExampleNormalize() {
	upload, err := os.ReadFile("network.tgz")
	if err != nil {
		log.Fatal(err)
	}

	n, err := bundle.Normalize(bytes.NewReader(upload))
	if err != nil {
		log.Fatal(err)
	}
	kind, err := bundle.Detect(n.Files)
	if err != nil {
		log.Fatal(err)
	}
	report, err := bundle.Inspect(n.Files, kind)
	if err != nil {
		log.Fatal(err)
	}
	switch kind {
	case bundle.KindTerraform:
		if _, err := bundle.Close(n.Files); err != nil {
			log.Fatal(err)
		}
	case bundle.KindHelm:
		if err := bundle.CloseChart(n.Files); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println(kind, len(report.Contract.Inputs), "inputs")
	for _, f := range report.Findings {
		fmt.Println(f.Severity, f.Code, f.Message)
	}
}
