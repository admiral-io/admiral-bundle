package bundle

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing/fstest"

	"github.com/hashicorp/terraform-config-inspect/tfconfig"
	"gopkg.in/yaml.v3"
)

// Kind is what a bundle is.
type Kind string

const (
	KindTerraform Kind = "TERRAFORM"
	KindHelm      Kind = "HELM"
	KindManifests Kind = "MANIFESTS"
)

// ErrUnknownKind is a tree with no Chart.yaml, no .tf and no YAML at the root.
var ErrUnknownKind = errors.New("cannot tell what kind of component this is: no Chart.yaml, .tf or YAML files at the root")

// Severity ranks a finding.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Finding is one thing the publish gate noticed and a registry may record
// alongside the revision. A finding never refuses a publish on its own;
// anything that must refuse comes back as Inspect's error.
type Finding struct {
	Severity Severity `json:"severity"`
	Source   string   `json:"source"`
	Code     string   `json:"code,omitempty"`
	Message  string   `json:"message"`
	Path     string   `json:"path,omitempty"`
}

// Contract is what the bundle takes and gives, as far as static inspection
// can tell.
type Contract struct {
	Inputs  []Input  `json:"inputs"`
	Outputs []Output `json:"outputs"`
}

// Input is one value the bundle accepts.
type Input struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     any    `json:"default,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
	Ephemeral   bool   `json:"ephemeral,omitempty"`
}

// Output is one value the bundle produces.
type Output struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

// Report is what Inspect learned.
type Report struct {
	// Kind is what the bundle is, detected or as passed in.
	Kind Kind
	// Contract is the inputs and outputs static inspection found.
	Contract Contract
	// Findings is what the publish gate has to say, in the order noticed.
	Findings []Finding
}

// Detect says what a tree is from what sits at its root: a Chart.yaml is a
// Helm chart, any .tf file is a Terraform module, otherwise YAML documents
// are raw manifests. Checked in that order, since a chart's templates are
// YAML and a module may carry a values file for its own reasons.
func Detect(files []File) (Kind, error) {
	var tf, yamls bool
	for _, f := range files {
		if strings.Contains(f.Path, "/") {
			continue
		}
		switch {
		case f.Path == "Chart.yaml":
			return KindHelm, nil
		case strings.HasSuffix(f.Path, ".tf") || strings.HasSuffix(f.Path, ".tf.json"):
			tf = true
		case strings.HasSuffix(f.Path, ".yaml") || strings.HasSuffix(f.Path, ".yml"):
			yamls = true
		}
	}
	switch {
	case tf:
		return KindTerraform, nil
	case yamls:
		return KindManifests, nil
	default:
		return "", ErrUnknownKind
	}
}

// Inspect reads a normalized tree and reports its kind, its contract and
// what the publish gate has to say. When kind is empty it is detected; a
// caller that knows better passes it.
func Inspect(files []File, kind Kind) (*Report, error) {
	if kind == "" {
		detected, err := Detect(files)
		if err != nil {
			return nil, err
		}
		kind = detected
	}
	switch kind {
	case KindTerraform:
		return inspectTerraform(files)
	case KindHelm:
		return inspectHelm(files)
	case KindManifests:
		return &Report{Kind: KindManifests, Findings: []Finding{}}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
}

// --- Terraform -------------------------------------------------------------

// inspectTerraform runs the static walk with terraform-config-inspect over
// an in-memory view of the tree. Nothing is written to disk and nothing is
// executed; the hermetic proof is a later step and a different tool.
func inspectTerraform(files []File) (*Report, error) {
	mod, diags := tfconfig.LoadModuleFromFilesystem(tfconfig.WrapFS(mapFS(files)), ".")
	report := &Report{Kind: KindTerraform, Findings: []Finding{}}

	for _, d := range diags {
		if d.Severity == tfconfig.DiagError {
			return nil, fmt.Errorf("terraform: %s: %s", d.Summary, d.Detail)
		}
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityLow, Source: "terraform-config-inspect",
			Message: strings.TrimSpace(d.Summary + ". " + d.Detail), Path: diagPath(d),
		})
	}

	for _, name := range sortedKeys(mod.Variables) {
		v := mod.Variables[name]
		in := Input{
			Name: v.Name, Type: v.Type, Description: v.Description,
			Required: v.Required, Sensitive: v.Sensitive,
		}
		if !v.Required {
			in.Default = v.Default
		}
		report.Contract.Inputs = append(report.Contract.Inputs, in)
	}
	for _, name := range sortedKeys(mod.Outputs) {
		o := mod.Outputs[name]
		report.Contract.Outputs = append(report.Contract.Outputs,
			Output{Name: o.Name, Description: o.Description, Sensitive: o.Sensitive})
	}

	// Providers are the runner's concern, but a constraint that is missing
	// or unbounded is worth a word at publish, because it is the difference
	// between a plan that is reproducible next month and one that is not.
	// terraform-config-inspect lists implied providers here too, with no
	// source: a resource or provider block whose provider was never declared
	// resolves to hashicorp/<name> on the runner, which is silently wrong for
	// anything else, and gets its own code.
	for _, name := range sortedKeys(mod.RequiredProviders) {
		req := mod.RequiredProviders[name]
		switch {
		case req.Source == "" && len(req.VersionConstraints) == 0:
			report.Findings = append(report.Findings, Finding{
				Severity: SeverityInfo, Source: "provider-constraint", Code: "undeclared",
				Message: fmt.Sprintf("provider %q is used but not declared in required_providers; it will resolve as hashicorp/%s with no version constraint", name, name),
			})
		case len(req.VersionConstraints) == 0:
			report.Findings = append(report.Findings, Finding{
				Severity: SeverityInfo, Source: "provider-constraint", Code: "missing",
				Message: fmt.Sprintf("provider %q declares no version constraint; every plan resolves whatever is newest", name),
			})
		case !bounded(req.VersionConstraints):
			report.Findings = append(report.Findings, Finding{
				Severity: SeverityInfo, Source: "provider-constraint", Code: "unbounded",
				Message: fmt.Sprintf("provider %q constraint %q has no upper bound", name, strings.Join(req.VersionConstraints, ", ")),
			})
		}
	}

	// required_version is the one fact about the runtime a bundle states
	// about itself, and a registry is where a consumer reads it before
	// choosing a runtime that cannot run it. Recorded when present; its
	// absence gets the same nudge a missing provider constraint does.
	if len(mod.RequiredCore) > 0 {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityInfo, Source: "core-constraint", Code: "required",
			Message: fmt.Sprintf("module requires OpenTofu %s", strings.Join(mod.RequiredCore, ", ")),
		})
	} else {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityInfo, Source: "core-constraint", Code: "missing",
			Message: "module declares no required_version; it runs on whatever the runner ships",
		})
	}

	// A source that is not a literal is refused, because a closed bundle has
	// no value-dependent graph by definition. terraform-config-inspect hands
	// back the raw expression for a non-literal source.
	for _, name := range sortedKeys(mod.ModuleCalls) {
		call := mod.ModuleCalls[name]
		if isExpression(call.Source) {
			return nil, fmt.Errorf("terraform: module %q has a non-literal source %q; a published bundle must name its sources as strings", name, call.Source)
		}
	}
	return report, nil
}

// mapFS builds an in-memory filesystem the walk can read.
func mapFS(files []File) fstest.MapFS {
	m := make(fstest.MapFS, len(files))
	for _, f := range files {
		m[f.Path] = &fstest.MapFile{Data: f.Data, Mode: fs.FileMode(f.Mode)}
	}
	return m
}

// bounded reports whether a constraint set has an upper bound: a pessimistic
// operator, a `<`, or an exact pin.
func bounded(constraints []string) bool {
	for _, c := range constraints {
		for _, part := range strings.Split(c, ",") {
			part = strings.TrimSpace(part)
			switch {
			case strings.HasPrefix(part, "~>"), strings.HasPrefix(part, "<"), strings.HasPrefix(part, "="):
				return true
			case part != "" && !strings.HasPrefix(part, ">") && !strings.HasPrefix(part, "!"):
				return true // bare version: an exact pin
			}
		}
	}
	return false
}

// isExpression reports whether a source string the walker returned is an
// unevaluated reference rather than an address.
func isExpression(source string) bool {
	return strings.HasPrefix(source, "var.") || strings.HasPrefix(source, "local.") || strings.Contains(source, "${")
}

func diagPath(d tfconfig.Diagnostic) string {
	if d.Pos == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", d.Pos.Filename, d.Pos.Line)
}

// --- Helm ------------------------------------------------------------------

// inspectHelm reads Chart.yaml and infers inputs from the top level of
// values.yaml. A chart has no declared outputs. Rendering (helm template) is
// the closure step's job and is not done here.
func inspectHelm(files []File) (*Report, error) {
	report := &Report{Kind: KindHelm, Findings: []Finding{}}
	var chart struct {
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		APIVersion string `yaml:"apiVersion"`
	}
	if data, ok := lookup(files, "Chart.yaml"); ok {
		if err := yaml.Unmarshal(data, &chart); err != nil {
			return nil, fmt.Errorf("helm: Chart.yaml: %w", err)
		}
	}
	if chart.Name == "" {
		return nil, errors.New("helm: Chart.yaml has no name")
	}

	if data, ok := lookup(files, "values.yaml"); ok {
		var values map[string]any
		if err := yaml.Unmarshal(data, &values); err != nil {
			return nil, fmt.Errorf("helm: values.yaml: %w", err)
		}
		for _, key := range sortedKeys(values) {
			report.Contract.Inputs = append(report.Contract.Inputs, Input{
				Name: key, Type: yamlType(values[key]), Default: values[key],
			})
		}
	}

	// The images a chart declares are worth recording, and cost a grep
	// during inspection. Findings, not contract.
	for _, f := range files {
		if !strings.HasPrefix(f.Path, "templates/") {
			continue
		}
		for _, line := range strings.Split(string(f.Data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "image:") && !strings.Contains(trimmed, "{{") {
				report.Findings = append(report.Findings, Finding{
					Severity: SeverityInfo, Source: "image-ref",
					Message: strings.TrimSpace(strings.TrimPrefix(trimmed, "image:")), Path: f.Path,
				})
			}
		}
	}
	return report, nil
}

func lookup(files []File, name string) ([]byte, bool) {
	for _, f := range files {
		if f.Path == name {
			return f.Data, true
		}
	}
	return nil, false
}

func yamlType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case int, int64, float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "list"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
