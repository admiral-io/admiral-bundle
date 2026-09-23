package bundle

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// Validation is one validation block on a Terraform variable. Both halves are
// kept as written: evaluating a condition needs the language's functions and
// a value, and inspection has neither.
type Validation struct {
	Condition    string `json:"condition"`
	ErrorMessage string `json:"error_message"`
}

// variableFacts is what a variable block says that terraform-config-inspect
// does not report: whether it accepts null, whether it is ephemeral, and its
// validation blocks.
type variableFacts struct {
	nullable    bool
	ephemeral   bool
	validations []Validation
}

var (
	variableBlocks = &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: "variable", LabelNames: []string{"name"}}},
	}
	variableBody = &hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "nullable"}, {Name: "ephemeral"}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "validation"}},
	}
	validationBody = &hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "condition"}, {Name: "error_message"}},
	}
)

// readVariableFacts parses the root module's .tf and .tf.json files a second
// time, for the variable attributes the static walk leaves out. It reports
// nothing it cannot read: a file that does not parse was already reported by
// the walk, and an attribute that is not a literal is left at its default.
func readVariableFacts(files []File) map[string]variableFacts {
	parser := hclparse.NewParser()
	facts := map[string]variableFacts{}
	for _, f := range files {
		if strings.Contains(f.Path, "/") {
			continue
		}
		var file *hcl.File
		switch {
		case strings.HasSuffix(f.Path, ".tf"):
			file, _ = parser.ParseHCL(f.Data, f.Path)
		case strings.HasSuffix(f.Path, ".tf.json"):
			file, _ = parser.ParseJSON(f.Data, f.Path)
		}
		if file == nil {
			continue
		}
		content, _, _ := file.Body.PartialContent(variableBlocks)
		if content == nil {
			continue
		}
		for _, block := range content.Blocks {
			facts[block.Labels[0]] = readVariable(block.Body, f.Data)
		}
	}
	return facts
}

func readVariable(body hcl.Body, src []byte) variableFacts {
	// Terraform's defaults: a variable accepts null unless it says otherwise,
	// and is not ephemeral unless it says so.
	v := variableFacts{nullable: true}
	content, _, _ := body.PartialContent(variableBody)
	if content == nil {
		return v
	}
	if b, ok := literalBool(content.Attributes["nullable"]); ok {
		v.nullable = b
	}
	if b, ok := literalBool(content.Attributes["ephemeral"]); ok {
		v.ephemeral = b
	}
	for _, block := range content.Blocks {
		vc, _, _ := block.Body.PartialContent(validationBody)
		if vc == nil {
			continue
		}
		v.validations = append(v.validations, Validation{
			Condition:    sourceOf(vc.Attributes["condition"], src),
			ErrorMessage: stringOrSource(vc.Attributes["error_message"], src),
		})
	}
	return v
}

func literalBool(attr *hcl.Attribute) (bool, bool) {
	if attr == nil {
		return false, false
	}
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || val.IsNull() || !val.IsKnown() || val.Type() != cty.Bool {
		return false, false
	}
	return val.True(), true
}

// stringOrSource is an error message as its reader will see it when it is a
// plain string, and as written when it interpolates.
func stringOrSource(attr *hcl.Attribute, src []byte) string {
	if attr == nil {
		return ""
	}
	if val, diags := attr.Expr.Value(nil); !diags.HasErrors() && val.IsKnown() && !val.IsNull() && val.Type() == cty.String {
		return val.AsString()
	}
	return sourceOf(attr, src)
}

func sourceOf(attr *hcl.Attribute, src []byte) string {
	if attr == nil {
		return ""
	}
	r := attr.Expr.Range()
	if r.Start.Byte < 0 || r.End.Byte > len(src) || r.Start.Byte > r.End.Byte {
		return ""
	}
	return string(src[r.Start.Byte:r.End.Byte])
}
