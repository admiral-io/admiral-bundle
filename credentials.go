package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// Credentials answers what a fetch may present to a URL. The platform
// registers credentials against a host or URL prefix and resolves them by
// longest prefix (design section 6); this is that lookup, so the fetcher is
// the same code whether the answers come from a developer's machine or from
// registered sources. A nil credential is an anonymous fetch.
type Credentials interface {
	Lookup(ctx context.Context, rawURL string) (*Credential, error)
}

// Credential is what a fetch presents, one of three protocol families (D33):
// a bearer token, basic auth, or an SSH private key. Exactly one is set. Each
// fetch site takes the family its protocol speaks and refuses another by
// name; a GitHub App is not a fourth family but a lookup that yields a Token.
type Credential struct {
	// Token goes in `Authorization: Bearer`: a module registry, an http
	// archive, an OCI registry token.
	Token string
	// Basic is a username and password: git over https (GitHub's
	// `x-access-token`), a Helm repository, an OCI login.
	Basic *BasicAuth
	// SSHKey is a private key for git over ssh.
	SSHKey *SSHKey
}

// BasicAuth is a username and password.
type BasicAuth struct {
	Username string
	Password string
}

// SSHKey is a PEM-encoded private key and its passphrase, if any.
type SSHKey struct {
	PEM        []byte
	Passphrase string
}

// ErrCredentialFamily is a credential of a family the protocol cannot present:
// an SSH key to a registry, a bearer token to git over ssh.
var ErrCredentialFamily = errors.New("credential is not of a kind this protocol can present")

// family names the one set field, for messages.
func (c *Credential) family() string {
	switch {
	case c == nil:
		return "none"
	case c.SSHKey != nil:
		return "ssh key"
	case c.Basic != nil:
		return "basic auth"
	default:
		return "bearer token"
	}
}

// authorize sets the request's Authorization header from a bearer token or
// basic auth; an SSH key has no HTTP form.
func (c *Credential) authorize(req *http.Request) error {
	switch {
	case c == nil:
		return nil
	case c.SSHKey != nil:
		return fmt.Errorf("%w: %s to %s", ErrCredentialFamily, c.family(), req.URL.Hostname())
	case c.Basic != nil:
		req.SetBasicAuth(c.Basic.Username, c.Basic.Password)
	case c.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return nil
}

// AmbientCredentials reads what tofu itself reads for a private module
// registry: `TF_TOKEN_<host>` in the environment, then the `credentials`
// blocks of the CLI configuration (TF_CLI_CONFIG_FILE, ~/.tofurc,
// ~/.terraformrc) and the file `tofu login` writes. Git and http archives are
// not answered here: git has its own agent, helper and insteadOf machinery,
// and an archive URL carries any auth it has.
type AmbientCredentials struct {
	environ []string
	home    string
}

// NewAmbientCredentials reads the process environment and home directory.
func NewAmbientCredentials() *AmbientCredentials {
	home, _ := os.UserHomeDir()
	return &AmbientCredentials{environ: os.Environ(), home: home}
}

// Lookup returns what the machine has for the URL: a registry token for its
// host, or the basic auth `helm repo add --username` stored for a chart
// repository whose URL is a prefix of it. Nil otherwise.
func (a *AmbientCredentials) Lookup(_ context.Context, rawURL string) (*Credential, error) {
	host := hostOf(rawURL)
	if host == "" {
		return nil, nil
	}
	if tok := a.fromEnv(host); tok != "" {
		return &Credential{Token: tok}, nil
	}
	tok, err := a.fromConfig(host)
	if err != nil {
		return nil, err
	}
	if tok != "" {
		return &Credential{Token: tok}, nil
	}
	return a.fromHelmRepositories(rawURL)
}

// fromHelmRepositories reads Helm's repositories.yaml (HELM_REPOSITORY_CONFIG,
// else Helm's per-OS config directory) for a repository whose URL is the
// longest prefix of rawURL and carries a username.
func (a *AmbientCredentials) fromHelmRepositories(rawURL string) (*Credential, error) {
	p := a.envValue("HELM_REPOSITORY_CONFIG")
	if p == "" {
		if a.home == "" {
			return nil, nil
		}
		p = filepath.Join(helmConfigDir(a.home, a.envValue("XDG_CONFIG_HOME")), "repositories.yaml")
	}
	src, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f struct {
		Repositories []struct {
			URL      string `yaml:"url"`
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		} `yaml:"repositories"`
	}
	if err := yaml.Unmarshal(src, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	var best *Credential
	bestLen := 0
	for _, r := range f.Repositories {
		u := strings.TrimSuffix(r.URL, "/")
		if r.Username == "" || u == "" {
			continue
		}
		if (rawURL == u || strings.HasPrefix(rawURL, u+"/")) && len(u) > bestLen {
			best, bestLen = &Credential{Basic: &BasicAuth{Username: r.Username, Password: r.Password}}, len(u)
		}
	}
	return best, nil
}

// helmConfigDir is where Helm keeps repositories.yaml: XDG on Linux,
// ~/Library/Preferences on macOS, as Helm's own helmpath does.
func helmConfigDir(home, xdg string) string {
	if xdg != "" {
		return filepath.Join(xdg, "helm")
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Preferences", "helm")
	}
	return filepath.Join(home, ".config", "helm")
}

// fromEnv finds TF_TOKEN_<host>, with `.` as `_` and `-` as `__`, matched
// case-insensitively the way tofu matches it.
func (a *AmbientCredentials) fromEnv(host string) string {
	want := "TF_TOKEN_" + strings.NewReplacer("-", "__", ".", "_").Replace(host)
	for _, kv := range a.environ {
		name, value, ok := strings.Cut(kv, "=")
		if ok && strings.EqualFold(name, want) && value != "" {
			return value
		}
	}
	return ""
}

// fromConfig reads the first CLI configuration that exists, then the
// credentials file `tofu login` maintains.
func (a *AmbientCredentials) fromConfig(host string) (string, error) {
	var candidates []string
	if p := a.envValue("TF_CLI_CONFIG_FILE"); p != "" {
		candidates = append(candidates, p)
	} else if a.home != "" {
		candidates = append(candidates, filepath.Join(a.home, ".tofurc"), filepath.Join(a.home, ".terraformrc"))
	}
	for _, p := range candidates {
		src, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		tok, err := credentialsFromHCL(src, p, host)
		if err != nil {
			return "", err
		}
		if tok != "" {
			return tok, nil
		}
		break // tofu reads one configuration file, the first that exists
	}
	if a.home == "" {
		return "", nil
	}
	for _, dir := range []string{".terraform.d", ".tofu.d"} {
		p := filepath.Join(a.home, dir, "credentials.tfrc.json")
		src, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		var f struct {
			Credentials map[string]struct {
				Token string `json:"token"`
			} `json:"credentials"`
		}
		if err := json.Unmarshal(src, &f); err != nil {
			return "", fmt.Errorf("%s: %w", p, err)
		}
		for h, c := range f.Credentials {
			if strings.EqualFold(h, host) && c.Token != "" {
				return c.Token, nil
			}
		}
	}
	return "", nil
}

func (a *AmbientCredentials) envValue(name string) string {
	for _, kv := range a.environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

// credentialsFromHCL reads `credentials "host" { token = "..." }` blocks.
func credentialsFromHCL(src []byte, filename, host string) (string, error) {
	f, diags := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return "", fmt.Errorf("%s: %s", filename, diags.Error())
	}
	content, _, diags := f.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: "credentials", LabelNames: []string{"host"}}},
	})
	if diags.HasErrors() {
		return "", fmt.Errorf("%s: %s", filename, diags.Error())
	}
	for _, b := range content.Blocks {
		if !strings.EqualFold(b.Labels[0], host) {
			continue
		}
		attrs, diags := b.Body.JustAttributes()
		if diags.HasErrors() {
			return "", fmt.Errorf("%s: %s", filename, diags.Error())
		}
		tok, ok := attrs["token"]
		if !ok {
			continue
		}
		v, diags := tok.Expr.Value(nil)
		if diags.HasErrors() || v.IsNull() || v.Type() != cty.String {
			continue
		}
		if s := v.AsString(); s != "" {
			return s, nil
		}
	}
	return "", nil
}

// hostOf is the host part of a URL, or the string itself when it is a bare
// hostname.
func hostOf(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		return strings.ToLower(strings.TrimSuffix(rawURL, "/"))
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
