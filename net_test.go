package bundle

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirectDowngradeIsRefused(t *testing.T) {
	client := newHTTPClient(0, nil)
	https, _ := url.Parse("https://example.test/a")
	http1, _ := url.Parse("http://example.test/b")
	https2, _ := url.Parse("https://other.test/c")
	via := []*http.Request{{URL: https}}
	assert.ErrorIs(t, client.CheckRedirect(&http.Request{URL: http1}, via), ErrRedirectDowngrade)
	assert.NoError(t, client.CheckRedirect(&http.Request{URL: https2}, via), "https to https, another host, is fine")
	assert.NoError(t, client.CheckRedirect(&http.Request{URL: http1}, []*http.Request{{URL: http1}}), "http to http never had anything to lose")
}

func TestDialPublic(t *testing.T) {
	for ip, public := range map[string]bool{
		"127.0.0.1":       false,
		"10.1.2.3":        false,
		"172.16.0.1":      false,
		"192.168.1.1":     false,
		"169.254.169.254": false,
		"100.64.0.1":      false,
		"0.0.0.0":         false,
		"::1":             false,
		"fe80::1":         false,
		"fd00::1":         false,
		"8.8.8.8":         true,
		"2606:4700::1111": true,
		// IPv4 embedded in IPv6: mapped, NAT64, 6to4.
		"::ffff:169.254.169.254": false,
		"64:ff9b::7f00:1":        false,
		"64:ff9b::a9fe:a9fe":     false,
		"64:ff9b::808:808":       true,
		"2002:7f00:1::":          false,
		"2002:808:808::":         true,
	} {
		assert.Equal(t, public, isPublic(net.ParseIP(ip)), ip)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)
	client := newHTTPClient(0, DialPublic)
	_, err := client.Get(srv.URL)
	assert.ErrorIs(t, err, ErrPrivateAddress, "loopback is not public, name or not")

	// The same dialer reaches every fetch: registry, archive, chart, OCI.
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "a" { source = "`+srv.URL+`/net.tgz" }`), 0o644))
	_, err = PackContext(context.Background(), root, Options{Dial: DialPublic})
	assert.ErrorIs(t, err, ErrPrivateAddress)
	dir := wrapperChart(t, srv.URL, "dependencies:\n- name: openfga\n  repository: "+srv.URL+"\n  version: 0.3.9\n")
	_, err = PackContext(context.Background(), dir, Options{Dial: DialPublic})
	assert.ErrorIs(t, err, ErrPrivateAddress)
}

func TestDialerReplacesTheProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.example.test:3128")
	tr, ok := newHTTPClient(0, DialPublic).Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.Proxy, "the dialer is the egress policy")
	tr, ok = newHTTPClient(0, nil).Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotNil(t, tr.Proxy, "without one, the environment's proxy applies")
}

func TestRedactSource(t *testing.T) {
	for in, want := range map[string]string{
		"../modules/net":                                               "../modules/net",
		"GoogleCloudPlatform/cloud-armor/google":                       "GoogleCloudPlatform/cloud-armor/google",
		"git::ssh://git@github.com/acme/x.git//sub?ref=v1&sshkey=AAAA": "git::ssh://git@github.com/acme/x.git//sub",
		"https://user:secret@host/x.zip?X-Amz-Signature=abc":           "https://user:xxxxx@host/x.zip",
		"http::https://host/x.zip?archive=tgz":                         "http::https://host/x.zip",
		"github.com/acme/x//sub":                                       "github.com/acme/x//sub",
	} {
		assert.Equal(t, want, redactSource(in), in)
	}
	u, _ := url.Parse("https://u:p@host/x?sig=1")
	assert.Equal(t, "https://u:xxxxx@host/x", redactURL(u))
}
