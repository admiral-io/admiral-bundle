package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// What every HTTP client in the package shares: the dialer a caller may
// replace, a redirect policy that never lets a credential follow a downgrade
// to cleartext, and the rule that a credential rides https or nothing.

var (
	// ErrInsecureHTTP is a credential that would have been presented over
	// cleartext http. Options.AllowInsecureHTTP permits it.
	ErrInsecureHTTP = errors.New("credential refused over cleartext http")
	// ErrRedirectDowngrade is a redirect from https to http, which is
	// refused whether or not a credential was in flight.
	ErrRedirectDowngrade = errors.New("redirect from https to http refused")
	// ErrPrivateAddress is a connection DialPublic refused: a loopback,
	// private, link-local or otherwise non-public destination.
	ErrPrivateAddress = errors.New("connection to a non-public address refused")
)

// Dialer is what Options.Dial takes: net.Dialer.DialContext's shape.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// newHTTPClient makes a client with the package's redirect policy and the
// caller's dialer, if any.
func newHTTPClient(timeout time.Duration, dial Dialer) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if dial != nil {
		// The dialer is the egress policy. A proxy from the environment
		// would be dialed in its place, so the destination it reaches would
		// never be checked; a caller that wants a proxy dials through it.
		transport.Proxy = nil
		transport.DialContext = dial
	} else {
		transport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("%w: %s -> %s", ErrRedirectDowngrade, via[0].URL.Redacted(), req.URL.Redacted())
			}
			return nil
		},
	}
}

// DialPublic is a Dialer that connects only to public addresses. The check
// runs after name resolution, on the address about to be dialed, so a name
// that resolves to the metadata service or a cluster-internal address is
// refused the same as the literal. A server that fetches what someone
// else's tree names sets Options.Dial to this.
func DialPublic(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !isPublic(ip) {
				return fmt.Errorf("%w: %s", ErrPrivateAddress, address)
			}
			return nil
		},
	}
	return d.DialContext(ctx, network, addr)
}

// isPublic is the complement of every range a fetch from inside a network
// must not reach: loopback, RFC 1918, link-local (169.254.0.0/16, which
// cloud metadata services answer on), unique-local, multicast, unspecified,
// the shared address space 100.64.0.0/10, and an IPv6 address that embeds
// one of those as IPv4 (mapped, NAT64, 6to4).
func isPublic(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := embeddedIPv4(ip); v4 != nil && !isPublic(v4) {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10
			return false
		}
		if v4[0] == 0 || v4[0] >= 240 { // 0.0.0.0/8, 240.0.0.0/4 and broadcast
			return false
		}
	}
	return true
}

// embeddedIPv4 is the IPv4 address an IPv6 address carries: the NAT64
// well-known prefix 64:ff9b::/96 in its last four bytes, 6to4 2002::/16 in
// bytes two to five. Nil for anything else; the mapped form ::ffff:a.b.c.d
// is what To4 already reads.
func embeddedIPv4(ip net.IP) net.IP {
	if ip.To4() != nil || len(ip) != net.IPv6len {
		return nil
	}
	switch {
	case bytes.HasPrefix(ip, []byte{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}):
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	case ip[0] == 0x20 && ip[1] == 0x02:
		return net.IPv4(ip[2], ip[3], ip[4], ip[5])
	}
	return nil
}

// redactSource is a source safe to record and print: the query, which may
// carry a pre-signed URL's signature or go-getter's sshkey, is dropped, and
// a password in the URL's userinfo is masked. The forced getter, the path
// and a `//subdir` stay, because that is what the author wrote and what a
// pin needs to be read back.
func redactSource(source string) string {
	forced, rest := forcedGetter(source)
	rest, _, _ = strings.Cut(rest, "?")
	if u, err := url.Parse(rest); err == nil && u.User != nil {
		if _, has := u.User.Password(); has {
			rest = u.Redacted()
		}
	}
	if forced != "" {
		return forced + "::" + rest
	}
	return rest
}

// redactURL is redactSource for a parsed URL.
func redactURL(u *url.URL) string {
	c := *u
	c.RawQuery = ""
	c.ForceQuery = false
	return c.Redacted()
}

// userAgent is what every fetch identifies itself as.
const userAgent = "go.admiral.io/bundle"
