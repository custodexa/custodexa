// Package guard holds safety checks shared by the development smoke tools in
// scripts/. Those tools send a Bearer JWT to whatever base URL the operator
// passes in, so an http:// or ws:// target outside the local machine would put
// the token on the wire in clear text.
package guard

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrPlainTextTransport is returned when a plain-text scheme is combined with a
// non-loopback host.
var ErrPlainTextTransport = errors.New("plain-text transport is only allowed to loopback; use https/wss or a loopback address")

// CheckPlainText rejects a base URL that would carry credentials in clear text
// to a host other than the local machine. http and ws are allowed only when the
// host is loopback (localhost, 127.0.0.0/8, ::1); https and wss are always
// allowed. Schemes other than these four are rejected as unusable.
func CheckPlainText(base string) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid base url %q: %w", base, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		return nil
	case "http", "ws":
		if isLoopbackHost(u.Host) {
			return nil
		}
		return fmt.Errorf("%w (got %s)", ErrPlainTextTransport, base)
	default:
		return fmt.Errorf("unsupported base url scheme %q; use http, https, ws or wss", u.Scheme)
	}
}

// isLoopbackHost reports whether the host part of a URL points at the local
// machine. A hostname only counts when it is literally "localhost" (or a
// subdomain of it); any other name may resolve anywhere, so it is not trusted.
func isLoopbackHost(host string) bool {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	hostname = strings.Trim(hostname, "[]")
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))

	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return true
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
