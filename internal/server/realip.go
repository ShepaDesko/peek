package server

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxies decides whose forwarding headers Peek believes.
//
// This is the single most load-bearing piece of the exposure story: rate
// limits, CIDR gates and the audit trail are all written against the client IP
// it returns. An attacker who could spoof it would bypass all three, so a
// header is only read when the immediate peer is inside a declared CIDR.
type TrustedProxies struct {
	nets []*net.IPNet
}

// NewTrustedProxies parses a list of IPs and CIDRs. Bare IPs become /32 or /128.
func NewTrustedProxies(entries []string) (*TrustedProxies, error) {
	tp := &TrustedProxies{}
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(raw); err == nil {
			tp.nets = append(tp.nets, n)
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, &net.ParseError{Type: "IP or CIDR", Text: raw}
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		tp.nets = append(tp.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return tp, nil
}

// Empty reports whether no proxy is trusted at all.
func (tp *TrustedProxies) Empty() bool { return tp == nil || len(tp.nets) == 0 }

// Contains reports whether ip is a trusted proxy.
func (tp *TrustedProxies) Contains(ip net.IP) bool {
	if tp == nil || ip == nil {
		return false
	}
	for _, n := range tp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the real client IP for a request.
//
// The peer address always wins unless the peer is a trusted proxy. For a
// trusted peer, the rightmost untrusted address of the forwarding chain is
// used: the hops a trusted proxy appended are trustworthy, anything the client
// itself put in front of them is not.
func (tp *TrustedProxies) ClientIP(r *http.Request) string {
	peer := peerIP(r)
	if peer == nil {
		return ""
	}
	if !tp.Contains(peer) {
		// Not behind a declared proxy: forwarding headers are ignored on purpose.
		return peer.String()
	}
	chain := tp.forwardedChain(r)
	for i := len(chain) - 1; i >= 0; i-- {
		ip := net.ParseIP(chain[i])
		if ip == nil {
			continue
		}
		if tp.Contains(ip) {
			continue
		}
		return ip.String()
	}
	return peer.String()
}

// forwardedChain collects the forwarded-for chain, preferring RFC 7239.
func (tp *TrustedProxies) forwardedChain(r *http.Request) []string {
	if fwd := r.Header.Get("Forwarded"); fwd != "" {
		var out []string
		for _, element := range strings.Split(fwd, ",") {
			for _, pair := range strings.Split(element, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(k), "for") {
					continue
				}
				out = append(out, normalizeForwardedFor(v))
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	var out []string
	for _, header := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(header, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, hostOnly(p))
			}
		}
	}
	return out
}

// Scheme returns the scheme the client used, honouring X-Forwarded-Proto only
// from a trusted proxy.
func (tp *TrustedProxies) Scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if tp.Contains(peerIP(r)) {
		if proto := firstToken(r.Header.Get("X-Forwarded-Proto")); proto != "" {
			return strings.ToLower(proto)
		}
		if fwd := r.Header.Get("Forwarded"); fwd != "" {
			for _, pair := range strings.Split(strings.Split(fwd, ",")[0], ";") {
				if k, v, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && strings.EqualFold(k, "proto") {
					return strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
				}
			}
		}
	}
	return "http"
}

// ForwardedHost returns the host the client asked for, honouring
// X-Forwarded-Host only from a trusted proxy. Used to resolve the brand by
// domain in multi-org mode.
func (tp *TrustedProxies) ForwardedHost(r *http.Request) string {
	if tp.Contains(peerIP(r)) {
		if h := firstToken(r.Header.Get("X-Forwarded-Host")); h != "" {
			return h
		}
	}
	return r.Host
}

func peerIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	// A PROXY protocol listener rewrites RemoteAddr before the handler runs,
	// so this covers that case too.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func hostOnly(s string) string {
	s = strings.Trim(strings.TrimSpace(s), `"`)
	if host, _, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(s, "[]")
}

func normalizeForwardedFor(v string) string {
	v = strings.Trim(strings.TrimSpace(v), `"`)
	if strings.EqualFold(v, "unknown") {
		return ""
	}
	return hostOnly(v)
}

func firstToken(v string) string {
	if v == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(v, ",")[0])
}
