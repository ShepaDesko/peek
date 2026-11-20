package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// PROXY protocol support, for load balancers that forward TCP rather than
// HTTP (Kemp layer 4 virtual services, HAProxy in tcp mode, AWS NLB).
//
// Only connections coming from a trusted proxy are parsed: an untrusted peer
// sending a PROXY header would otherwise hand itself any source address.

var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const proxyHeaderTimeout = 5 * time.Second

// proxyListener wraps a listener and rewrites the remote address of accepted
// connections according to the PROXY header.
type proxyListener struct {
	net.Listener
	trusted *TrustedProxies
}

// newProxyListener enables PROXY protocol parsing on l.
func newProxyListener(l net.Listener, trusted *TrustedProxies) net.Listener {
	return &proxyListener{Listener: l, trusted: trusted}
}

func (l *proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	peer, _ := c.RemoteAddr().(*net.TCPAddr)
	if peer == nil || !l.trusted.Contains(peer.IP) {
		// Untrusted peer: do not even look for a PROXY header.
		return c, nil
	}

	_ = c.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
	br := bufio.NewReader(c)
	src, err := parseProxyHeader(br)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("proxy protocol: %w", err)
	}
	wrapped := &bufferedConn{Conn: c, reader: br}
	if src == nil {
		return wrapped, nil
	}
	return &rewrittenConn{Conn: wrapped, remote: src}, nil
}

// parseProxyHeader consumes a v1 or v2 header if present and returns the
// client address it announces. A nil address means "no header, local proxy
// health check or UNKNOWN transport": keep the real peer address.
func parseProxyHeader(br *bufio.Reader) (net.Addr, error) {
	prefix, err := br.Peek(12)
	if err != nil {
		if errors.Is(err, io.EOF) && len(prefix) == 0 {
			return nil, nil
		}
		if len(prefix) < 12 {
			// Too short to be either form; treat it as a plain connection.
			return nil, nil
		}
		return nil, err
	}
	switch {
	case bytes.Equal(prefix, proxyV2Signature):
		return parseProxyV2(br)
	case bytes.HasPrefix(prefix, []byte("PROXY ")):
		return parseProxyV1(br)
	default:
		return nil, nil
	}
}

func parseProxyV1(br *bufio.Reader) (net.Addr, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) > 108 {
		return nil, errors.New("v1 header too long")
	}
	fields := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, errors.New("malformed v1 header")
	}
	switch fields[1] {
	case "UNKNOWN":
		return nil, nil
	case "TCP4", "TCP6":
		if len(fields) != 6 {
			return nil, errors.New("malformed v1 address block")
		}
		ip := net.ParseIP(fields[2])
		port, err := strconv.Atoi(fields[4])
		if ip == nil || err != nil || port < 0 || port > 65535 {
			return nil, errors.New("malformed v1 source address")
		}
		return &net.TCPAddr{IP: ip, Port: port}, nil
	default:
		return nil, fmt.Errorf("unsupported v1 transport %q", fields[1])
	}
}

func parseProxyV2(br *bufio.Reader) (net.Addr, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	command := header[12] & 0x0F
	family := header[13] >> 4
	protocol := header[13] & 0x0F
	length := int(binary.BigEndian.Uint16(header[14:16]))
	body := make([]byte, length)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	// command 0 is LOCAL: a health check from the proxy itself.
	if command != 1 || protocol == 0 {
		return nil, nil
	}
	switch family {
	case 1: // AF_INET
		if length < 12 {
			return nil, errors.New("v2 IPv4 block too short")
		}
		return &net.TCPAddr{IP: net.IP(body[0:4]), Port: int(binary.BigEndian.Uint16(body[8:10]))}, nil
	case 2: // AF_INET6
		if length < 36 {
			return nil, errors.New("v2 IPv6 block too short")
		}
		return &net.TCPAddr{IP: net.IP(body[0:16]), Port: int(binary.BigEndian.Uint16(body[32:34]))}, nil
	default:
		return nil, nil
	}
}

// bufferedConn keeps the bytes the PROXY parser read ahead available to the
// HTTP server.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// rewrittenConn reports the address announced by the PROXY header.
type rewrittenConn struct {
	net.Conn
	remote net.Addr
}

func (c *rewrittenConn) RemoteAddr() net.Addr { return c.remote }
