// Independent RFC 9220 WebSocket-over-HTTP/3 echo peer built on an unmodified,
// pinned quic-go/http3 release (see go.mod/go.sum). Only the WebSocket framing
// (RFC 6455) is implemented here; QUIC, HTTP/3, extended CONNECT and path
// validation are quic-go's own.
//
// Path evidence for every received WebSocket message is two-fold:
//   - "remote": the connection's current peer address, *quic.Conn.RemoteAddr().
//     quic-go server connections switch it only after receiving the
//     highest-numbered non-probing packet from a new, validated client address
//     (RFC 9000 section 9.3), so it changes only when application packets
//     arrived on the new path.
//   - "sources": cumulative UDP datagram/byte counts per source address, taken
//     from a counting wrapper around the listening socket (every datagram the
//     server reads passes through it). A large post-migration message proves
//     its bytes arrived from the new address and not the old one.
//
// Events are JSON lines on stdout; the launcher (gate.py) asserts them.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const pinnedQuicGo = "v0.65.0"
const maxMessage = 1 << 20

var output sync.Mutex

func emit(value map[string]any) {
	output.Lock()
	defer output.Unlock()
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		os.Exit(3)
	}
}

type sourceStats struct {
	Datagrams int `json:"datagrams"`
	Bytes     int `json:"bytes"`
}

// countingConn records the source address of every datagram the server reads.
type countingConn struct {
	net.PacketConn
	mu      sync.Mutex
	sources map[string]*sourceStats
}

func (c *countingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if n > 0 && addr != nil {
		c.mu.Lock()
		stats := c.sources[addr.String()]
		if stats == nil {
			stats = &sourceStats{}
			c.sources[addr.String()] = stats
		}
		stats.Datagrams++
		stats.Bytes += n
		c.mu.Unlock()
	}
	return n, addr, err
}

func (c *countingConn) snapshot() map[string]sourceStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make(map[string]sourceStats, len(c.sources))
	for addr, stats := range c.sources {
		copied[addr] = *stats
	}
	return copied
}

type connKey struct{}

type tracked struct {
	id   int64
	conn *quic.Conn
}

func quicGoVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/quic-go/quic-go" {
			if dep.Replace != nil {
				return "replaced"
			}
			return dep.Version
		}
	}
	return ""
}

// certificates creates an ephemeral CA and an example.test leaf; the CA is
// written to caPath for the client and never reused across runs.
func certificates(caPath string) (tls.Certificate, error) {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "HTTP3 migration acceptance root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		DNSNames: []string{"example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, nil
}

func main() {
	caPath := flag.String("ca-out", "", "path to write the ephemeral CA certificate")
	lifetime := flag.Duration("lifetime", 90*time.Second, "hard upper bound on the peer's lifetime")
	flag.Parse()
	version := quicGoVersion()
	if version != pinnedQuicGo {
		fmt.Fprintf(os.Stderr, "quic-go version %q, want unmodified %s\n", version, pinnedQuicGo)
		os.Exit(2)
	}
	if *caPath == "" {
		fmt.Fprintln(os.Stderr, "--ca-out is required")
		os.Exit(2)
	}
	time.AfterFunc(*lifetime, func() {
		emit(map[string]any{"event": "lifetime_expired"})
		os.Exit(4)
	})
	certificate, err := certificates(*caPath)
	if err != nil {
		panic(err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	counting := &countingConn{PacketConn: udp, sources: map[string]*sourceStats{}}
	var connections atomic.Int64
	server := &http3.Server{
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13},
		QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			id := connections.Add(1)
			emit(map[string]any{"event": "connection", "conn": id, "remote": conn.RemoteAddr().String()})
			go func() {
				<-conn.Context().Done()
				emit(map[string]any{"event": "connection_closed", "conn": id, "remote": conn.RemoteAddr().String(),
					"cause": fmt.Sprint(context.Cause(conn.Context()))})
			}()
			return context.WithValue(ctx, connKey{}, tracked{id: id, conn: conn})
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveWebSocket(w, r, counting)
		}),
	}
	emit(map[string]any{"event": "listening", "address": udp.LocalAddr().String(), "quic_go": version})
	if err := server.Serve(counting); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func serveWebSocket(w http.ResponseWriter, r *http.Request, counting *countingConn) {
	owner, ok := r.Context().Value(connKey{}).(tracked)
	if !ok || r.Method != http.MethodConnect || r.Proto != "websocket" || r.URL.Path != "/echo" ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		emit(map[string]any{"event": "refused", "method": r.Method, "protocol": r.Proto, "path": r.URL.Path})
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	stream, err := w.(http3.HTTPStreamer).HTTPStream()
	if err != nil {
		emit(map[string]any{"event": "takeover_failed", "error": err.Error()})
		return
	}
	streamID := int64(stream.StreamID())
	emit(map[string]any{"event": "open", "conn": owner.id, "stream": streamID, "remote": owner.conn.RemoteAddr().String()})
	reader := bufio.NewReader(stream)
	for {
		opcode, payload, err := readMessage(reader, stream)
		if err != nil {
			emit(map[string]any{"event": "stream_error", "conn": owner.id, "stream": streamID, "error": err.Error()})
			stream.CancelRead(0x10c) // H3_REQUEST_CANCELLED
			stream.CancelWrite(0x10c)
			return
		}
		if opcode == 0x8 {
			code, reason := closePayload(payload)
			emit(map[string]any{"event": "close", "conn": owner.id, "stream": streamID, "code": code,
				"reason": reason, "remote": owner.conn.RemoteAddr().String()})
			if _, err := stream.Write(frame(0x8, payload)); err != nil {
				emit(map[string]any{"event": "stream_error", "conn": owner.id, "stream": streamID, "error": err.Error()})
				return
			}
			stream.Close()
			rest, err := io.Copy(io.Discard, reader)
			emit(map[string]any{"event": "stream_end", "conn": owner.id, "stream": streamID,
				"fin": err == nil, "trailing_bytes": rest, "error": fmt.Sprint(err)})
			return
		}
		digest := sha256.Sum256(payload)
		emit(map[string]any{"event": "message", "conn": owner.id, "stream": streamID, "opcode": opcode,
			"bytes": len(payload), "sha256": hex.EncodeToString(digest[:]),
			"remote": owner.conn.RemoteAddr().String(), "sources": counting.snapshot()})
		if _, err := stream.Write(frame(opcode, payload)); err != nil {
			emit(map[string]any{"event": "stream_error", "conn": owner.id, "stream": streamID, "error": err.Error()})
			return
		}
	}
}

// readMessage returns the next complete data or Close message, answering
// Pings in between. Client frames must be masked (RFC 6455 section 5.1).
func readMessage(reader *bufio.Reader, stream *http3.Stream) (byte, []byte, error) {
	var opcode byte
	var message []byte
	for {
		fin, frameOpcode, payload, err := readFrame(reader)
		if err != nil {
			return 0, nil, err
		}
		switch {
		case frameOpcode == 0x9:
			if !fin || len(payload) > 125 {
				return 0, nil, errors.New("invalid ping")
			}
			if _, err := stream.Write(frame(0xA, payload)); err != nil {
				return 0, nil, err
			}
			continue
		case frameOpcode == 0xA:
			continue
		case frameOpcode == 0x8:
			if !fin || len(payload) > 125 || len(payload) == 1 {
				return 0, nil, errors.New("invalid close")
			}
			return 0x8, payload, nil
		case frameOpcode == 0x0:
			if opcode == 0 {
				return 0, nil, errors.New("continuation without a message")
			}
		case frameOpcode == 0x1 || frameOpcode == 0x2:
			if opcode != 0 {
				return 0, nil, errors.New("interleaved data message")
			}
			opcode = frameOpcode
		default:
			return 0, nil, fmt.Errorf("unsupported opcode %d", frameOpcode)
		}
		if len(message)+len(payload) > maxMessage {
			return 0, nil, errors.New("message too large")
		}
		message = append(message, payload...)
		if fin {
			return opcode, message, nil
		}
	}
}

func readFrame(reader *bufio.Reader) (bool, byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return false, 0, nil, err
	}
	if header[0]&0x70 != 0 {
		return false, 0, nil, errors.New("reserved bits set")
	}
	if header[1]&0x80 == 0 {
		return false, 0, nil, errors.New("unmasked client frame")
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > maxMessage {
		return false, 0, nil, errors.New("frame too large")
	}
	var mask [4]byte
	if _, err := io.ReadFull(reader, mask[:]); err != nil {
		return false, 0, nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return false, 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return header[0]&0x80 != 0, header[0] & 0x0f, payload, nil
}

// frame encodes one unmasked, final server frame.
func frame(opcode byte, payload []byte) []byte {
	out := []byte{0x80 | opcode}
	switch n := len(payload); {
	case n < 126:
		out = append(out, byte(n))
	case n <= 0xffff:
		out = append(out, 126)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	default:
		out = append(out, 127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	return append(out, payload...)
}

func closePayload(payload []byte) (int, string) {
	if len(payload) < 2 {
		return 1005, ""
	}
	return int(binary.BigEndian.Uint16(payload[:2])), string(payload[2:])
}
