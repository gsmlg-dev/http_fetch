// Independent quic-go v0.62.0 server fixture; no transport implementation changes.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var output sync.Mutex

func emit(value any) { output.Lock(); defer output.Unlock(); json.NewEncoder(os.Stdout).Encode(value) }

// zeroCIDs configures the upstream public ConnectionIDGenerator extension point
// with zero-length connection IDs: quic-go then issues no NEW_CONNECTION_ID.
type zeroCIDs struct{}

func (zeroCIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionIDFromBytes(nil), nil
}
func (zeroCIDs) ConnectionIDLen() int { return 0 }

func main() {
	cert := flag.String("cert", "", "certificate")
	key := flag.String("key", "", "key")
	mode := flag.String("mode", "echo", "echo or reset")
	zeroCID := flag.Bool("zero-cid", false, "server uses zero-length connection IDs (no spare CID)")
	matrix := matrixFlags{}
	flag.IntVar(&matrix.listeners, "listeners", 1, "matrix: number of listeners sharing one TLS config")
	flag.BoolVar(&matrix.allow0RTT, "allow-0rtt", false, "matrix: quic.Config.Allow0RTT with an early listener")
	flag.BoolVar(&matrix.retry, "retry", false, "matrix: Transport.VerifySourceAddress always requests Retry")
	flag.StringVar(&matrix.curves, "curves", "", "matrix: tls.Config.CurvePreferences (p256)")
	flag.BoolVar(&matrix.rejectEarly, "reject-early", false, "matrix: UnwrapSession clears SessionState.EarlyData")
	flag.BoolVar(&matrix.noReliableReset, "no-reliable-reset", false, "matrix: do not enable reset_stream_at")
	flag.BoolVar(&matrix.qlog, "qlog", false, "matrix: qlog.DefaultConnectionTracer (QLOGDIR)")
	port := flag.Int("port", 0, "client: server port on 127.0.0.1")
	ca := flag.String("ca", "", "client: trusted root certificate")
	connections := flag.Int("connections", 3, "client: one full, then 0-RTT connections")
	linger := flag.Int("linger", 1500, "client: ms each 0-RTT connection stays open after its echo")
	flag.Parse()
	if *mode == "client" {
		runClient(*port, *ca, *connections, *linger)
		return
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		panic(err)
	}
	if *mode == "matrix" {
		runMatrix(pair, matrix)
		return
	}
	var listener interface {
		Accept(context.Context) (*quic.Conn, error)
		Close() error
		Addr() net.Addr
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"ex-quic-m2", "ex-quic-r1"}}
	config := &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true}
	if *mode == "early" {
		config.Allow0RTT = true
		config.InitialConnectionReceiveWindow = 65536
		config.InitialStreamReceiveWindow = 65536
		config.MaxIncomingStreams = 8
		config.MaxIncomingUniStreams = 8
		listener, err = quic.ListenAddrEarly("127.0.0.1:0", tlsConfig, config)
	} else if *zeroCID {
		udp, udpErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if udpErr != nil {
			panic(udpErr)
		}
		transport := &quic.Transport{Conn: udp, ConnectionIDGenerator: zeroCIDs{}}
		listener, err = transport.Listen(tlsConfig, config)
	} else {
		listener, err = quic.ListenAddr("127.0.0.1:0", tlsConfig, config)
	}
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	emit(map[string]any{"event": "listening", "address": listener.Addr().String(), "peer": "quic-go-v0.62.0", "module": quicGoModule(), "zero_cid": *zeroCID})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		if *mode == "early" {
			select {
			case <-conn.HandshakeComplete():
			case <-ctx.Done():
				return
			}
		}
		if *mode == "reset" {
			go serveReset(ctx, conn)
		} else {
			go serve(ctx, conn)
		}
	}
}
func serve(ctx context.Context, conn *quic.Conn) {
	state := conn.ConnectionState()
	emit(map[string]any{"event": "handshake", "alpn": state.TLS.NegotiatedProtocol, "resumed": state.TLS.DidResume, "early": state.Used0RTT, "reliable_reset": state.SupportsStreamResetPartialDelivery})
	go func() {
		for {
			data, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if err := conn.SendDatagram(data); err != nil {
				panic(err)
			}
		}
	}()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			var received []byte
			buffer := make([]byte, 4096)
			for {
				n, err := stream.Read(buffer)
				if n > 0 {
					received = append(received, buffer[:n]...)
					if _, writeErr := stream.Write(buffer[:n]); writeErr != nil {
						panic(writeErr)
					}
					digest := sha256.Sum256(received)
					emit(map[string]any{"event": "receipt", "stream": stream.StreamID(), "bytes": len(received), "sha256": hex.EncodeToString(digest[:]), "remote": conn.RemoteAddr().String()})
				}
				if err != nil {
					digest := sha256.Sum256(received)
					emit(map[string]any{"event": "stream", "stream": stream.StreamID(), "bytes": len(received), "sha256": hex.EncodeToString(digest[:]), "fin": err == io.EOF, "error": fmt.Sprint(err), "remote": conn.RemoteAddr().String()})
					stream.Close()
					return
				}
			}
		}()
	}
}

func serveReset(ctx context.Context, conn *quic.Conn) {
	state := conn.ConnectionState()
	emit(map[string]any{"event": "handshake", "reliable_reset": state.SupportsStreamResetPartialDelivery})
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		panic(err)
	}
	data, err := io.ReadAll(stream)
	var reset *quic.StreamError
	if !errors.As(err, &reset) || reset.ErrorCode != 42 || !bytes.HasPrefix(data, []byte("client-header")) {
		panic(fmt.Sprintf("missing reliable client prefix/reset: %d bytes %v", len(data), err))
	}
	emit(map[string]any{"event": "client_reset", "bytes": len(data), "prefix": true, "code": reset.ErrorCode})
	stream.CancelWrite(0)
	outgoing, err := conn.OpenStreamSync(ctx)
	if err != nil {
		panic(err)
	}
	outgoing.Write([]byte("server-header"))
	outgoing.SetReliableBoundary()
	outgoing.Write([]byte("server-tail"))
	outgoing.CancelWrite(43)
	emit(map[string]any{"event": "server_reset", "prefix": 13, "written": 24, "code": 43})
	<-ctx.Done()
}

// quicGoModule reports the quic-go module version linked into this binary.
func quicGoModule() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/quic-go/quic-go" {
				return dep.Path + "@" + dep.Version
			}
		}
	}
	return "unknown"
}

type matrixFlags struct {
	listeners                                            int
	allow0RTT, retry, rejectEarly, noReliableReset, qlog bool
	curves                                               string
}

// runMatrix serves the R1/R2/reliable-reset negative matrices. Every knob is a
// public quic-go or crypto/tls configuration field; the stack is unmodified.
func runMatrix(pair tls.Certificate, flags matrixFlags) {
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"ex-quic-m2", "ex-quic-r1"}}
	if flags.curves == "p256" {
		tlsConfig.CurvePreferences = []tls.CurveID{tls.CurveP256}
	}
	rotate := func() {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			panic(err)
		}
		tlsConfig.SetSessionTicketKeys([][32]byte{key})
	}
	rotate()
	// Default ticket handling through the public hooks, always with this base
	// config's key set (quic-go clones the config per connection), so a ticket
	// presentation is observable per client address and keys can rotate.
	base := tlsConfig
	listenerConfig := base.Clone()
	listenerConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		remote := info.Conn.RemoteAddr().String()
		config := base.Clone()
		config.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
			emit(map[string]any{"event": "ticket_issued", "remote": remote, "early": ss.EarlyData})
			return base.EncryptTicket(cs, ss)
		}
		config.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
			session, err := base.DecryptTicket(identity, cs)
			early := session != nil && session.EarlyData
			emit(map[string]any{"event": "ticket_presented", "remote": remote, "decrypted": session != nil,
				"early": early, "early_cleared": early && flags.rejectEarly})
			if early && flags.rejectEarly {
				session.EarlyData = false
			}
			return session, err
		}
		return config, nil
	}
	config := &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: !flags.noReliableReset,
		InitialConnectionReceiveWindow: 65536, InitialStreamReceiveWindow: 65536, MaxIncomingStreams: 8, MaxIncomingUniStreams: 8}
	if flags.allow0RTT {
		config.Allow0RTT = true
	}
	if flags.qlog {
		config.Tracer = qlog.DefaultConnectionTracer
	}
	type acceptor interface {
		Accept(context.Context) (*quic.Conn, error)
		Addr() net.Addr
	}
	var listeners []acceptor
	var transports []*quic.Transport
	var addresses []string
	for index := 0; index < flags.listeners; index++ {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			panic(err)
		}
		transport := &quic.Transport{Conn: udp}
		transports = append(transports, transport)
		if flags.retry {
			transport.VerifySourceAddress = func(net.Addr) bool { return true }
		}
		var listener acceptor
		if flags.allow0RTT {
			listener, err = transport.ListenEarly(listenerConfig, config)
		} else {
			listener, err = transport.Listen(listenerConfig, config)
		}
		if err != nil {
			panic(err)
		}
		listeners = append(listeners, listener)
		addresses = append(addresses, listener.Addr().String())
	}
	emit(map[string]any{"event": "listening", "address": addresses[0], "addresses": addresses, "peer": "quic-go-v0.62.0",
		"module": quicGoModule(), "mode": "matrix", "allow_0rtt": flags.allow0RTT, "retry": flags.retry, "curves": flags.curves,
		"reject_early": flags.rejectEarly, "reliable_reset": !flags.noReliableReset, "qlog": flags.qlog})
	ctx, cancel := context.WithTimeout(context.Background(), 170*time.Second)
	defer cancel()
	// SIGTERM closes every connection so that each qlog trace is flushed.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	closed := make(chan struct{})
	go func() {
		<-signals
		for _, transport := range transports {
			transport.Close()
		}
		time.Sleep(500 * time.Millisecond)
		emit(map[string]any{"event": "peer_closed"})
		close(closed)
		cancel()
	}()
	var connections atomic.Int64
	var wait sync.WaitGroup
	for index, listener := range listeners {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for {
				conn, err := listener.Accept(ctx)
				if err != nil {
					return
				}
				go serveMatrix(ctx, conn, index, int(connections.Add(1)-1), rotate)
			}
		}()
	}
	wait.Wait()
	select {
	case <-closed:
	case <-ctx.Done():
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
	}
}

func serveMatrix(ctx context.Context, conn *quic.Conn, listener, index int, rotate func()) {
	go func() {
		select {
		case <-conn.HandshakeComplete():
		case <-ctx.Done():
			return
		}
		state := conn.ConnectionState()
		emit(map[string]any{"event": "handshake", "conn": index, "listener": listener, "alpn": state.TLS.NegotiatedProtocol,
			"resumed": state.TLS.DidResume, "early": state.Used0RTT, "hrr": state.TLS.HelloRetryRequest,
			"curve": state.TLS.CurveID.String(), "reliable_reset": state.SupportsStreamResetPartialDelivery,
			"remote": conn.RemoteAddr().String()})
	}()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go serveCommand(conn, index, stream, rotate)
	}
}

func pattern(offset, length int) []byte {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte((offset + i) % 251)
	}
	return data
}

// serveCommand reads one command line, then acts on the rest of the stream.
// Byte counts and digests always cover everything received on the stream.
func serveCommand(conn *quic.Conn, index int, stream *quic.Stream, rotate func()) {
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil {
		emit(map[string]any{"event": "command_error", "conn": index, "stream": stream.StreamID(), "error": fmt.Sprint(err)})
		return
	}
	received := []byte(line)
	fields := strings.Fields(line)
	number := func(i int) int {
		value, err := strconv.Atoi(fields[i])
		if err != nil {
			panic(err)
		}
		return value
	}
	report := func(event string, err error, extra map[string]any) map[string]any {
		digest := sha256.Sum256(received)
		record := map[string]any{"event": event, "conn": index, "stream": stream.StreamID(), "command": fields[0],
			"bytes": len(received), "sha256": hex.EncodeToString(digest[:]), "fin": err == io.EOF, "error": fmt.Sprint(err)}
		var reset *quic.StreamError
		if errors.As(err, &reset) {
			record["reset_code"] = reset.ErrorCode
			record["reset_remote"] = reset.Remote
		}
		for key, value := range extra {
			record[key] = value
		}
		emit(record)
		return record
	}
	buffer := make([]byte, 4096)
	switch fields[0] {
	case "echo":
		if _, err := stream.Write(received); err != nil {
			panic(err)
		}
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				received = append(received, buffer[:n]...)
				if _, writeErr := stream.Write(buffer[:n]); writeErr != nil {
					panic(writeErr)
				}
			}
			if err != nil {
				report("stream", err, nil)
				stream.Close()
				return
			}
		}
	case "sink":
		rest, err := io.ReadAll(reader)
		received = append(received, rest...)
		if err == nil {
			err = io.EOF
		}
		// The receipt also travels back on this stream's still-open send
		// direction, so the runtime learns what the peer application read.
		encoded, _ := json.Marshal(report("stream", err, nil))
		stream.Write(append(encoded, '\n'))
		stream.Close()
	case "stop":
		// stop <after-bytes> <code> <delay-ms>: STOP_SENDING once enough arrived.
		for len(received) < number(1) {
			n, err := reader.Read(buffer)
			received = append(received, buffer[:n]...)
			if err != nil {
				report("stream", err, nil)
				return
			}
		}
		time.Sleep(time.Duration(number(3)) * time.Millisecond)
		stream.CancelRead(quic.StreamErrorCode(number(2)))
		encoded, _ := json.Marshal(report("stop_sent", nil, map[string]any{"code": number(2)}))
		stream.Write(append(encoded, '\n'))
		stream.Close()
	case "reset":
		// reset <reliable-size> <total> <code>: write, mark the reliable boundary, then reset.
		prefix, total := number(1), number(2)
		if _, err := stream.Write(pattern(0, prefix)); err != nil {
			panic(err)
		}
		stream.SetReliableBoundary()
		if _, err := stream.Write(pattern(prefix, total-prefix)); err != nil {
			panic(err)
		}
		stream.CancelWrite(quic.StreamErrorCode(number(3)))
		digest := sha256.Sum256(pattern(0, prefix))
		emit(map[string]any{"event": "server_reset", "conn": index, "stream": stream.StreamID(), "prefix": prefix,
			"written": total, "code": number(3), "prefix_sha256": hex.EncodeToString(digest[:])})
		io.Copy(io.Discard, reader)
	case "rotate":
		rotate()
		emit(map[string]any{"event": "rotated", "conn": index})
		stream.Write([]byte("rotated\n"))
		stream.Close()
	default:
		panic("unknown command " + fields[0])
	}
}

// notifyingCache is crypto/tls's own LRU session cache; Put is observed only
// to know when the server's ticket has arrived.
type notifyingCache struct {
	tls.ClientSessionCache
	stored chan struct{}
}

func (c notifyingCache) Put(key string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, state)
	if state != nil {
		select {
		case c.stored <- struct{}{}:
		default:
		}
	}
}

// runClient: a full connection that stores a ticket, then a 0-RTT connection
// that writes one stream before the handshake completes; both exact echoes.
func runClient(port int, ca string, connections, linger int) {
	pem, err := os.ReadFile(ca)
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("no root certificate")
	}
	cache := notifyingCache{tls.NewLRUClientSessionCache(4), make(chan struct{}, 1)}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "example.test", NextProtos: []string{"ex-quic-r1"}, ClientSessionCache: cache}
	emit(map[string]any{"event": "client_started", "peer": "quic-go-v0.62.0", "module": quicGoModule()})
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for index := 0; index < connections; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second+time.Duration(linger)*time.Millisecond)
		conn, err := quic.DialAddrEarly(ctx, address, tlsConfig, &quic.Config{EnableDatagrams: true})
		if err != nil {
			panic(err)
		}
		stream, err := conn.OpenStream()
		if err != nil {
			panic(err)
		}
		payload := append([]byte(fmt.Sprintf("late/%d/", index)), pattern(0, 20000)...)
		if _, err := stream.Write(payload); err != nil {
			panic(err)
		}
		stream.Close()
		echoed, err := io.ReadAll(stream)
		if err != nil || !bytes.Equal(echoed, payload) {
			panic(fmt.Sprintf("echo mismatch: %d bytes, %v", len(echoed), err))
		}
		select {
		case <-conn.HandshakeComplete():
		case <-ctx.Done():
			panic("handshake deadline")
		}
		if index == 0 {
			select {
			case <-cache.stored:
			case <-ctx.Done():
				panic("ticket deadline")
			}
		}
		state := conn.ConnectionState()
		digest := sha256.Sum256(payload)
		emit(map[string]any{"event": "handshake", "index": index, "resumed": state.TLS.DidResume, "early": state.Used0RTT,
			"bytes": len(payload), "sha256": hex.EncodeToString(digest[:]), "echo_exact": true, "local": conn.LocalAddr().String()})
		if index > 0 {
			// Keep the connection open while late 0-RTT datagrams arrive at the server.
			time.Sleep(time.Duration(linger) * time.Millisecond)
		}
		emit(map[string]any{"event": "closing", "index": index, "alive": conn.Context().Err() == nil})
		conn.CloseWithError(0, "")
		cancel()
	}
}
