// Independent quic-go v0.62.0 server fixture; no transport implementation changes.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	quic "github.com/quic-go/quic-go"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

var output sync.Mutex

func emit(value any) { output.Lock(); defer output.Unlock(); json.NewEncoder(os.Stdout).Encode(value) }
func main() {
	cert := flag.String("cert", "", "certificate")
	key := flag.String("key", "", "key")
	mode := flag.String("mode", "echo", "echo or reset")
	flag.Parse()
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		panic(err)
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
	} else {
		listener, err = quic.ListenAddr("127.0.0.1:0", tlsConfig, config)
	}
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	emit(map[string]any{"event": "listening", "address": listener.Addr().String(), "peer": "quic-go-v0.62.0"})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
