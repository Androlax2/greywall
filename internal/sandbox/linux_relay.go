//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	relayDialTimeout = 10 * time.Second
	// dnsReplyTimeout bounds how long a DNS exchange waits for the upstream
	// server once the sandbox side has sent its query.
	dnsReplyTimeout = 5 * time.Second
	// unixDialRetries and unixDialInterval match the socat options the
	// reverse bridge used (retry=50,interval=0.1): the socket is created by a
	// listener inside the sandbox that may start after the host listener.
	unixDialRetries  = 50
	unixDialInterval = 100 * time.Millisecond
)

// relayHandler serves one accepted connection. It must return once ctx is
// canceled; the relay closes the accepted connection after it returns.
type relayHandler func(ctx context.Context, downstream net.Conn)

// relay accepts connections in-process and serves each in a goroutine, so a
// bridge costs one listener instead of a socat process per listener and per
// connection.
type relay struct {
	name     string
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func startRelay(name string, listener net.Listener, handle relayHandler) *relay {
	ctx, cancel := context.WithCancel(context.Background())
	r := &relay{name: name, listener: listener, cancel: cancel}
	r.wg.Add(1)
	go r.acceptLoop(ctx, handle)
	return r
}

func (r *relay) acceptLoop(ctx context.Context, handle relayHandler) {
	defer r.wg.Done()
	for {
		downstream, err := r.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Typically EMFILE: back off instead of spinning, and keep serving.
			fmt.Fprintf(os.Stderr, "[greywall:linux] %s: accept failed: %v\n", r.name, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() { _ = downstream.Close() }()
			handle(ctx, downstream)
		}()
	}
}

// Close stops accepting, closes every open connection and waits for the
// handlers to return.
func (r *relay) Close() {
	r.cancel()
	_ = r.listener.Close()
	r.wg.Wait()
}

// closeOnCancel closes conns when ctx is canceled, unblocking pending reads
// and writes. The returned function releases the hook.
func closeOnCancel(ctx context.Context, conns ...net.Conn) func() bool {
	return context.AfterFunc(ctx, func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
}

// streamTo returns a handler that connects each accepted connection to
// network/address and copies bytes both ways.
func streamTo(name, network, address string, debug bool) relayHandler {
	return func(ctx context.Context, downstream net.Conn) {
		dialer := net.Dialer{Timeout: relayDialTimeout}
		upstream, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] %s: dial %s %s: %v\n", name, network, address, err)
			}
			return
		}
		defer func() { _ = upstream.Close() }()
		defer closeOnCancel(ctx, downstream, upstream)()
		pipe(downstream, upstream)
	}
}

// streamToUnixWithRetry is streamTo for a Unix socket that may not exist yet.
func streamToUnixWithRetry(name, socketPath string, debug bool) relayHandler {
	return func(ctx context.Context, downstream net.Conn) {
		upstream, err := dialUnixWithRetry(ctx, socketPath)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] %s: dial unix %s: %v\n", name, socketPath, err)
			}
			return
		}
		defer func() { _ = upstream.Close() }()
		defer closeOnCancel(ctx, downstream, upstream)()
		pipe(downstream, upstream)
	}
}

func dialUnixWithRetry(ctx context.Context, socketPath string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: relayDialTimeout}
	var lastErr error
	for range unixDialRetries {
		conn, err := dialer.DialContext(ctx, "unix", socketPath)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(unixDialInterval):
		}
	}
	return nil, lastErr
}

// pipe copies a<->b until both directions finish. A clean EOF is passed on as
// a half-close (like socat), so request/response protocols that shut down
// their write side keep working; an error tears down both connections.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go copyHalf(&wg, a, b)
	go copyHalf(&wg, b, a)
	wg.Wait()
}

type writeCloser interface {
	CloseWrite() error
}

func copyHalf(wg *sync.WaitGroup, dst, src net.Conn) {
	defer wg.Done()
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = src.Close()
		return
	}
	if half, ok := dst.(writeCloser); ok {
		_ = half.CloseWrite()
		return
	}
	_ = dst.Close()
}

// dnsOverStream returns a handler for the socat DNS relay inside the sandbox
// (UDP4-RECVFROM:53,fork -> UNIX-CONNECT): it writes one query per
// connection, shuts down its write side, and waits briefly for the reply.
// Each chunk read from the stream is sent as one datagram, as socat did, and
// the exchange ends after the first reply.
func dnsOverStream(name, dnsAddr string, debug bool) relayHandler {
	return func(ctx context.Context, downstream net.Conn) {
		dialer := net.Dialer{Timeout: relayDialTimeout}
		upstream, err := dialer.DialContext(ctx, "udp", dnsAddr)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] %s: dial udp %s: %v\n", name, dnsAddr, err)
			}
			return
		}
		defer func() { _ = upstream.Close() }()
		defer closeOnCancel(ctx, downstream, upstream)()

		_ = downstream.SetReadDeadline(time.Now().Add(dnsReplyTimeout))
		_ = upstream.SetReadDeadline(time.Now().Add(dnsReplyTimeout))

		replies := make(chan struct{})
		go func() {
			defer close(replies)
			buf := make([]byte, 65535)
			n, err := upstream.Read(buf)
			if err != nil {
				return
			}
			_, _ = downstream.Write(buf[:n])
		}()

		buf := make([]byte, 65535)
		for {
			n, err := downstream.Read(buf)
			if n > 0 {
				if _, werr := upstream.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		<-replies
	}
}
