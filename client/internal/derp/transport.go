package derp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

// Transport is the injectable DERP home + peer-stream transport.
//
// The default ClientManager uses a no-op transport; tests inject MemTransport.
// The real wire-protocol DERP client/server (Tailscale vendoring vs custom) is
// an open decision (Open Decision 6) and is intentionally out of scope: this
// interface lets a real transport be plugged in later without changing
// ClientManager's public API.
type Transport interface {
	// ConnectHome establishes/refreshes the long-lived home connection for the
	// selected home node. Returns nil if already connected to the same node.
	// Must be safe to call repeatedly (idempotent reconnect); a different node
	// triggers a reconnect.
	ConnectHome(ctx context.Context, home Node) error
	// CloseHome closes the current home connection if any.
	CloseHome() error
	// OpenPeerStream opens a peer stream to remoteKey/remote home, wrapped as a
	// net.Conn. The returned conn MUST be closable (FR-27).
	OpenPeerStream(ctx context.Context, remoteKey string, remote PeerState) (net.Conn, error)
	// HomeConnected reports whether the home connection is currently up.
	HomeConnected() bool
}

// noopTransport is the dormant transport used when no transport is injected.
// It keeps the manager's home-connection loop a no-op and OpenPeerStream
// returns ErrNotImplemented, matching the deferred Open Decision 6.
type noopTransport struct{}

func (noopTransport) ConnectHome(context.Context, Node) error { return nil }
func (noopTransport) CloseHome() error                        { return nil }
func (noopTransport) OpenPeerStream(context.Context, string, PeerState) (net.Conn, error) {
	return nil, fmt.Errorf("%w: %w", ErrNotConnected, ErrNotImplemented)
}
func (noopTransport) HomeConnected() bool { return false }

// PeerStreamHandler is the server-side callback tests register on MemTransport
// to observe (and drive) the server end of a peer stream. When OpenPeerStream
// is called, the handler is invoked with the remote key/state and MUST return
// one end of a connected pair (typically one end of a net.Pipe); the test
// handler keeps the other end so it can exchange data with the client side.
//
// The returned conn becomes the client-side net.Conn returned by
// OpenPeerStream. Returning an error simulates a server-side refusal.
type PeerStreamHandler func(remoteKey string, remote PeerState) (net.Conn, error)

// MemTransport is an in-memory, deterministic Transport for tests. It has no
// network dependencies and is goroutine-safe.
//
// Tests can configure fail-then-succeed home-connection behavior by setting
// FailConnect and ConnectErr directly (same package), and register a
// PeerStreamHandler via SetPeerHandler to drive the server side of peer
// streams. If no handler is registered, OpenPeerStream returns an error.
type MemTransport struct {
	mu sync.Mutex

	homeConnected bool
	homeNode      Node

	// FailConnect is the number of ConnectHome calls that fail before the next
	// one succeeds. Each failing call returns ConnectErr (or a default error if
	// nil). ConnectHome calls beyond FailConnect succeed.
	FailConnect int
	// ConnectErr is the error returned by failing ConnectHome calls. If nil, a
	// generic error is used.
	ConnectErr error

	// ConnectAttempts records the total number of ConnectHome calls observed,
	// for backoff-loop assertions.
	ConnectAttempts int

	peerHandler PeerStreamHandler
}

// SetPeerHandler registers the server-side handler used by OpenPeerStream.
func (m *MemTransport) SetPeerHandler(h PeerStreamHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerHandler = h
}

// ConnectHome implements idempotent home connection with optional injected
// failures. Calling ConnectHome on the same node while already connected is a
// no-op. Calling it with a different node reconnects.
func (m *MemTransport) ConnectHome(_ context.Context, home Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ConnectAttempts++

	if m.FailConnect > 0 {
		m.FailConnect--
		err := m.ConnectErr
		if err == nil {
			err = errors.New("derp mem transport: injected connect failure")
		}
		m.homeConnected = false
		m.homeNode = Node{}
		return err
	}

	m.homeConnected = true
	m.homeNode = home
	return nil
}

// CloseHome drops the in-memory home connection.
func (m *MemTransport) CloseHome() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.homeConnected = false
	m.homeNode = Node{}
	return nil
}

// HomeConnected reports the in-memory home connection state.
func (m *MemTransport) HomeConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.homeConnected
}

// OpenPeerStream invokes the registered peer handler and returns its conn.
// It requires the home connection to be up; if not, it returns ErrNotConnected.
// If no handler is registered, it returns ErrNotImplemented.
func (m *MemTransport) OpenPeerStream(ctx context.Context, remoteKey string, remote PeerState) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.Lock()
	connected := m.homeConnected
	handler := m.peerHandler
	m.mu.Unlock()

	if !connected {
		return nil, fmt.Errorf("%w: home not connected", ErrNotConnected)
	}
	if handler == nil {
		return nil, fmt.Errorf("%w: no peer handler registered", ErrNotImplemented)
	}
	return handler(remoteKey, remote)
}
