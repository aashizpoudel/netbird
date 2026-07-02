package derp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoopTransport(t *testing.T) {
	tr := noopTransport{}

	assert.NoError(t, tr.CloseHome())
	assert.False(t, tr.HomeConnected())
	assert.NoError(t, tr.ConnectHome(context.Background(), Node{ID: "n1"}))
	assert.False(t, tr.HomeConnected(), "noopTransport never reports connected")

	conn, err := tr.OpenPeerStream(context.Background(), "remote", PeerState{Enabled: true})
	assert.Nil(t, conn)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConnected))
	assert.True(t, errors.Is(err, ErrNotImplemented))
}

func TestMemTransport_ConnectHomeIdempotent(t *testing.T) {
	tr := &MemTransport{}
	home := Node{ID: "home-1", RegionID: 7, PublicKey: []byte{1}}

	require.NoError(t, tr.ConnectHome(context.Background(), home))
	assert.True(t, tr.HomeConnected())

	// Second ConnectHome on the same node is a no-op (idempotent reconnect).
	require.NoError(t, tr.ConnectHome(context.Background(), home))
	assert.True(t, tr.HomeConnected())
	assert.Equal(t, 2, tr.ConnectAttempts, "ConnectAttempts should count both calls")
}

func TestMemTransport_ConnectHomeReconnectsOnNodeChange(t *testing.T) {
	tr := &MemTransport{}

	require.NoError(t, tr.ConnectHome(context.Background(), Node{ID: "home-1"}))
	require.True(t, tr.HomeConnected())

	// Connecting to a different node should reconnect, not no-op.
	require.NoError(t, tr.ConnectHome(context.Background(), Node{ID: "home-2"}))
	assert.True(t, tr.HomeConnected())
}

func TestMemTransport_CloseHomeClearsConnected(t *testing.T) {
	tr := &MemTransport{}

	require.NoError(t, tr.ConnectHome(context.Background(), Node{ID: "home-1"}))
	require.True(t, tr.HomeConnected())

	require.NoError(t, tr.CloseHome())
	assert.False(t, tr.HomeConnected())
}

func TestMemTransport_FailThenSucceed(t *testing.T) {
	tr := &MemTransport{}
	tr.FailConnect = 2
	tr.ConnectErr = errors.New("boom")

	err := tr.ConnectHome(context.Background(), Node{ID: "home-1"})
	require.Error(t, err)
	assert.False(t, tr.HomeConnected())

	err = tr.ConnectHome(context.Background(), Node{ID: "home-1"})
	require.Error(t, err)
	assert.False(t, tr.HomeConnected())

	// Third attempt succeeds.
	err = tr.ConnectHome(context.Background(), Node{ID: "home-1"})
	require.NoError(t, err)
	assert.True(t, tr.HomeConnected())
	assert.Equal(t, 3, tr.ConnectAttempts)
}

func TestMemTransport_OpenPeerStreamRequiresHome(t *testing.T) {
	tr := &MemTransport{}
	tr.SetPeerHandler(func(string, PeerState) (net.Conn, error) {
		t.Fatal("handler must not be called when home is down")
		return nil, nil
	})

	conn, err := tr.OpenPeerStream(context.Background(), "remote", PeerState{Enabled: true})
	assert.Nil(t, conn)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConnected))
}

func TestMemTransport_OpenPeerStreamNoHandler(t *testing.T) {
	tr := &MemTransport{}
	require.NoError(t, tr.ConnectHome(context.Background(), Node{ID: "home-1"}))

	conn, err := tr.OpenPeerStream(context.Background(), "remote", PeerState{Enabled: true})
	assert.Nil(t, conn)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotImplemented), "no handler should yield ErrNotImplemented")
}

func TestMemTransport_OpenPeerStreamReturnsWorkingPipe(t *testing.T) {
	tr := &MemTransport{}
	require.NoError(t, tr.ConnectHome(context.Background(), Node{ID: "home-1"}))

	// The handler keeps the server end of a net.Pipe and returns the client end.
	serverCh := make(chan net.Conn, 1)
	tr.SetPeerHandler(func(remoteKey string, remote PeerState) (net.Conn, error) {
		assert.Equal(t, "remote-key", remoteKey)
		assert.True(t, remote.Enabled)
		client, server := net.Pipe()
		serverCh <- server
		return client, nil
	})

	clientConn, err := tr.OpenPeerStream(context.Background(), "remote-key", PeerState{Enabled: true, HomeRegionID: 7})
	require.NoError(t, err)
	require.NotNil(t, clientConn)

	serverConn := <-serverCh
	require.NotNil(t, serverConn)

	// Concurrent exchange both ways over the pipe.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := clientConn.Write([]byte("ping-from-client"))
		assert.NoError(t, err)
	}()

	go func() {
		defer wg.Done()
		_, err := serverConn.Write([]byte("pong-from-server"))
		assert.NoError(t, err)
	}()

	// Read on each end; net.Pipe writes block until both ends are reading, so do
	// the reads concurrently too.
	type readResult struct {
		n   int
		err error
		buf []byte
	}
	clientRead := make(chan readResult, 1)
	serverRead := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 32)
		n, err := clientConn.Read(buf)
		clientRead <- readResult{n, err, buf[:n]}
	}()
	go func() {
		buf := make([]byte, 32)
		n, err := serverConn.Read(buf)
		serverRead <- readResult{n, err, buf[:n]}
	}()

	select {
	case r := <-clientRead:
		require.NoError(t, r.err)
		assert.Equal(t, "pong-from-server", string(r.buf))
	case <-time.After(2 * time.Second):
		t.Fatal("client read timed out")
	}

	select {
	case r := <-serverRead:
		require.NoError(t, r.err)
		assert.Equal(t, "ping-from-client", string(r.buf))
	case <-time.After(2 * time.Second):
		t.Fatal("server read timed out")
	}

	wg.Wait()

	// Close must be non-fatal (FR-27: closable).
	assert.NoError(t, clientConn.Close())
	assert.NoError(t, serverConn.Close())

	// After close, reads should surface a closed/EOF error.
	buf := make([]byte, 8)
	_, err = clientConn.Read(buf)
	require.Error(t, err, "expected read error after close")
	assert.True(t,
		err == io.EOF || err == io.ErrClosedPipe || err == net.ErrClosed,
		"expected EOF/ErrClosedPipe/ErrClosed after close, got %v", err)
}

func TestMemTransport_OpenPeerStreamHandlerError(t *testing.T) {
	tr := &MemTransport{}
	require.NoError(t, tr.ConnectHome(context.Background(), Node{ID: "home-1"}))

	refused := errors.New("server refused")
	tr.SetPeerHandler(func(string, PeerState) (net.Conn, error) {
		return nil, refused
	})

	conn, err := tr.OpenPeerStream(context.Background(), "remote", PeerState{Enabled: true})
	assert.Nil(t, conn)
	require.Error(t, err)
	assert.ErrorIs(t, err, refused)
}

func TestMemTransport_ConcurrentSafe(t *testing.T) {
	// A light race check: concurrent ConnectHome/HomeConnected/OpenPeerStream
	// must not panic. Run with -race to validate.
	tr := &MemTransport{}
	tr.SetPeerHandler(func(string, PeerState) (net.Conn, error) {
		c, s := net.Pipe()
		go s.Close()
		return c, nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tr.ConnectHome(context.Background(), Node{ID: "home"})
			_ = tr.HomeConnected()
			c, _ := tr.OpenPeerStream(context.Background(), "r", PeerState{Enabled: true})
			if c != nil {
				_ = c.Close()
			}
		}()
	}
	wg.Wait()
}
