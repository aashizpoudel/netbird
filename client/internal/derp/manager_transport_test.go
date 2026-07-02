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

// newTransportManager wires a ClientManager to a MemTransport with a tiny
// backoff so the tests stay sub-second.
func newTransportManager(tr *MemTransport) *ClientManager {
	m := NewManagerWithTransport(tr)
	m.backoff = Backoff{Initial: 5 * time.Millisecond, Max: 50 * time.Millisecond}
	return m
}

// waitForHomeConnected polls HomeConnected with a generous timeout so the test
// does not flake on slow CI but still bounds runtime.
func waitForHomeConnected(t *testing.T, m *ClientManager, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.HomeConnected() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return m.HomeConnected()
}

func TestStart_BackoffLoopReachesHomeConnected(t *testing.T) {
	tr := &MemTransport{}
	tr.FailConnect = 3
	tr.ConnectErr = errors.New("dial failed")

	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))
	assert.False(t, m.HomeConnected(), "HomeConnected must be false before Start")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, m.Start(ctx))

	require.True(t, waitForHomeConnected(t, m, 2*time.Second),
		"loop never reached HomeConnected; attempts=%d", tr.ConnectAttempts)
	assert.True(t, tr.HomeConnected())

	// The loop must have actually retried through the injected failures.
	assert.GreaterOrEqual(t, tr.ConnectAttempts, 4, "expected at least 3 failures + 1 success")
}

func TestStart_BackoffLoopRespectsBackoffDurations(t *testing.T) {
	// With Initial=5ms doubling each failure, 2 failures should delay the
	// success by ~5ms+10ms=15ms. We assert the loop took at least that long
	// and bounded by a small multiple (no busy-loop).
	tr := &MemTransport{}
	tr.FailConnect = 2
	tr.ConnectErr = errors.New("dial failed")

	m := newTransportManager(tr)
	// Use slightly larger backoffs so the floor is measurable above scheduler
	// jitter on slow runners.
	m.backoff = Backoff{Initial: 15 * time.Millisecond, Max: 50 * time.Millisecond}
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	require.NoError(t, m.Start(ctx))
	require.True(t, waitForHomeConnected(t, m, 2*time.Second))
	elapsed := time.Since(start)

	// 2 failures with 15ms then 30ms backoff => at least 45ms of sleep before
	// the successful dial. Allow a small floor tolerance.
	minExpected := 40 * time.Millisecond
	assert.GreaterOrEqual(t, elapsed, minExpected,
		"backoff not respected: elapsed %v < expected floor %v", elapsed, minExpected)
}

func TestStart_BackoffLoopIdlesAfterSuccess(t *testing.T) {
	tr := &MemTransport{}

	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, m.Start(ctx))
	require.True(t, waitForHomeConnected(t, m, 2*time.Second))

	attempts := tr.ConnectAttempts
	// After success the loop idles; over a short window it should not keep
	// hammering ConnectHome (which is idempotent but should not busy-loop).
	time.Sleep(20 * time.Millisecond)
	assert.LessOrEqual(t, tr.ConnectAttempts-attempts, 2,
		"loop busy-looped after success: attempts grew from %d to %d", attempts, tr.ConnectAttempts)

	assert.True(t, m.HomeConnected(), "still connected while idling")
}

func TestStart_LoopExitsOnContextCancel(t *testing.T) {
	tr := &MemTransport{}
	// Make it fail forever so the loop is guaranteed to be in the backoff path
	// when we cancel.
	tr.FailConnect = 1 << 30
	tr.ConnectErr = errors.New("dial failed")

	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, m.Start(ctx))

	// Let it fail a few times, then cancel the context.
	time.Sleep(20 * time.Millisecond)
	cancel()

	// Close waits for the loop to exit; if the loop ignored ctx it would
	// deadlock and the test would time out.
	done := make(chan struct{})
	go func() {
		_ = m.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after ctx cancel; loop did not exit")
	}
	assert.False(t, m.HomeConnected())
}

func TestStart_SecondStartIsNoopForLoop(t *testing.T) {
	tr := &MemTransport{}
	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, m.Start(ctx))
	require.True(t, waitForHomeConnected(t, m, 2*time.Second))

	attempts := tr.ConnectAttempts
	// A second Start must not spawn a second loop.
	require.NoError(t, m.Start(ctx))
	time.Sleep(20 * time.Millisecond)
	// Only the single loop keeps idling.
	assert.LessOrEqual(t, tr.ConnectAttempts-attempts, 2)
}

func TestOpenPeerConn_WithTransportReturnsLiveConn(t *testing.T) {
	tr := &MemTransport{}
	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, m.Start(ctx))
	require.True(t, waitForHomeConnected(t, m, 2*time.Second))

	serverCh := make(chan net.Conn, 1)
	tr.SetPeerHandler(func(remoteKey string, remote PeerState) (net.Conn, error) {
		assert.Equal(t, "remote-key", remoteKey)
		assert.True(t, remote.Enabled)
		client, server := net.Pipe()
		serverCh <- server
		return client, nil
	})

	conn, err := m.OpenPeerConn(ctx, "remote-key", PeerState{Enabled: true, HomeRegionID: 1, HomeNodeID: "node-1"})
	require.NoError(t, err)
	require.NotNil(t, conn)

	serverConn := <-serverCh
	require.NotNil(t, serverConn)

	// Bidirectional data flow over the manager-returned net.Conn (FR-16).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, werr := conn.Write([]byte("hello-derp"))
		assert.NoError(t, werr)
	}()
	go func() {
		defer wg.Done()
		_, werr := serverConn.Write([]byte("world-derp"))
		assert.NoError(t, werr)
	}()

	clientRead := make(chan []byte, 1)
	serverRead := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		clientRead <- buf[:n]
	}()
	go func() {
		buf := make([]byte, 32)
		n, _ := serverConn.Read(buf)
		serverRead <- buf[:n]
	}()

	select {
	case b := <-clientRead:
		assert.Equal(t, "world-derp", string(b))
	case <-time.After(2 * time.Second):
		t.Fatal("client read timed out")
	}
	select {
	case b := <-serverRead:
		assert.Equal(t, "hello-derp", string(b))
	case <-time.After(2 * time.Second):
		t.Fatal("server read timed out")
	}
	wg.Wait()

	// Close is non-fatal (FR-27).
	assert.NoError(t, conn.Close())
	assert.NoError(t, serverConn.Close())
	buf := make([]byte, 8)
	_, err = conn.Read(buf)
	require.Error(t, err, "expected read error after close")
	assert.True(t,
		err == io.EOF || err == io.ErrClosedPipe || err == net.ErrClosed,
		"expected EOF/ErrClosedPipe/ErrClosed after close, got %v", err)
}

func TestOpenPeerConn_WithTransportRejectsInvalidInput(t *testing.T) {
	tr := &MemTransport{}
	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, m.Start(ctx))
	require.True(t, waitForHomeConnected(t, m, 2*time.Second))

	// Empty remote key.
	_, err := m.OpenPeerConn(ctx, "", PeerState{Enabled: true})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConnected))

	// Remote not DERP-enabled.
	_, err = m.OpenPeerConn(ctx, "remote", PeerState{Enabled: false})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConnected))
}

func TestOpenPeerConn_WithTransportHandlerErrorWrapped(t *testing.T) {
	tr := &MemTransport{}
	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, m.Start(ctx))
	require.True(t, waitForHomeConnected(t, m, 2*time.Second))

	refused := errors.New("server refused")
	tr.SetPeerHandler(func(string, PeerState) (net.Conn, error) {
		return nil, refused
	})

	_, err := m.OpenPeerConn(ctx, "remote", PeerState{Enabled: true, HomeRegionID: 1, HomeNodeID: "node-1"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConnected), "outer wrapper must be ErrNotConnected")
	assert.ErrorIs(t, err, refused)
}

func TestClose_StopsLoopAndClosesHome(t *testing.T) {
	tr := &MemTransport{}
	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, m.Start(ctx))
	require.True(t, waitForHomeConnected(t, m, 2*time.Second))
	assert.True(t, tr.HomeConnected(), "transport home should be up before close")

	require.NoError(t, m.Close())

	assert.False(t, m.HomeConnected())
	assert.False(t, m.Ready(), "Close clears selection readiness")
	assert.False(t, tr.HomeConnected(), "transport home must be closed by Close")
}

func TestClose_BeforeStartIsSafe(t *testing.T) {
	tr := &MemTransport{}
	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	// Close without Start must not panic on nil loopCancel/loopDone.
	require.NoError(t, m.Close())
	assert.False(t, m.HomeConnected())
}

func TestDormantManager_HomeConnectedStaysFalse(t *testing.T) {
	// A default NewManager() (no transport) must keep HomeConnected false even
	// after Start + UpdateMap, matching the dormant contract.
	m := NewManager()
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))
	require.NoError(t, m.Start(context.Background()))

	assert.True(t, m.Ready(), "selection readiness still works without transport")
	assert.False(t, m.HomeConnected(), "dormant manager must not report a live home connection")

	require.NoError(t, m.Close())
	assert.False(t, m.Ready())
}

// TestSetOnHomeStateChange_FiresOnConnectAndClose verifies the registered
// callback is invoked when the effective home connection state transitions
// (disconnected -> connected on the loop's first success, and connected ->
// disconnected on Close), and that it is NOT invoked for redundant states.
func TestSetOnHomeStateChange_FiresOnConnectAndClose(t *testing.T) {
	tr := &MemTransport{}
	m := newTransportManager(tr)
	require.NoError(t, m.UpdateMap(oneNodeConfig(1, "node-1")))

	var (
		mu        sync.Mutex
		calls     int
		lastState bool
	)
	// Track the state observed by the callback by re-reading the manager.
	m.SetOnHomeStateChange(func() {
		mu.Lock()
		defer mu.Unlock()
		calls++
		lastState = m.HomeConnected()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, m.Start(ctx))

	require.True(t, waitForHomeConnected(t, m, 2*time.Second))

	// Wait for the callback to observe the connected transition.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls > 0 && lastState
	}, time.Second, 2*time.Millisecond, "callback did not observe connected transition")

	connectedCalls := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}()
	beforeClose := connectedCalls

	require.NoError(t, m.Close())

	// Close must drive a disconnected transition notification.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls > beforeClose && !lastState
	}, time.Second, 2*time.Millisecond, "callback did not observe disconnected transition on Close")
}
