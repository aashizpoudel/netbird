package derp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

var (
	ErrDisabled       = errors.New("derp disabled")
	ErrNoHomeNode     = errors.New("derp home node unavailable")
	ErrNotConnected   = errors.New("derp not connected")
	ErrNotImplemented = errors.New("derp peer connections not implemented")
)

// Manager is the DERP client control-plane surface peer and engine integration
// can depend on while the concrete protocol implementation evolves.
type Manager interface {
	UpdateMap(config *Config) error
	Start(ctx context.Context) error
	Close() error
	Ready() bool
	LocalState() (PeerState, bool)
	OpenPeerConn(ctx context.Context, remoteKey string, remote PeerState) (net.Conn, error)
}

// ClientManager stores DERP map state and exposes the current local DERP advertisement.
// It intentionally does not depend on, or speak, a real DERP protocol yet.
type ClientManager struct {
	mu         sync.RWMutex
	config     Config
	homeRegion Region
	homeNode   Node
	started    bool
	closed     bool
	ready      bool
	generation uint64
	backoff    Backoff

	// transport is the injectable DERP transport. nil means dormant: Start runs
	// no home-connection loop and OpenPeerConn returns ErrNotImplemented (the
	// real protocol origin is deferred per Open Decision 6).
	transport Transport

	// homeConnected is the manager's view of the live home connection state,
	// maintained by the home-connection loop. It is distinct from ready (which
	// only reflects home-node selection) so existing callers that check Ready
	// after UpdateMap keep working.
	homeConnected bool

	// onHomeStateChange is invoked (without holding m.mu) when the effective
	// home connection state transitions, so callers such as the engine can
	// refresh cached status. nil means no notification. See
	// notifyHomeStateChange.
	onHomeStateChange func()

	// homeNotified is the last home-connected state delivered to
	// onHomeStateChange, used to suppress redundant notifications.
	homeNotified bool

	// loopCtx/loopCancel drive the home-connection goroutine; loopDone is
	// closed when the loop exits so Close can wait for a clean shutdown.
	loopCtx    context.Context
	loopCancel context.CancelFunc
	loopDone   chan struct{}
}

// Backoff is a small reconnect placeholder for the future protocol loop.
type Backoff struct {
	Initial time.Duration
	Max     time.Duration
}

// NewManager creates a manager with conservative reconnect placeholder values.
// The returned manager is dormant: it selects a home node on UpdateMap but does
// not maintain a live home connection until a real Transport is injected
// (Open Decision 6). Use NewManagerWithTransport for tests.
func NewManager() *ClientManager {
	return &ClientManager{
		backoff: Backoff{
			Initial: time.Second,
			Max:     30 * time.Second,
		},
	}
}

// NewManagerWithTransport creates a manager wired to the given Transport. It is
// additive to NewManager (which stays dormant) and intended for tests; a nil
// transport is equivalent to NewManager.
func NewManagerWithTransport(t Transport) *ClientManager {
	m := NewManager()
	if t != nil {
		m.transport = t
	}
	return m
}

// UpdateMap stores config and selects a deterministic home node.
func (m *ClientManager) UpdateMap(config *Config) error {
	m.mu.Lock()

	if m.closed {
		m.mu.Unlock()
		return errors.New("derp manager closed")
	}

	m.generation++
	oldHomeNode := m.homeNode
	m.config = cloneConfig(config)
	m.homeRegion = Region{}
	m.homeNode = Node{}
	m.ready = false
	transport := m.transport

	if config == nil || !config.Enabled {
		m.homeConnected = false
		m.mu.Unlock()
		if transport != nil {
			_ = transport.CloseHome()
		}
		return nil
	}

	region, node, err := selectHome(m.config)
	if err != nil {
		m.homeConnected = false
		m.mu.Unlock()
		if transport != nil {
			_ = transport.CloseHome()
		}
		return err
	}

	m.homeRegion = region
	m.homeNode = node
	m.ready = true
	closeHome := transport != nil && oldHomeNode.ID != "" && nodeMapKey(oldHomeNode) != nodeMapKey(node)
	if closeHome {
		m.homeConnected = false
	}
	m.mu.Unlock()
	if closeHome {
		_ = transport.CloseHome()
	}
	return nil
}

// Start marks the manager active. With an injected Transport it runs a
// reconnect-with-backoff home-connection loop in a goroutine (FR-13, NFR-9).
// With no transport (the default) it only marks the manager started so behavior
// stays dormant (Open Decision 6).
//
// The loop does not hold m.mu while sleeping or calling the transport: it
// snapshots the home node under lock, releases the lock, then dials.
func (m *ClientManager) Start(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("derp manager closed")
	}
	m.started = true

	if m.transport == nil {
		m.mu.Unlock()
		return nil
	}

	// Spawn the home-connection loop only once. A second Start is a no-op for
	// the loop (the manager stays started).
	if m.loopDone != nil {
		m.mu.Unlock()
		return nil
	}

	loopCtx, loopCancel := context.WithCancel(ctx)
	m.loopCtx = loopCtx
	m.loopCancel = loopCancel
	m.loopDone = make(chan struct{})
	done := m.loopDone
	transport := m.transport
	m.mu.Unlock()

	go m.runHomeLoop(loopCtx, transport, done)
	return nil
}

// runHomeLoop maintains the long-lived home connection with exponential
// backoff. It exits cleanly when loopCtx is cancelled (by Close or the parent
// context). On success it marks homeConnected and idles; on failure it sleeps
// with exponential backoff (Initial → Max, doubling each failure, reset on
// success).
func (m *ClientManager) runHomeLoop(ctx context.Context, transport Transport, done chan<- struct{}) {
	defer close(done)

	// Snapshot the backoff policy once; it is not mutated after construction.
	initial := m.backoff.Initial
	max := m.backoff.Max
	if initial <= 0 {
		initial = time.Second
	}
	if max <= 0 {
		max = 30 * time.Second
	}
	if max < initial {
		max = initial
	}

	current := initial
	// idle is the re-check interval while connected. Using Max keeps the loop
	// responsive to home-node changes / external drops without busy-looping.
	idle := max

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		m.mu.Lock()
		closed := m.closed
		enabled := m.config.Enabled
		homeNode := m.homeNode
		m.mu.Unlock()

		if closed {
			return
		}

		if !enabled || homeNode.ID == "" {
			_ = transport.CloseHome()
			m.mu.Lock()
			m.homeConnected = false
			m.mu.Unlock()
			m.notifyHomeStateChange()
			// No home selected yet; wait for UpdateMap to provide one.
			if !sleepCtx(ctx, idle) {
				return
			}
			continue
		}

		// Already connected? Re-check on an idle interval to detect drops or
		// home-node changes without busy-looping.
		if transport.HomeConnected() {
			if !sleepCtx(ctx, idle) {
				return
			}
			continue
		}

		// Mark not connected while we attempt a (re)connect.
		m.mu.Lock()
		m.homeConnected = false
		m.mu.Unlock()
		m.notifyHomeStateChange()

		err := transport.ConnectHome(ctx, homeNode)
		if err == nil {
			m.mu.Lock()
			if !m.closed {
				m.homeConnected = true
			}
			m.mu.Unlock()
			m.notifyHomeStateChange()
			current = initial // reset backoff on success
			if !sleepCtx(ctx, idle) {
				return
			}
			continue
		}

		// Failure: back off before retrying.
		if !sleepCtx(ctx, current) {
			return
		}
		current *= 2
		if current > max {
			current = max
		}
	}
}

// sleepCtx sleeps for d, returning false if ctx was cancelled during the
// sleep. A non-positive d is treated as an immediate yield.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// Close stops the manager, cancels the home-connection loop, closes the
// transport's home connection if any, and clears readiness.
func (m *ClientManager) Close() error {
	m.mu.Lock()
	m.closed = true
	m.started = false
	m.ready = false
	m.homeConnected = false
	cancel := m.loopCancel
	done := m.loopDone
	transport := m.transport
	m.loopCancel = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
		if done != nil {
			<-done
		}
	}
	if transport != nil {
		_ = transport.CloseHome()
	}
	m.notifyHomeStateChange()
	return nil
}

// Ready reports whether an enabled config has a selected home node. This
// reflects selection readiness, not the live home connection; use
// HomeConnected for the live connection state.
func (m *ClientManager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ready
}

// SetOnHomeStateChange registers a callback invoked when the home connection
// state transitions between connected and disconnected. The callback is called
// without holding the manager lock and may re-enter the manager (for example to
// read HomeConnected). It is safe to call before Start; setting nil clears a
// previously registered callback.
func (m *ClientManager) SetOnHomeStateChange(fn func()) {
	m.mu.Lock()
	m.onHomeStateChange = fn
	m.mu.Unlock()
}

// effectiveHomeConnectedLocked mirrors HomeConnected's logic assuming m.mu is
// already held. transport.HomeConnected takes the transport's own lock, which is
// distinct from m.mu and never re-enters the manager, so this does not
// self-deadlock.
func (m *ClientManager) effectiveHomeConnectedLocked() bool {
	if m.closed || !m.homeConnected || m.transport == nil {
		return false
	}
	return m.transport.HomeConnected()
}

// notifyHomeStateChange fires onHomeStateChange when the effective home
// connection state has changed since the last notification. Callers must NOT
// hold m.mu: the callback may re-enter the manager (e.g. via HomeConnected).
func (m *ClientManager) notifyHomeStateChange() {
	m.mu.Lock()
	current := m.effectiveHomeConnectedLocked()
	cb := m.onHomeStateChange
	changed := current != m.homeNotified
	if changed {
		m.homeNotified = current
	}
	m.mu.Unlock()
	if changed && cb != nil {
		cb()
	}
}

// HomeConnected reports whether the long-lived home connection is currently up.
// It is additive to Ready and only meaningful when a Transport is injected and
// Start has been called; with the default (dormant) manager it always returns
// false.
func (m *ClientManager) HomeConnected() bool {
	m.mu.RLock()
	transport := m.transport
	cached := m.homeConnected
	closed := m.closed
	defer m.mu.RUnlock()
	if closed || !cached {
		return false
	}
	if transport == nil {
		return false
	}
	return transport.HomeConnected()
}

// LocalState returns the DERP state that should be advertised to remote peers.
func (m *ClientManager) LocalState() (PeerState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.ready || !m.config.Enabled {
		return PeerState{Generation: m.generation}, false
	}

	return PeerState{
		Enabled:           true,
		HomeRegionID:      m.homeRegion.ID,
		HomeNodeID:        m.homeNode.ID,
		HomeNodePublicKey: cloneBytes(m.homeNode.PublicKey),
		Generation:        m.generation,
	}, true
}

// OpenPeerConn opens a DERP peer stream wrapped as a net.Conn (FR-16, FR-27).
//
// With no injected Transport it returns ErrNotImplemented (dormant, Open
// Decision 6). With a Transport it requires the manager to be ready, the
// remote peer to advertise DERP, and a non-empty remote key, then delegates to
// the transport.
func (m *ClientManager) OpenPeerConn(ctx context.Context, remoteKey string, remote PeerState) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	transport := m.transport
	ready := m.ready
	remoteNode, remoteNodeOK := m.resolveRemoteNodeLocked(remote)
	m.mu.RUnlock()

	if transport == nil {
		// Dormant path: preserve the original error shape so existing tests and
		// callers see ErrNotConnected + ErrNotImplemented.
		if !ready {
			return nil, fmt.Errorf("%w: %w", ErrNotConnected, ErrNoHomeNode)
		}
		if remoteKey == "" || !remote.Enabled {
			return nil, fmt.Errorf("%w: remote peer has no DERP state", ErrNotConnected)
		}
		return nil, fmt.Errorf("%w: %w", ErrNotConnected, ErrNotImplemented)
	}

	if !ready {
		return nil, fmt.Errorf("%w: %w", ErrNotConnected, ErrNoHomeNode)
	}
	if remoteKey == "" || !remote.Enabled {
		return nil, fmt.Errorf("%w: remote peer has no DERP state", ErrNotConnected)
	}
	if !remoteNodeOK {
		return nil, fmt.Errorf("%w: remote DERP home node unavailable", ErrNotConnected)
	}

	conn, err := transport.OpenPeerStream(ctx, remoteKey, remote, remoteNode)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotConnected, err)
	}
	return conn, nil
}

func (m *ClientManager) resolveRemoteNodeLocked(remote PeerState) (Node, bool) {
	if !remote.Enabled || remote.HomeRegionID == 0 || remote.HomeNodeID == "" {
		return Node{}, false
	}
	for _, region := range m.config.Regions {
		if region.ID != remote.HomeRegionID {
			continue
		}
		for _, node := range region.Nodes {
			if node.ID != remote.HomeNodeID || node.STUNOnly {
				continue
			}
			if node.RegionID != 0 && node.RegionID != region.ID {
				continue
			}
			return node, true
		}
	}
	return Node{}, false
}

func selectHome(config Config) (Region, Node, error) {
	regions := eligibleRegions(config)
	if len(regions) == 0 {
		return Region{}, Node{}, fmt.Errorf("%w: no eligible regions", ErrNoHomeNode)
	}

	if config.SelectionPolicy.PreferredRegionID != 0 {
		for _, region := range regions {
			if region.ID == config.SelectionPolicy.PreferredRegionID {
				node, ok := firstUsableNode(region)
				if !ok {
					break
				}
				return region, node, nil
			}
		}
	}

	sort.SliceStable(regions, func(i, j int) bool {
		return regions[i].ID < regions[j].ID
	})

	for _, region := range regions {
		node, ok := firstUsableNode(region)
		if ok {
			return region, node, nil
		}
	}

	return Region{}, Node{}, fmt.Errorf("%w: no usable nodes", ErrNoHomeNode)
}

func eligibleRegions(config Config) []Region {
	allowed := make(map[int]struct{}, len(config.SelectionPolicy.AllowedRegionIDs))
	for _, id := range config.SelectionPolicy.AllowedRegionIDs {
		allowed[id] = struct{}{}
	}
	denied := make(map[int]struct{}, len(config.SelectionPolicy.DeniedRegionIDs))
	for _, id := range config.SelectionPolicy.DeniedRegionIDs {
		denied[id] = struct{}{}
	}

	regions := make([]Region, 0, len(config.Regions))
	for _, region := range config.Regions {
		if _, ok := denied[region.ID]; ok {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[region.ID]; !ok {
				continue
			}
		}
		regions = append(regions, region)
	}
	return regions
}

func firstUsableNode(region Region) (Node, bool) {
	nodes := append([]Node(nil), region.Nodes...)
	sort.SliceStable(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	for _, node := range nodes {
		if node.STUNOnly {
			continue
		}
		if node.RegionID != 0 && node.RegionID != region.ID {
			continue
		}
		return node, true
	}
	return Node{}, false
}

func cloneConfig(config *Config) Config {
	if config == nil {
		return Config{}
	}

	cloned := *config
	cloned.SelectionPolicy.AllowedRegionIDs = append([]int(nil), config.SelectionPolicy.AllowedRegionIDs...)
	cloned.SelectionPolicy.DeniedRegionIDs = append([]int(nil), config.SelectionPolicy.DeniedRegionIDs...)
	cloned.Regions = make([]Region, 0, len(config.Regions))
	for _, region := range config.Regions {
		clonedRegion := region
		clonedRegion.Nodes = make([]Node, 0, len(region.Nodes))
		for _, node := range region.Nodes {
			clonedNode := node
			clonedNode.PublicKey = cloneBytes(node.PublicKey)
			clonedRegion.Nodes = append(clonedRegion.Nodes, clonedNode)
		}
		cloned.Regions = append(cloned.Regions, clonedRegion)
	}
	return cloned
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return append([]byte(nil), value...)
}
