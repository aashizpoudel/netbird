package peer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeDERPWGIface struct {
	mu                  sync.Mutex
	proxies             []*fakeDERPProxy
	updatePeerCalls     int
	removeEndpointCalls int
	lastEndpoint        *net.UDPAddr
	lastRemovedKey      string
	stats               map[string]configurer.WGStats
}

func (f *fakeDERPWGIface) UpdatePeer(_ string, _ []netip.Prefix, _ time.Duration, endpoint *net.UDPAddr, _ *wgtypes.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updatePeerCalls++
	if endpoint != nil {
		cp := *endpoint
		f.lastEndpoint = &cp
	} else {
		f.lastEndpoint = nil
	}
	return nil
}

func (f *fakeDERPWGIface) RemovePeer(string) error {
	return nil
}

func (f *fakeDERPWGIface) GetStats() (map[string]configurer.WGStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stats := make(map[string]configurer.WGStats, len(f.stats))
	for key, value := range f.stats {
		stats[key] = value
	}
	return stats, nil
}

func (f *fakeDERPWGIface) GetProxy() wgproxy.Proxy {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.proxies) == 0 {
		panic("fakeDERPWGIface.GetProxy called with no queued proxy")
	}
	proxy := f.proxies[0]
	f.proxies = f.proxies[1:]
	return proxy
}

func (f *fakeDERPWGIface) Address() wgaddr.Address {
	addr, _ := wgaddr.ParseWGAddress("100.64.0.1/16")
	return addr
}

func (f *fakeDERPWGIface) RemoveEndpointAddress(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeEndpointCalls++
	f.lastRemovedKey = key
	f.lastEndpoint = nil
	return nil
}

func (f *fakeDERPWGIface) snapshot() (updates int, removes int, endpoint *net.UDPAddr, removedKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updatePeerCalls, f.removeEndpointCalls, f.lastEndpoint, f.lastRemovedKey
}

type fakeDERPProxy struct {
	mu                 sync.Mutex
	endpoint           *net.UDPAddr
	addTurnConnCalls   int
	workCalls          int
	pauseCalls         int
	redirectCalls      int
	closeCalls         int
	disconnectListener func()
	remoteConn         net.Conn
}

func newFakeDERPProxy(port int) *fakeDERPProxy {
	return &fakeDERPProxy{endpoint: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}}
}

func (p *fakeDERPProxy) AddTurnConn(_ context.Context, _ *net.UDPAddr, remoteConn net.Conn) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addTurnConnCalls++
	p.remoteConn = remoteConn
	return nil
}

func (p *fakeDERPProxy) EndpointAddr() *net.UDPAddr {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := *p.endpoint
	return &cp
}

func (p *fakeDERPProxy) Work() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.workCalls++
}

func (p *fakeDERPProxy) Pause() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pauseCalls++
}

func (p *fakeDERPProxy) RedirectAs(*net.UDPAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirectCalls++
}

func (p *fakeDERPProxy) CloseConn() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeCalls++
	return nil
}

func (p *fakeDERPProxy) SetDisconnectListener(disconnected func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.disconnectListener = disconnected
}

func (p *fakeDERPProxy) InjectPacket([]byte) error {
	return nil
}

func (p *fakeDERPProxy) snapshot() (work int, pause int, redirects int, closes int, addTurnConn int, listener func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.workCalls, p.pauseCalls, p.redirectCalls, p.closeCalls, p.addTurnConnCalls, p.disconnectListener
}

func TestConnActiveDERPConfiguresProxyEndpointStatusAndConnected(t *testing.T) {
	h := newDERPConnSwitchHarness(t, conntype.None)
	defer h.close()
	proxy := h.queueProxy(31001)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	h.conn.onDERPConnectionIsReady(DERPConnInfo{
		derpConn:        local,
		rosenpassPubKey: []byte("rp-key"),
		rosenpassAddr:   "rp.example:33080",
	})

	work, _, _, _, addTurnConn, listener := proxy.snapshot()
	if addTurnConn != 1 {
		t.Fatalf("expected proxy AddTurnConn once, got %d", addTurnConn)
	}
	if work != 1 {
		t.Fatalf("expected active DERP proxy Work once, got %d", work)
	}
	if listener == nil {
		t.Fatal("expected DERP disconnect listener to be configured")
	}
	if h.conn.currentConnPriority != conntype.DERP {
		t.Fatalf("expected DERP priority, got %s", h.conn.currentConnPriority)
	}
	if h.conn.statusDERP.Get() != worker.StatusConnected {
		t.Fatalf("expected DERP worker status connected, got %s", h.conn.statusDERP)
	}
	updates, _, endpoint, _ := h.iface.snapshot()
	if updates != 1 {
		t.Fatalf("expected one WireGuard endpoint update, got %d", updates)
	}
	if endpoint == nil || endpoint.Port != 31001 {
		t.Fatalf("unexpected WireGuard endpoint: %v", endpoint)
	}
	if h.connectedCalls != 1 || string(h.connectedRosenpassKey) != "rp-key" || h.connectedRosenpassAddr != "rp.example:33080" {
		t.Fatalf("unexpected onConnected call: calls=%d key=%q addr=%s", h.connectedCalls, string(h.connectedRosenpassKey), h.connectedRosenpassAddr)
	}
	state := h.peerState(t)
	if state.ConnStatus != StatusConnected || !state.Relayed || state.RelayServerAddress == "" || !state.RosenpassEnabled {
		t.Fatalf("unexpected active DERP peer status: %+v", state)
	}
}

func TestConnDERPStandbyWhileICEActiveStoresProxyAndStatus(t *testing.T) {
	h := newDERPConnSwitchHarness(t, conntype.ICEP2P)
	defer h.close()
	h.conn.statusICE.SetConnected()
	proxy := h.queueProxy(31002)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	h.conn.onDERPConnectionIsReady(DERPConnInfo{derpConn: local})

	work, _, _, _, addTurnConn, _ := proxy.snapshot()
	if addTurnConn != 1 {
		t.Fatalf("expected proxy AddTurnConn once, got %d", addTurnConn)
	}
	if work != 0 {
		t.Fatalf("standby DERP proxy should not Work, got %d", work)
	}
	updates, _, endpoint, _ := h.iface.snapshot()
	if updates != 0 || endpoint != nil {
		t.Fatalf("standby DERP should not reconfigure endpoint, updates=%d endpoint=%v", updates, endpoint)
	}
	if h.conn.wgProxyDERP != proxy {
		t.Fatal("expected DERP proxy to be stored for standby fallback")
	}
	if h.conn.currentConnPriority != conntype.ICEP2P {
		t.Fatalf("expected ICE priority to remain active, got %s", h.conn.currentConnPriority)
	}
	if h.conn.statusDERP.Get() != worker.StatusConnected {
		t.Fatalf("expected DERP standby status connected, got %s", h.conn.statusDERP)
	}
	if h.connectedCalls != 0 {
		t.Fatalf("standby DERP should not call onConnected, got %d calls", h.connectedCalls)
	}
}

func TestConnICEToDERPFallbackUsesStandbyProxy(t *testing.T) {
	h := newDERPConnSwitchHarness(t, conntype.ICEP2P)
	defer h.close()
	h.conn.statusICE.SetConnected()
	proxy := h.queueProxy(31003)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	h.conn.onDERPConnectionIsReady(DERPConnInfo{derpConn: local, rosenpassPubKey: []byte("standby-rp")})
	h.conn.onICEStateDisconnected(false)

	work, _, _, _, _, _ := proxy.snapshot()
	if work != 1 {
		t.Fatalf("expected fallback DERP proxy Work once, got %d", work)
	}
	if h.conn.currentConnPriority != conntype.DERP {
		t.Fatalf("expected priority to switch to DERP, got %s", h.conn.currentConnPriority)
	}
	if h.conn.statusICE.Get() != worker.StatusDisconnected {
		t.Fatalf("expected ICE status disconnected, got %s", h.conn.statusICE)
	}
	updates, removes, endpoint, _ := h.iface.snapshot()
	if updates != 1 {
		t.Fatalf("expected one endpoint switch to DERP, got %d", updates)
	}
	if removes != 0 {
		t.Fatalf("sessionChanged=false should not remove endpoint before switch, got %d removes", removes)
	}
	if endpoint == nil || endpoint.Port != 31003 {
		t.Fatalf("unexpected fallback DERP endpoint: %v", endpoint)
	}
	state := h.peerState(t)
	if state.ConnStatus != StatusConnected || !state.Relayed || state.ConnectionType != "DERP" || state.RelayServerAddress == "" {
		t.Fatalf("unexpected fallback DERP peer status: %+v", state)
	}
}

func TestConnRelayToDERPFallbackUsesStandbyProxyAndUpdatesStatus(t *testing.T) {
	h := newDERPConnSwitchHarness(t, conntype.None)
	defer h.close()
	relayProxy := h.queueProxy(31004)
	relayLocal, relayRemote := net.Pipe()
	defer relayLocal.Close()
	defer relayRemote.Close()
	derpProxy := h.queueProxy(31005)
	derpLocal, derpRemote := net.Pipe()
	defer derpLocal.Close()
	defer derpRemote.Close()

	h.conn.onRelayConnectionIsReady(RelayConnInfo{relayedConn: relayLocal})
	_, _, _, _, _, relayListener := relayProxy.snapshot()
	if relayListener == nil {
		t.Fatal("expected Relay disconnect listener")
	}
	h.conn.onDERPConnectionIsReady(DERPConnInfo{derpConn: derpLocal, rosenpassPubKey: []byte("standby-rp")})

	relayListener()

	work, _, _, _, _, _ := derpProxy.snapshot()
	if work != 1 {
		t.Fatalf("expected fallback DERP proxy Work once, got %d", work)
	}
	if h.conn.currentConnPriority != conntype.DERP {
		t.Fatalf("expected priority to switch to DERP, got %s", h.conn.currentConnPriority)
	}
	if h.conn.statusRelay.Get() != worker.StatusDisconnected {
		t.Fatalf("expected Relay status disconnected, got %s", h.conn.statusRelay)
	}
	updates, removes, endpoint, _ := h.iface.snapshot()
	if updates != 2 {
		t.Fatalf("expected Relay configure and DERP switch endpoint updates, got %d", updates)
	}
	if removes != 0 {
		t.Fatalf("Relay fallback should not remove endpoint before switch, got %d removes", removes)
	}
	if endpoint == nil || endpoint.Port != 31005 {
		t.Fatalf("unexpected fallback DERP endpoint: %v", endpoint)
	}
	state := h.peerState(t)
	if state.ConnStatus != StatusConnected || !state.Relayed || state.ConnectionType != "DERP" || state.RelayServerAddress == "" {
		t.Fatalf("unexpected Relay to DERP fallback peer status: %+v", state)
	}
}

func TestConnActiveDERPDisconnectClearsProxyEndpointStatusAndRelayAddress(t *testing.T) {
	h := newDERPConnSwitchHarness(t, conntype.None)
	defer h.close()
	proxy := h.queueProxy(31006)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	h.conn.onDERPConnectionIsReady(DERPConnInfo{derpConn: local, rosenpassPubKey: []byte("rp-key")})
	_, _, _, _, _, listener := proxy.snapshot()
	if listener == nil {
		t.Fatal("expected DERP disconnect listener")
	}

	listener()

	_, _, _, closes, _, _ := proxy.snapshot()
	if closes != 1 {
		t.Fatalf("expected DERP proxy CloseConn once, got %d", closes)
	}
	if h.conn.wgProxyDERP != nil {
		t.Fatal("expected DERP proxy to be cleared")
	}
	if h.conn.currentConnPriority != conntype.None {
		t.Fatalf("expected priority reset to none, got %s", h.conn.currentConnPriority)
	}
	if h.conn.statusDERP.Get() != worker.StatusDisconnected {
		t.Fatalf("expected DERP status disconnected, got %s", h.conn.statusDERP)
	}
	_, removes, _, removedKey := h.iface.snapshot()
	if removes != 1 || removedKey != h.conn.config.WgConfig.RemoteKey {
		t.Fatalf("expected endpoint removal for remote key, removes=%d key=%s", removes, removedKey)
	}
	state := h.peerState(t)
	if state.Relayed || state.RelayServerAddress != "" {
		t.Fatalf("expected relayed status cleared after DERP disconnect: %+v", state)
	}
}

type derpConnSwitchHarness struct {
	t                      *testing.T
	conn                   *Conn
	iface                  *fakeDERPWGIface
	cancel                 context.CancelFunc
	connectedCalls         int
	connectedRosenpassKey  []byte
	connectedRosenpassAddr string
	connectedWireGuardKey  string
	connectedWireGuardIP   string
}

func newDERPConnSwitchHarness(t *testing.T, priority conntype.ConnPriority) *derpConnSwitchHarness {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	logger := log.NewEntry(log.StandardLogger())
	remoteKey := "remote-key"
	allowedIP := netip.MustParsePrefix("100.64.0.2/32")
	iface := &fakeDERPWGIface{
		stats: map[string]configurer.WGStats{
			remoteKey: {LastHandshake: time.Now()},
		},
	}
	statusRecorder := NewRecorder("https://mgm")
	if err := statusRecorder.AddPeer(remoteKey, "peer.example", "100.64.0.2", ""); err != nil {
		t.Fatal(err)
	}
	dumpState := &stateDump{log: logger}
	conn := &Conn{
		Log: logger,
		ctx: ctx,
		config: ConnConfig{
			Key:      remoteKey,
			LocalKey: "zz-local-key",
			WgConfig: WgConfig{
				WgListenPort: 51820,
				RemoteKey:    remoteKey,
				WgInterface:  iface,
				AllowedIps:   []netip.Prefix{allowedIP},
			},
		},
		statusRecorder:      statusRecorder,
		statusRelay:         worker.NewAtomicStatus(),
		statusDERP:          worker.NewAtomicStatus(),
		statusICE:           worker.NewAtomicStatus(),
		currentConnPriority: priority,
		dumpState:           dumpState,
		metricsStages:       &MetricsStages{},
	}
	conn.endpointUpdater = NewEndpointUpdater(logger, conn.config.WgConfig, true)
	conn.wgWatcher = NewWGWatcher(logger, iface, remoteKey, dumpState)
	conn.guard = guard.NewGuard(logger, func() guard.ConnStatus { return guard.ConnStatusConnected }, time.Second, nil)

	h := &derpConnSwitchHarness{
		t:      t,
		conn:   conn,
		iface:  iface,
		cancel: cancel,
	}
	conn.onConnected = func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string) {
		h.connectedCalls++
		h.connectedWireGuardKey = remoteWireGuardKey
		h.connectedRosenpassKey = append([]byte(nil), remoteRosenpassPubKey...)
		h.connectedWireGuardIP = wireGuardIP
		h.connectedRosenpassAddr = remoteRosenpassAddr
	}
	return h
}

func (h *derpConnSwitchHarness) queueProxy(port int) *fakeDERPProxy {
	h.t.Helper()
	proxy := newFakeDERPProxy(port)
	h.iface.mu.Lock()
	h.iface.proxies = append(h.iface.proxies, proxy)
	h.iface.mu.Unlock()
	return proxy
}

func (h *derpConnSwitchHarness) peerState(t *testing.T) State {
	t.Helper()
	state, err := h.conn.statusRecorder.GetPeer(h.conn.config.Key)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (h *derpConnSwitchHarness) close() {
	h.cancel()
	h.conn.wgWatcherWg.Wait()
}
