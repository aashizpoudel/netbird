package derp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go4.org/mem"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	tsderp "tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	tskey "tailscale.com/types/key"
)

const packetConnBuffer = 128

type tailscaleDERPClient interface {
	Connect(context.Context) error
	Close() error
	Send(tskey.NodePublic, []byte) error
	Recv() (tsderp.ReceivedMessage, error)
	SendPong([8]byte) error
	ServerPublicKey() tskey.NodePublic
	SelfPublicKey() tskey.NodePublic
}

type tailscaleDERPClientFactory func(node Node) (tailscaleDERPClient, error)

// TailscaleTransport relays NetBird WireGuard packets through Tailscale DERP
// servers using the existing WireGuard node key as the DERP node identity.
type TailscaleTransport struct {
	mu sync.Mutex

	privateKey tskey.NodePrivate
	factory    tailscaleDERPClientFactory

	home *derpClientEntry

	clients map[string]*derpClientEntry
	conns   map[string]map[*packetConn]struct{}
	closed  bool
}

type derpClientEntry struct {
	node      Node
	client    tailscaleDERPClient
	home      bool
	closeOnce sync.Once
	done      chan struct{}
}

// NewTailscaleTransport creates a production DERP transport from NetBird's
// existing WireGuard private key. No separate DERP identity is generated.
func NewTailscaleTransport(wgPrivateKey wgtypes.Key) (*TailscaleTransport, error) {
	raw := [32]byte(wgPrivateKey)
	privateKey := tskey.NodePrivateFromRaw32(mem.B(raw[:]))
	if privateKey.IsZero() {
		return nil, errors.New("derp tailscale transport: zero private key")
	}

	tr := &TailscaleTransport{
		privateKey: privateKey,
		clients:    make(map[string]*derpClientEntry),
		conns:      make(map[string]map[*packetConn]struct{}),
	}
	netMon := netmon.NewStatic()
	tr.factory = func(node Node) (tailscaleDERPClient, error) {
		if node.URL == "" {
			return nil, fmt.Errorf("node %q has no DERP URL", node.ID)
		}
		c, err := derphttp.NewClient(privateKey, node.URL, tailscaleLogf, netMon)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return tr, nil
}

func newTailscaleTransportForTest(factory tailscaleDERPClientFactory) *TailscaleTransport {
	return &TailscaleTransport{
		factory: factory,
		clients: make(map[string]*derpClientEntry),
		conns:   make(map[string]map[*packetConn]struct{}),
	}
}

func tailscaleLogf(format string, args ...any) {
	logrus.Debugf("derp: "+format, args...)
}

func (t *TailscaleTransport) ConnectHome(ctx context.Context, home Node) error {
	entry, err := t.clientForNode(ctx, home, true)
	if err != nil {
		return err
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		entry.close()
		return net.ErrClosed
	}
	t.home = entry
	t.mu.Unlock()
	return nil
}

func (t *TailscaleTransport) CloseHome() error {
	t.mu.Lock()
	entries := make([]*derpClientEntry, 0, len(t.clients))
	for _, entry := range t.clients {
		entries = append(entries, entry)
	}
	t.home = nil
	t.clients = make(map[string]*derpClientEntry)
	conns := t.allConnsLocked()
	t.conns = make(map[string]map[*packetConn]struct{})
	t.mu.Unlock()

	for _, conn := range conns {
		conn.closeFromTransport()
	}
	for _, entry := range entries {
		entry.close()
	}
	return nil
}

func (t *TailscaleTransport) HomeConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.home != nil && !t.closed
}

func (t *TailscaleTransport) OpenPeerStream(ctx context.Context, remoteKey string, remote PeerState, remoteNode Node) (net.Conn, error) {
	remotePub, err := parseNodePublicKey(remoteKey)
	if err != nil {
		return nil, err
	}
	if remoteNode.ID == "" || remoteNode.URL == "" {
		return nil, fmt.Errorf("remote DERP node %q in region %d has no URL", remote.HomeNodeID, remote.HomeRegionID)
	}

	entry, err := t.clientForNode(ctx, remoteNode, false)
	if err != nil {
		return nil, err
	}

	conn := newPacketConn(t, entry, remotePub)
	t.registerConn(remotePub, conn)
	logrus.Debugf("derp[trace]: OpenPeerStream for %s created conn %p", remotePub.ShortString(), conn)
	return conn, nil
}

func (t *TailscaleTransport) clientForNode(ctx context.Context, node Node, home bool) (*derpClientEntry, error) {
	key := nodeMapKey(node)
	if key == "" {
		return nil, errors.New("DERP node has no ID or URL")
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	if entry := t.clients[key]; entry != nil {
		if home {
			entry.home = true
			t.home = entry
		}
		t.mu.Unlock()
		return entry, nil
	}
	t.mu.Unlock()

	client, err := t.factory(node)
	if err != nil {
		return nil, err
	}
	if err := client.Connect(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}

	entry := &derpClientEntry{
		node:   node,
		client: client,
		home:   home,
		done:   make(chan struct{}),
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		entry.close()
		return nil, net.ErrClosed
	}
	if existing := t.clients[key]; existing != nil {
		t.mu.Unlock()
		entry.close()
		return existing, nil
	}
	t.clients[key] = entry
	if home {
		t.home = entry
	}
	t.mu.Unlock()

	go t.recvLoop(entry, key)
	return entry, nil
}

func (t *TailscaleTransport) recvLoop(entry *derpClientEntry, clientKey string) {
	defer func() {
		t.mu.Lock()
		if t.clients[clientKey] == entry {
			delete(t.clients, clientKey)
		}
		if t.home == entry {
			t.home = nil
		}
		conns := t.removeConnsForEntryLocked(entry)
		t.mu.Unlock()

		for _, conn := range conns {
			conn.closeFromTransport()
		}
		entry.close()
		close(entry.done)
	}()

	for {
		msg, err := entry.client.Recv()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				logrus.Debugf("derp: receive loop for node %q stopped: %v", entry.node.ID, err)
			}
			logrus.Debugf("derp[trace]: recvLoop for node %q exiting", entry.node.ID)
			return
		}

		switch m := msg.(type) {
		case tsderp.ReceivedPacket:
			data := append([]byte(nil), m.Data...)
			logrus.Debugf("derp[trace]: recvLoop got ReceivedPacket from %s len=%d", m.Source.ShortString(), len(data))
			t.dispatchPacket(m.Source, data)
		case tsderp.PingMessage:
			if err := entry.client.SendPong([8]byte(m)); err != nil && !errors.Is(err, net.ErrClosed) {
				logrus.Debugf("derp: failed to send pong to node %q: %v", entry.node.ID, err)
			}
		default:
			logrus.Tracef("derp: ignoring %T from node %q", msg, entry.node.ID)
		}
	}
}

func (t *TailscaleTransport) dispatchPacket(source tskey.NodePublic, data []byte) {
	t.mu.Lock()
	key := nodePublicMapKey(source)
	conns := make([]*packetConn, 0, len(t.conns[key]))
	for conn := range t.conns[key] {
		conns = append(conns, conn)
	}
	t.mu.Unlock()

	if len(conns) == 0 {
		logrus.Warnf("derp[trace]: dispatchPacket from %s len=%d DROP (no registered packetConn)", source.ShortString(), len(data))
		return
	}
	logrus.Debugf("derp[trace]: dispatchPacket from %s len=%d -> %d conn(s)", source.ShortString(), len(data), len(conns))
	for _, conn := range conns {
		conn.deliver(data)
	}
}

func (t *TailscaleTransport) registerConn(remote tskey.NodePublic, conn *packetConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := nodePublicMapKey(remote)
	if t.conns[key] == nil {
		t.conns[key] = make(map[*packetConn]struct{})
	}
	n := len(t.conns[key])
	t.conns[key][conn] = struct{}{}
	logrus.Debugf("derp[trace]: registerConn %s conn %p (now %d conn(s) for peer)", remote.ShortString(), conn, n+1)
}

func (t *TailscaleTransport) unregisterConn(remote tskey.NodePublic, conn *packetConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := nodePublicMapKey(remote)
	delete(t.conns[key], conn)
	remaining := len(t.conns[key])
	if remaining == 0 {
		delete(t.conns, key)
	}
	logrus.Debugf("derp[trace]: unregisterConn %s conn %p (now %d conn(s) for peer)", remote.ShortString(), conn, remaining)
}

func (t *TailscaleTransport) allConnsLocked() []*packetConn {
	var conns []*packetConn
	for _, set := range t.conns {
		for conn := range set {
			conns = append(conns, conn)
		}
	}
	return conns
}

func (t *TailscaleTransport) removeConnsForEntryLocked(entry *derpClientEntry) []*packetConn {
	var conns []*packetConn
	for key, set := range t.conns {
		for conn := range set {
			if conn.entry == entry || entry.home {
				conns = append(conns, conn)
				delete(set, conn)
			}
		}
		if len(set) == 0 {
			delete(t.conns, key)
		}
	}
	return conns
}

func (e *derpClientEntry) close() {
	e.closeOnce.Do(func() {
		_ = e.client.Close()
	})
}

type packetConn struct {
	transport *TailscaleTransport
	entry     *derpClientEntry
	remote    tskey.NodePublic

	inbox   chan []byte
	closeCh chan struct{}
	once    sync.Once

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func newPacketConn(transport *TailscaleTransport, entry *derpClientEntry, remote tskey.NodePublic) *packetConn {
	return &packetConn{
		transport: transport,
		entry:     entry,
		remote:    remote,
		inbox:     make(chan []byte, packetConnBuffer),
		closeCh:   make(chan struct{}),
	}
}

func (c *packetConn) Read(b []byte) (int, error) {
	timer, timerCh := c.deadlineTimer(true)
	if timer != nil {
		defer timer.Stop()
	}

	select {
	case pkt := <-c.inbox:
		return copy(b, pkt), nil
	case <-c.closeCh:
		return 0, net.ErrClosed
	case <-timerCh:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *packetConn) Write(b []byte) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	if c.deadlineExceeded(false) {
		return 0, os.ErrDeadlineExceeded
	}
	pkt := append([]byte(nil), b...)
	if err := c.entry.client.Send(c.remote, pkt); err != nil {
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	return len(b), nil
}

func (c *packetConn) Close() error {
	c.once.Do(func() {
		c.transport.unregisterConn(c.remote, c)
		close(c.closeCh)
	})
	return nil
}

func (c *packetConn) closeFromTransport() {
	c.once.Do(func() {
		close(c.closeCh)
	})
}

func (c *packetConn) LocalAddr() net.Addr {
	return derpAddr("derp-local")
}

func (c *packetConn) RemoteAddr() net.Addr {
	return derpAddr(derpRemoteAddrString(c.entry.node, c.remote))
}

// derpRemoteAddrString renders the relay address reported by netbird status.
// It surfaces the DERP server the stream is relayed through (the remote peer's
// home node hostname from the DERP map), falling back to the node URL, ID, or
// finally the peer's short public key so the value is never empty.
func derpRemoteAddrString(node Node, remote tskey.NodePublic) string {
	switch {
	case node.Hostname != "":
		return "derp-via-" + node.Hostname
	case node.URL != "":
		return "derp-via-" + node.URL
	case node.ID != "":
		return "derp-via-" + node.ID
	default:
		return "derp-" + remote.ShortString()
	}
}

func (c *packetConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func (c *packetConn) deliver(data []byte) {
	select {
	case <-c.closeCh:
		logrus.Debugf("derp[trace]: deliver to %s DROP (closed)", c.remote.ShortString())
	case c.inbox <- data:
		logrus.Debugf("derp[trace]: deliver to %s len=%d OK (inbox len=%d)", c.remote.ShortString(), len(data), len(c.inbox))
	default:
		logrus.Warnf("derp[trace]: deliver to %s DROP (inbox full)", c.remote.ShortString())
	}
}

func (c *packetConn) isClosed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *packetConn) deadlineExceeded(read bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := c.writeDeadline
	if read {
		deadline = c.readDeadline
	}
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

func (c *packetConn) deadlineTimer(read bool) (*time.Timer, <-chan time.Time) {
	c.mu.Lock()
	deadline := c.readDeadline
	if !read {
		deadline = c.writeDeadline
	}
	c.mu.Unlock()
	if deadline.IsZero() {
		return nil, nil
	}
	d := time.Until(deadline)
	if d <= 0 {
		timer := time.NewTimer(0)
		return timer, timer.C
	}
	timer := time.NewTimer(d)
	return timer, timer.C
}

type derpAddr string

func (a derpAddr) Network() string { return "derp" }
func (a derpAddr) String() string  { return string(a) }

func parseNodePublicKey(value string) (tskey.NodePublic, error) {
	wgKey, err := wgtypes.ParseKey(value)
	if err != nil {
		return tskey.NodePublic{}, fmt.Errorf("parse remote WireGuard public key: %w", err)
	}
	raw := [32]byte(wgKey)
	pub := tskey.NodePublicFromRaw32(mem.B(raw[:]))
	if pub.IsZero() {
		return tskey.NodePublic{}, errors.New("remote WireGuard public key is zero")
	}
	return pub, nil
}

func nodeMapKey(node Node) string {
	if node.RegionID != 0 || node.ID != "" {
		return fmt.Sprintf("%d/%s", node.RegionID, node.ID)
	}
	return node.URL
}

func nodePublicMapKey(pub tskey.NodePublic) string {
	return string(pub.AppendTo(nil))
}
