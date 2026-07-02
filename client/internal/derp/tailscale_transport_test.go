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
	"go4.org/mem"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	tsderp "tailscale.com/derp"
	tskey "tailscale.com/types/key"
)

type fakeDERPClient struct {
	self tskey.NodePublic

	mu       sync.Mutex
	closed   bool
	connects int
	sent     []fakeSentPacket
	pongs    [][8]byte

	recvCh chan tsderp.ReceivedMessage
}

type fakeSentPacket struct {
	dst  tskey.NodePublic
	data []byte
}

func newFakeDERPClient(self tskey.NodePublic) *fakeDERPClient {
	return &fakeDERPClient{
		self:   self,
		recvCh: make(chan tsderp.ReceivedMessage, 16),
	}
}

func (f *fakeDERPClient) Connect(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	f.connects++
	return nil
}

func (f *fakeDERPClient) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeDERPClient) Send(dst tskey.NodePublic, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	f.sent = append(f.sent, fakeSentPacket{dst: dst, data: append([]byte(nil), data...)})
	return nil
}

func (f *fakeDERPClient) Recv() (tsderp.ReceivedMessage, error) {
	for {
		f.mu.Lock()
		closed := f.closed
		f.mu.Unlock()
		if closed {
			return nil, io.EOF
		}
		select {
		case msg := <-f.recvCh:
			return msg, nil
		case <-time.After(time.Millisecond):
		}
	}
}

func (f *fakeDERPClient) SendPong(data [8]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	f.pongs = append(f.pongs, data)
	return nil
}

func (f *fakeDERPClient) ServerPublicKey() tskey.NodePublic { return f.self }
func (f *fakeDERPClient) SelfPublicKey() tskey.NodePublic   { return f.self }

func (f *fakeDERPClient) recv(msg tsderp.ReceivedMessage) {
	f.recvCh <- msg
}

func (f *fakeDERPClient) sentPackets() []fakeSentPacket {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeSentPacket, len(f.sent))
	copy(out, f.sent)
	return out
}

func (f *fakeDERPClient) sentPongs() [][8]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][8]byte, len(f.pongs))
	copy(out, f.pongs)
	return out
}

func TestTailscaleTransportPacketConnSendsAndReceivesByPeerKey(t *testing.T) {
	localPriv, localPub := mustWGKeyPair(t)
	remotePriv, remotePub := mustWGKeyPair(t)
	_, otherPub := mustWGKeyPair(t)
	_ = localPriv
	_ = remotePriv

	clients := map[string]*fakeDERPClient{
		"home":   newFakeDERPClient(nodePublicFromWGKey(localPub)),
		"remote": newFakeDERPClient(nodePublicFromWGKey(remotePub)),
	}
	tr := newTailscaleTransportForTest(func(node Node) (tailscaleDERPClient, error) {
		c := clients[node.ID]
		if c == nil {
			return nil, errors.New("unexpected node")
		}
		return c, nil
	})

	ctx := context.Background()
	require.NoError(t, tr.ConnectHome(ctx, Node{ID: "home", URL: "https://home.example/derp", RegionID: 1}))
	require.True(t, tr.HomeConnected())

	conn, err := tr.OpenPeerStream(ctx, remotePub.String(), PeerState{
		Enabled:      true,
		HomeRegionID: 2,
		HomeNodeID:   "remote",
	}, Node{ID: "remote", URL: "https://remote.example/derp", RegionID: 2})
	require.NoError(t, err)
	defer conn.Close()

	n, err := conn.Write([]byte("packet-out"))
	require.NoError(t, err)
	assert.Equal(t, len("packet-out"), n)

	sent := clients["remote"].sentPackets()
	require.Len(t, sent, 1)
	assert.Equal(t, 0, sent[0].dst.Compare(nodePublicFromWGKey(remotePub)))
	assert.Equal(t, "packet-out", string(sent[0].data))

	clients["home"].recv(tsderp.ReceivedPacket{
		Source: nodePublicFromWGKey(otherPub),
		Data:   []byte("ignored"),
	})
	clients["home"].recv(tsderp.ReceivedPacket{
		Source: nodePublicFromWGKey(remotePub),
		Data:   []byte("packet-in"),
	})

	buf := make([]byte, 32)
	n, err = conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "packet-in", string(buf[:n]))
}

func TestTailscaleTransportHandlesPingAndClose(t *testing.T) {
	_, localPub := mustWGKeyPair(t)
	_, remotePub := mustWGKeyPair(t)

	home := newFakeDERPClient(nodePublicFromWGKey(localPub))
	remote := newFakeDERPClient(nodePublicFromWGKey(remotePub))
	tr := newTailscaleTransportForTest(func(node Node) (tailscaleDERPClient, error) {
		switch node.ID {
		case "home":
			return home, nil
		case "remote":
			return remote, nil
		default:
			return nil, errors.New("unexpected node")
		}
	})

	ctx := context.Background()
	require.NoError(t, tr.ConnectHome(ctx, Node{ID: "home", URL: "https://home.example/derp", RegionID: 1}))
	conn, err := tr.OpenPeerStream(ctx, remotePub.String(), PeerState{
		Enabled:      true,
		HomeRegionID: 2,
		HomeNodeID:   "remote",
	}, Node{ID: "remote", URL: "https://remote.example/derp", RegionID: 2})
	require.NoError(t, err)

	home.recv(tsderp.PingMessage{1, 2, 3, 4, 5, 6, 7, 8})
	require.Eventually(t, func() bool {
		return len(home.sentPongs()) == 1
	}, time.Second, time.Millisecond)
	assert.Equal(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, home.sentPongs()[0])

	require.NoError(t, tr.CloseHome())
	assert.False(t, tr.HomeConnected())

	_, err = conn.Write([]byte("after-close"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, net.ErrClosed))

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, net.ErrClosed))
}

func mustWGKeyPair(t *testing.T) (wgtypes.Key, wgtypes.Key) {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return priv, priv.PublicKey()
}

func nodePublicFromWGKey(k wgtypes.Key) tskey.NodePublic {
	raw := [32]byte(k)
	return tskey.NodePublicFromRaw32(mem.B(raw[:]))
}

func TestBufferedPacketFlushedOnRegister(t *testing.T) {
	_, localPub := mustWGKeyPair(t)
	_, remotePub := mustWGKeyPair(t)

	home := newFakeDERPClient(nodePublicFromWGKey(localPub))
	remote := newFakeDERPClient(nodePublicFromWGKey(remotePub))
	tr := newTailscaleTransportForTest(func(node Node) (tailscaleDERPClient, error) {
		switch node.ID {
		case "home":
			return home, nil
		case "remote":
			return remote, nil
		default:
			return nil, errors.New("unexpected node")
		}
	})

	ctx := context.Background()
	require.NoError(t, tr.ConnectHome(ctx, Node{ID: "home", URL: "https://home.example/derp", RegionID: 1}))

	// Dispatch a packet for the remote peer before any packetConn is registered
	home.recv(tsderp.ReceivedPacket{
		Source: nodePublicFromWGKey(remotePub),
		Data:   []byte("buffered-packet"),
	})

	// Give the receive loop time to dispatch the packet
	time.Sleep(time.Millisecond * 10)

	// Now open a stream for that remote peer
	conn, err := tr.OpenPeerStream(ctx, remotePub.String(), PeerState{
		Enabled:      true,
		HomeRegionID: 2,
		HomeNodeID:   "remote",
	}, Node{ID: "remote", URL: "https://remote.example/derp", RegionID: 2})
	require.NoError(t, err)
	defer conn.Close()

	// Set a read deadline to avoid hanging indefinitely
	conn.SetReadDeadline(time.Now().Add(time.Second))

	// The buffered packet should be flushed to the new connection
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "buffered-packet", string(buf[:n]))
}
