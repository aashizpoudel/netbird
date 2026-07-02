package peer

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/derp"
	log "github.com/sirupsen/logrus"
)

type fakeDERPManager struct {
	ready      bool
	localState DERPPeerState
	localOK    bool
	openConn   net.Conn
	openErr    error

	openCalled int
	remoteKey  string
	remote     DERPPeerState
}

func (m *fakeDERPManager) Ready() bool {
	return m.ready
}

func (m *fakeDERPManager) LocalState() (DERPPeerState, bool) {
	return m.localState, m.localOK
}

func (m *fakeDERPManager) OpenPeerConn(_ context.Context, remoteKey string, remote DERPPeerState) (net.Conn, error) {
	m.openCalled++
	m.remoteKey = remoteKey
	m.remote = remote
	if m.openErr != nil {
		return nil, m.openErr
	}
	return m.openConn, nil
}

type clientManagerDERPAdapter struct {
	manager *derp.ClientManager
}

func (a clientManagerDERPAdapter) Ready() bool {
	return a.manager.Ready()
}

func (a clientManagerDERPAdapter) LocalState() (DERPPeerState, bool) {
	state, ok := a.manager.LocalState()
	if !ok {
		return DERPPeerState{}, false
	}
	return DERPPeerState{
		Enabled:           state.Enabled,
		HomeRegionID:      state.HomeRegionID,
		HomeNodeID:        state.HomeNodeID,
		HomeNodePublicKey: state.HomeNodePublicKey,
		Generation:        state.Generation,
	}, true
}

func (a clientManagerDERPAdapter) OpenPeerConn(ctx context.Context, remoteKey string, remote DERPPeerState) (net.Conn, error) {
	return a.manager.OpenPeerConn(ctx, remoteKey, derp.PeerState{
		Enabled:           remote.Enabled,
		HomeRegionID:      remote.HomeRegionID,
		HomeNodeID:        remote.HomeNodeID,
		HomeNodePublicKey: remote.HomeNodePublicKey,
		Generation:        remote.Generation,
	})
}

func waitForDERPHomeConnected(t *testing.T, manager *derp.ClientManager) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if manager.HomeConnected() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("timed out waiting for DERP home connection")
}

func TestHandshakerBuildOfferAnswerIncludesDERPState(t *testing.T) {
	localState := DERPPeerState{
		Enabled:           true,
		HomeRegionID:      10,
		HomeNodeID:        "node-a",
		HomeNodePublicKey: []byte("node-key"),
		Generation:        42,
	}
	manager := &fakeDERPManager{
		ready:      true,
		localState: localState,
		localOK:    true,
	}
	workerDERP := NewWorkerDERP(context.Background(), log.NewEntry(log.StandardLogger()), ConnConfig{}, nil, manager)
	handshaker := &Handshaker{
		config: ConnConfig{
			LocalWgPort: 51820,
		},
		derp: workerDERP,
	}

	offer := handshaker.buildOfferAnswer()

	if offer.DERPState.Enabled != localState.Enabled ||
		offer.DERPState.HomeRegionID != localState.HomeRegionID ||
		offer.DERPState.HomeNodeID != localState.HomeNodeID ||
		offer.DERPState.Generation != localState.Generation ||
		string(offer.DERPState.HomeNodePublicKey) != string(localState.HomeNodePublicKey) {
		t.Fatalf("unexpected DERP state in offer: %+v", offer.DERPState)
	}
}

func TestWorkerDERPOpensPeerConnWhenBothSidesSupportDERP(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	remoteState := DERPPeerState{
		Enabled:      true,
		HomeRegionID: 11,
		HomeNodeID:   "node-b",
		Generation:   7,
	}
	manager := &fakeDERPManager{
		ready:      true,
		localState: DERPPeerState{Enabled: true, HomeRegionID: 10, HomeNodeID: "node-a"},
		localOK:    true,
		openConn:   local,
	}
	workerDERP := NewWorkerDERP(context.Background(), log.NewEntry(log.StandardLogger()), ConnConfig{Key: "peer-key"}, nil, manager)

	readyCh := make(chan DERPConnInfo, 1)
	workerDERP.onReady = func(info DERPConnInfo) {
		readyCh <- info
	}

	workerDERP.OnNewOffer(&OfferAnswer{DERPState: remoteState})

	select {
	case info := <-readyCh:
		if info.derpConn != local {
			t.Fatal("ready callback received unexpected DERP connection")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DERP ready callback")
	}

	if manager.openCalled != 1 {
		t.Fatalf("expected one OpenPeerConn call, got %d", manager.openCalled)
	}
	if manager.remoteKey != "peer-key" {
		t.Fatalf("unexpected remote key: %s", manager.remoteKey)
	}
	if manager.remote.Enabled != remoteState.Enabled ||
		manager.remote.HomeRegionID != remoteState.HomeRegionID ||
		manager.remote.HomeNodeID != remoteState.HomeNodeID ||
		manager.remote.Generation != remoteState.Generation {
		t.Fatalf("unexpected remote DERP state: %+v", manager.remote)
	}
	if !workerDERP.IsDERPConnectionSupportedWithPeer() {
		t.Fatal("expected worker to mark DERP supported with peer")
	}
}

func TestWorkerDERPSkipsOpenWhenUnsupported(t *testing.T) {
	manager := &fakeDERPManager{
		ready:      true,
		localState: DERPPeerState{Enabled: true},
		localOK:    true,
		openErr:    errors.New("should not be called"),
	}
	workerDERP := NewWorkerDERP(context.Background(), log.NewEntry(log.StandardLogger()), ConnConfig{Key: "peer-key"}, nil, manager)

	workerDERP.OnNewOffer(&OfferAnswer{})

	if manager.openCalled != 0 {
		t.Fatalf("expected OpenPeerConn not to be called, got %d calls", manager.openCalled)
	}
	if workerDERP.IsDERPConnectionSupportedWithPeer() {
		t.Fatal("expected DERP to be unsupported with peer")
	}
}

func TestWorkerDERPWithClientManagerMemTransport(t *testing.T) {
	transport := &derp.MemTransport{}
	manager := derp.NewManagerWithTransport(transport)
	requireNoError(t, manager.UpdateMap(&derp.Config{
		Enabled: true,
		Regions: []derp.Region{
			{
				ID:   1,
				Name: "test-region",
				Nodes: []derp.Node{
					{
						ID:        "local-node",
						URL:       "mem://local-node",
						PublicKey: []byte("local-node-key"),
						RegionID:  1,
					},
				},
			},
			// Remote peers' home nodes must exist in the local map: the
			// manager resolves the remote home node (URL/public key) from the
			// local DERP map before delegating to the transport.
			{
				ID:   7,
				Name: "remote-region",
				Nodes: []derp.Node{
					{
						ID:        "remote-node",
						URL:       "mem://remote-node",
						PublicKey: []byte("remote-node-key"),
						RegionID:  7,
					},
				},
			},
			{
				ID:   8,
				Name: "manager-region",
				Nodes: []derp.Node{
					{
						ID:        "manager-node",
						URL:       "mem://manager-node",
						PublicKey: []byte("manager-node-key"),
						RegionID:  8,
					},
				},
			},
		},
		SelectionPolicy: derp.SelectionPolicy{AutoSelect: true},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requireNoError(t, manager.Start(ctx))
	defer manager.Close()
	waitForDERPHomeConnected(t, manager)

	observedCh := make(chan observedOpen, 3)
	transport.SetPeerHandler(func(remoteKey string, remote derp.PeerState) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		observedCh <- observedOpen{
			remoteKey: remoteKey,
			remote:    remote,
			server:    serverSide,
		}
		return clientSide, nil
	})

	workerDERP := NewWorkerDERP(ctx, log.NewEntry(log.StandardLogger()), ConnConfig{Key: "peer-key"}, nil, clientManagerDERPAdapter{manager: manager})
	readyCh := make(chan DERPConnInfo, 1)
	workerDERP.onReady = func(info DERPConnInfo) {
		readyCh <- info
	}

	remoteState := DERPPeerState{
		Enabled:           true,
		HomeRegionID:      7,
		HomeNodeID:        "remote-node",
		HomeNodePublicKey: []byte("remote-node-key"),
		Generation:        9,
	}
	workerDERP.OnNewOffer(&OfferAnswer{
		DERPState:       remoteState,
		RosenpassPubKey: []byte("remote-rosenpass-key"),
		RosenpassAddr:   "127.0.0.1:33080",
	})

	info := waitForDERPReady(t, readyCh)
	if string(info.rosenpassPubKey) != "remote-rosenpass-key" {
		t.Fatalf("unexpected Rosenpass key: %q", string(info.rosenpassPubKey))
	}
	if info.rosenpassAddr != "127.0.0.1:33080" {
		t.Fatalf("unexpected Rosenpass address: %s", info.rosenpassAddr)
	}
	if !workerDERP.IsDERPConnectionSupportedWithPeer() {
		t.Fatal("expected worker to mark DERP supported with peer")
	}

	workerOpen := waitForDERPOpen(t, observedCh)
	defer workerOpen.server.Close()
	if workerOpen.remoteKey != "peer-key" {
		t.Fatalf("unexpected worker remote key: %s", workerOpen.remoteKey)
	}
	if workerOpen.remote.HomeNodeID != remoteState.HomeNodeID ||
		workerOpen.remote.HomeRegionID != remoteState.HomeRegionID ||
		workerOpen.remote.Generation != remoteState.Generation ||
		string(workerOpen.remote.HomeNodePublicKey) != string(remoteState.HomeNodePublicKey) {
		t.Fatalf("unexpected worker remote DERP state: %+v", workerOpen.remote)
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := workerOpen.server.Write([]byte("x"))
		writeErr <- err
	}()
	buf := make([]byte, 1)
	if _, err := info.derpConn.Read(buf); err != nil {
		t.Fatalf("worker pipe read failed: %v", err)
	}
	requireNoError(t, <-writeErr)
	if string(buf) != "x" {
		t.Fatalf("unexpected worker pipe payload: %q", string(buf))
	}

	directManagerConn, err := manager.OpenPeerConn(ctx, "manager-peer", derp.PeerState{Enabled: true, HomeRegionID: 8, HomeNodeID: "manager-node"})
	requireNoError(t, err)
	defer directManagerConn.Close()
	directManagerOpen := waitForDERPOpen(t, observedCh)
	defer directManagerOpen.server.Close()
	if directManagerOpen.remoteKey != "manager-peer" || directManagerOpen.remote.HomeNodeID != "manager-node" {
		t.Fatalf("manager OpenPeerConn did not propagate remote key/state: %+v", directManagerOpen)
	}

	directTransportConn, err := transport.OpenPeerStream(ctx, "transport-peer", derp.PeerState{Enabled: true, HomeRegionID: 9, HomeNodeID: "transport-node"}, derp.Node{ID: "transport-node", RegionID: 9})
	requireNoError(t, err)
	defer directTransportConn.Close()
	directTransportOpen := waitForDERPOpen(t, observedCh)
	defer directTransportOpen.server.Close()
	if directTransportOpen.remoteKey != "transport-peer" || directTransportOpen.remote.HomeNodeID != "transport-node" {
		t.Fatalf("transport OpenPeerStream did not propagate remote key/state: %+v", directTransportOpen)
	}

	workerOpen.server.SetReadDeadline(time.Now().Add(time.Second))
	workerDERP.CloseConn()
	n, err := workerOpen.server.Read(buf)
	if err == nil || n != 0 {
		t.Fatalf("expected CloseConn to close pipe, read n=%d err=%v", n, err)
	}
	if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected pipe close error: %v", err)
	}
}

func waitForDERPReady(t *testing.T, readyCh <-chan DERPConnInfo) DERPConnInfo {
	t.Helper()

	select {
	case info := <-readyCh:
		return info
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DERP ready callback")
		return DERPConnInfo{}
	}
}

func waitForDERPOpen(t *testing.T, observedCh <-chan observedOpen) observedOpen {
	t.Helper()

	select {
	case observed := <-observedCh:
		return observed
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DERP transport open")
		return observedOpen{}
	}
}

type observedOpen struct {
	remoteKey string
	remote    derp.PeerState
	server    net.Conn
}

func requireNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}
