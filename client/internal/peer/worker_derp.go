package peer

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// DERPPeerState is the peer-layer runtime state advertised through offer/answer.
// Proto and engine integration can map to this struct without making peer depend on them.
type DERPPeerState struct {
	Enabled           bool
	HomeRegionID      int
	HomeNodeID        string
	HomeNodePublicKey []byte
	Generation        uint64
}

func (s DERPPeerState) IsZero() bool {
	return !s.Enabled && s.HomeRegionID == 0 && s.HomeNodeID == "" && len(s.HomeNodePublicKey) == 0 && s.Generation == 0
}

// DERPManager is the narrow peer-layer interface implemented by the future DERP runtime.
type DERPManager interface {
	Ready() bool
	LocalState() (DERPPeerState, bool)
	OpenPeerConn(ctx context.Context, remoteKey string, remote DERPPeerState) (net.Conn, error)
}

type DERPConnInfo struct {
	derpConn        net.Conn
	rosenpassPubKey []byte
	rosenpassAddr   string
}

type WorkerDERP struct {
	peerCtx context.Context
	log     *log.Entry
	config  ConnConfig
	conn    *Conn
	manager DERPManager
	onReady func(DERPConnInfo)

	derpConn         net.Conn
	lastRemoteState  DERPPeerState
	pendingOffer     *OfferAnswer
	derpLock         sync.Mutex
	setupInProgress  atomic.Bool
	derpSupportedOnRemotePeer atomic.Bool
}

func NewWorkerDERP(ctx context.Context, log *log.Entry, config ConnConfig, conn *Conn, manager DERPManager) *WorkerDERP {
	w := &WorkerDERP{
		peerCtx: ctx,
		log:     log,
		config:  config,
		conn:    conn,
		manager: manager,
	}
	if conn != nil {
		w.onReady = conn.onDERPConnectionIsReady
	}
	return w
}

// sameDERPHome reports whether the remote peer still advertises the same DERP
// home. Generation is intentionally ignored: a remote client restart with an
// unchanged home does not invalidate the existing stream.
func sameDERPHome(a, b DERPPeerState) bool {
	return a.HomeRegionID == b.HomeRegionID && a.HomeNodeID == b.HomeNodeID
}

func (w *WorkerDERP) OnNewOffer(remoteOfferAnswer *OfferAnswer) {
	if !w.isDERPSupported(remoteOfferAnswer) {
		w.log.Debugf("DERP is not supported by remote peer or local manager")
		w.derpSupportedOnRemotePeer.Store(false)
		return
	}
	w.derpSupportedOnRemotePeer.Store(true)

	w.derpLock.Lock()
	existing := w.derpConn
	last := w.lastRemoteState
	w.derpLock.Unlock()

	if existing != nil && sameDERPHome(last, remoteOfferAnswer.DERPState) {
		if oc, ok := existing.(interface{ IsClosed() bool }); !ok || !oc.IsClosed() {
			w.log.Debugf("handled offer by reusing existing DERP connection")
			return
		}
	}

	if !w.setupInProgress.CompareAndSwap(false, true) {
		w.derpLock.Lock()
		w.pendingOffer = remoteOfferAnswer
		w.derpLock.Unlock()
		w.log.Debugf("DERP setup in progress, queued latest offer")
		return
	}
	defer w.finishSetup()

	derpConn, err := w.manager.OpenPeerConn(w.peerCtx, w.config.Key, remoteOfferAnswer.DERPState)
	if err != nil {
		w.log.Errorf("failed to open connection via DERP: %s", err)
		return
	}

	w.derpLock.Lock()
	w.derpConn = derpConn
	w.lastRemoteState = remoteOfferAnswer.DERPState
	w.derpLock.Unlock()

	// The superseded connection, if any, is intentionally left open here: it is
	// still wired to the old wgProxy's disconnect listener, and closing it would
	// tear down the new connection. conn.setDERPProxy closes it safely later.

	w.log.Debugf("peer conn opened via DERP")
	if w.onReady == nil {
		_ = derpConn.Close()
		return
	}
	go w.onReady(DERPConnInfo{
		derpConn:        derpConn,
		rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
		rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
	})
}

// finishSetup marks the current setup attempt as done and, if a newer offer
// arrived while it was running, re-enters OnNewOffer with that offer. It must
// run after setupInProgress is cleared and must not hold derpLock while
// calling OnNewOffer to avoid deadlocking on re-entry.
func (w *WorkerDERP) finishSetup() {
	w.setupInProgress.Store(false)

	w.derpLock.Lock()
	pending := w.pendingOffer
	w.pendingOffer = nil
	w.derpLock.Unlock()

	if pending != nil {
		w.OnNewOffer(pending)
	}
}

func (w *WorkerDERP) LocalState() (DERPPeerState, bool) {
	if w.manager == nil || !w.manager.Ready() {
		return DERPPeerState{}, false
	}
	return w.manager.LocalState()
}

func (w *WorkerDERP) IsDERPConnectionSupportedWithPeer() bool {
	return w.derpSupportedOnRemotePeer.Load() && w.DERPIsSupportedLocally()
}

func (w *WorkerDERP) DERPIsSupportedLocally() bool {
	if w.manager == nil || !w.manager.Ready() {
		return false
	}
	state, ok := w.manager.LocalState()
	return ok && state.Enabled
}

func (w *WorkerDERP) CloseConn() {
	w.derpLock.Lock()
	defer w.derpLock.Unlock()

	w.pendingOffer = nil

	if w.derpConn == nil {
		return
	}

	if err := w.derpConn.Close(); err != nil {
		w.log.Warnf("failed to close DERP connection: %v", err)
	}

	w.derpConn = nil
	w.lastRemoteState = DERPPeerState{}
}

func (w *WorkerDERP) isDERPSupported(answer *OfferAnswer) bool {
	if !w.DERPIsSupportedLocally() {
		return false
	}
	return answer.DERPState.Enabled
}
