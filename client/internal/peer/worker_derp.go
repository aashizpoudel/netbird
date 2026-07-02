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

	derpConn net.Conn
	derpLock sync.Mutex

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

func (w *WorkerDERP) OnNewOffer(remoteOfferAnswer *OfferAnswer) {
	if !w.isDERPSupported(remoteOfferAnswer) {
		w.log.Debugf("DERP is not supported by remote peer or local manager")
		w.derpSupportedOnRemotePeer.Store(false)
		return
	}
	w.derpSupportedOnRemotePeer.Store(true)

	derpConn, err := w.manager.OpenPeerConn(w.peerCtx, w.config.Key, remoteOfferAnswer.DERPState)
	if err != nil {
		w.log.Errorf("failed to open connection via DERP: %s", err)
		return
	}

	w.derpLock.Lock()
	w.derpConn = derpConn
	w.derpLock.Unlock()

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
	if w.derpConn == nil {
		return
	}

	if err := w.derpConn.Close(); err != nil {
		w.log.Warnf("failed to close DERP connection: %v", err)
	}
}

func (w *WorkerDERP) isDERPSupported(answer *OfferAnswer) bool {
	if !w.DERPIsSupportedLocally() {
		return false
	}
	return answer.DERPState.Enabled
}
