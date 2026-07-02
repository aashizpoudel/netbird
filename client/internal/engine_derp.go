package internal

import (
	"context"
	"fmt"
	"net"

	"github.com/netbirdio/netbird/client/internal/derp"
	"github.com/netbirdio/netbird/client/internal/peer"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

// derpManagerAdapter bridges the real derp.ClientManager to the narrow
// peer.DERPManager interface. It exists because peer keeps its own
// DERPPeerState struct so the peer package does not have to depend on the
// derp runtime package.
type derpManagerAdapter struct {
	manager *derp.ClientManager
}

func (a *derpManagerAdapter) Ready() bool {
	if a == nil || a.manager == nil {
		return false
	}
	return a.manager.Ready()
}

func (a *derpManagerAdapter) LocalState() (peer.DERPPeerState, bool) {
	if a == nil || a.manager == nil {
		return peer.DERPPeerState{}, false
	}
	state, ok := a.manager.LocalState()
	if !ok {
		return peer.DERPPeerState{}, false
	}
	return peer.DERPPeerState{
		Enabled:           state.Enabled,
		HomeRegionID:      state.HomeRegionID,
		HomeNodeID:        state.HomeNodeID,
		HomeNodePublicKey: append([]byte(nil), state.HomeNodePublicKey...),
		Generation:        state.Generation,
	}, true
}

func (a *derpManagerAdapter) OpenPeerConn(ctx context.Context, remoteKey string, remote peer.DERPPeerState) (net.Conn, error) {
	if a == nil || a.manager == nil {
		return nil, fmt.Errorf("derp manager unavailable")
	}
	return a.manager.OpenPeerConn(ctx, remoteKey, derp.PeerState{
		Enabled:           remote.Enabled,
		HomeRegionID:      remote.HomeRegionID,
		HomeNodeID:        remote.HomeNodeID,
		HomeNodePublicKey: append([]byte(nil), remote.HomeNodePublicKey...),
		Generation:        remote.Generation,
	})
}

// convertDERPConfig maps the management protobuf DERP config into the internal
// derp package model. A nil proto config yields a disabled internal config so
// old management servers (and accounts without DERP) keep the manager dormant.
func convertDERPConfig(in *mgmProto.DERPConfig) *derp.Config {
	if in == nil {
		return &derp.Config{}
	}

	cfg := &derp.Config{
		Enabled:  in.GetEnabled(),
		Priority: convertDERPPriority(in.GetPriority()),
	}

	for _, region := range in.GetRegions() {
		if region == nil {
			continue
		}
		out := derp.Region{
			ID:   int(region.GetId()),
			Name: region.GetName(),
		}
		for _, node := range region.GetNodes() {
			if node == nil {
				continue
			}
			out.Nodes = append(out.Nodes, derp.Node{
				ID:        node.GetId(),
				URL:       node.GetUrl(),
				PublicKey: append([]byte(nil), node.GetPublicKey()...),
				Hostname:  node.GetHostname(),
				RegionID:  int(node.GetRegionId()),
				STUNOnly:  node.GetStunOnly(),
			})
		}
		cfg.Regions = append(cfg.Regions, out)
	}

	if sp := in.GetSelectionPolicy(); sp != nil {
		cfg.SelectionPolicy = derp.SelectionPolicy{
			AllowedRegionIDs:  append([]int(nil), intsFromInt32(sp.GetAllowedRegionIds())...),
			DeniedRegionIDs:   append([]int(nil), intsFromInt32(sp.GetDeniedRegionIds())...),
			PreferredRegionID: int(sp.GetPreferredRegionId()),
			AutoSelect:        sp.GetAutoSelect(),
		}
	}

	return cfg
}

func convertDERPPriority(p mgmProto.DERPPriority) derp.Priority {
	switch p {
	case mgmProto.DERPPriority_DERP_PRIORITY_AFTER_NETBIRD_RELAY:
		return derp.PriorityAfterNetBirdRelay
	case mgmProto.DERPPriority_DERP_PRIORITY_BEFORE_NETBIRD_RELAY:
		return derp.PriorityBeforeNetBirdRelay
	default:
		return derp.PriorityUnspecified
	}
}

func intsFromInt32(in []int32) []int {
	if len(in) == 0 {
		return nil
	}
	out := make([]int, 0, len(in))
	for _, v := range in {
		out = append(out, int(v))
	}
	return out
}

// handleDERPUpdate applies a management-supplied DERP config to the local
// manager. nil config disables DERP without producing an error so the engine
// keeps working with management servers that never send DERP fields.
func (e *Engine) handleDERPUpdate(update *mgmProto.DERPConfig) error {
	if e.derpManager == nil {
		return nil
	}
	if err := e.derpManager.UpdateMap(convertDERPConfig(update)); err != nil {
		return fmt.Errorf("update derp map: %w", err)
	}
	return nil
}

// convertSignalDERPPeerState maps the signal protobuf DERP peer state into the
// peer-layer struct used by offer/answer handling. A nil proto state yields the
// zero value so peer.DERPPeerState.IsZero() returns true for old peers that do
// not advertise DERP. The public key slice is copied so callers cannot mutate
// the proto's backing array through the returned struct.
func convertSignalDERPPeerState(in *sProto.DERPPeerState) peer.DERPPeerState {
	if in == nil {
		return peer.DERPPeerState{}
	}
	return peer.DERPPeerState{
		Enabled:           in.GetEnabled(),
		HomeRegionID:      int(in.GetHomeRegionId()),
		HomeNodeID:        in.GetHomeNodeId(),
		HomeNodePublicKey: append([]byte(nil), in.GetHomeNodePublicKey()...),
		Generation:        in.GetGeneration(),
	}
}
