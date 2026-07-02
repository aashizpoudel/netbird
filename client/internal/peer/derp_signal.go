package peer

import (
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

// derpPeerStateToProto converts the peer-layer DERP state into the signal proto
// form used inside offer/answer credentials. It returns nil for zero state so
// that offers/answers sent to peers that predate DERP support stay
// byte-identical (the proto field is omitted entirely rather than serialized
// as an empty message).
func derpPeerStateToProto(s DERPPeerState) *sProto.DERPPeerState {
	if s.IsZero() {
		return nil
	}
	// A peer that advertises DERP as enabled is implicitly capable, so mirror
	// enabled into the proto's capable field for older/vanilla consumers that
	// only inspect capable.
	return &sProto.DERPPeerState{
		Enabled:           s.Enabled,
		Capable:           s.Enabled,
		HomeRegionId:      int32(s.HomeRegionID),
		HomeNodeId:        s.HomeNodeID,
		HomeNodePublicKey: append([]byte(nil), s.HomeNodePublicKey...),
		Generation:        s.Generation,
	}
}

// derpPeerStateFromProto converts a signal proto DERP state back into the
// peer-layer struct. A nil proto (the case for messages from peers that do not
// advertise DERP) yields the zero value. The HomeNodePublicKey slice is copied
// so callers can mutate the returned struct without aliasing the proto's
// backing array.
func derpPeerStateFromProto(p *sProto.DERPPeerState) DERPPeerState {
	if p == nil {
		return DERPPeerState{}
	}
	return DERPPeerState{
		Enabled:           p.GetEnabled(),
		HomeRegionID:      int(p.GetHomeRegionId()),
		HomeNodeID:        p.GetHomeNodeId(),
		HomeNodePublicKey: append([]byte(nil), p.GetHomeNodePublicKey()...),
		Generation:        p.GetGeneration(),
	}
}
