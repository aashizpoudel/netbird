package peer

import (
	"testing"

	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

func TestDerpPeerStateToProto_ZeroReturnsNil(t *testing.T) {
	if got := derpPeerStateToProto(DERPPeerState{}); got != nil {
		t.Fatalf("expected nil proto for zero state, got %+v", got)
	}
}

func TestDerpPeerStateToProto_RoundTripFields(t *testing.T) {
	in := DERPPeerState{
		Enabled:           true,
		HomeRegionID:      5,
		HomeNodeID:        "n5",
		HomeNodePublicKey: []byte{1, 2, 3, 4},
		Generation:        9,
	}
	got := derpPeerStateToProto(in)
	if got == nil {
		t.Fatal("expected non-nil proto for non-zero state")
	}
	if got.GetEnabled() != true {
		t.Errorf("Enabled = %v, want true", got.GetEnabled())
	}
	if got.GetCapable() != true {
		t.Errorf("Capable = %v, want true (mirrored from enabled)", got.GetCapable())
	}
	if got.GetHomeRegionId() != 5 {
		t.Errorf("HomeRegionId = %d, want 5", got.GetHomeRegionId())
	}
	if got.GetHomeNodeId() != "n5" {
		t.Errorf("HomeNodeId = %q, want %q", got.GetHomeNodeId(), "n5")
	}
	if string(got.GetHomeNodePublicKey()) != string(in.HomeNodePublicKey) {
		t.Errorf("HomeNodePublicKey = %v, want %v", got.GetHomeNodePublicKey(), in.HomeNodePublicKey)
	}
	if got.GetGeneration() != 9 {
		t.Errorf("Generation = %d, want 9", got.GetGeneration())
	}
}

func TestDerpPeerStateFromProto_NilReturnsZero(t *testing.T) {
	got := derpPeerStateFromProto(nil)
	if !got.IsZero() {
		t.Fatalf("expected zero DERPPeerState for nil proto, got %+v", got)
	}
}

func TestDerpPeerStateFromProto_CopiesBytes(t *testing.T) {
	p := &sProto.DERPPeerState{
		Enabled:           true,
		HomeRegionId:      7,
		HomeNodeId:        "n7",
		HomeNodePublicKey: []byte{9, 8, 7},
		Generation:        42,
	}

	first := derpPeerStateFromProto(p)
	first.HomeNodePublicKey[0] = 0xFF

	second := derpPeerStateFromProto(p)
	if second.HomeNodePublicKey[0] == 0xFF {
		t.Fatal("mutating returned slice leaked into the proto backing array; expected an independent copy")
	}
	if second.Enabled != true || second.HomeRegionID != 7 || second.HomeNodeID != "n7" || second.Generation != 42 {
		t.Errorf("field copy mismatch: %+v", second)
	}
}
