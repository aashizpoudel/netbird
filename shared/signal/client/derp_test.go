package client

import (
	"testing"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestMarshalCredential_IncludesDERPStateWhenSet(t *testing.T) {
	myKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	remoteKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	derp := &proto.DERPPeerState{
		Enabled:           true,
		Capable:           true,
		HomeRegionId:      5,
		HomeNodeId:        "n5",
		HomeNodePublicKey: []byte{1, 2},
		Generation:        9,
	}

	msg, err := MarshalCredential(myKey, remoteKey.PublicKey().String(), CredentialPayload{
		Type:         proto.Body_OFFER,
		WgListenPort: 12345,
		Credential:   &Credential{UFrag: "u", Pwd: "p"},
		DERPState:    derp,
	})
	if err != nil {
		t.Fatalf("MarshalCredential: %v", err)
	}

	got := msg.GetBody().GetDerpPeerState()
	if got == nil {
		t.Fatal("expected DerpPeerState to be present on the body, got nil")
	}
	if got.GetEnabled() != true {
		t.Errorf("Enabled = %v, want true", got.GetEnabled())
	}
	if got.GetCapable() != true {
		t.Errorf("Capable = %v, want true", got.GetCapable())
	}
	if got.GetHomeRegionId() != 5 {
		t.Errorf("HomeRegionId = %d, want 5", got.GetHomeRegionId())
	}
	if got.GetHomeNodeId() != "n5" {
		t.Errorf("HomeNodeId = %q, want %q", got.GetHomeNodeId(), "n5")
	}
	if string(got.GetHomeNodePublicKey()) != string([]byte{1, 2}) {
		t.Errorf("HomeNodePublicKey = %v, want [1 2]", got.GetHomeNodePublicKey())
	}
	if got.GetGeneration() != 9 {
		t.Errorf("Generation = %d, want 9", got.GetGeneration())
	}
}

func TestMarshalCredential_OmitsDERPStateWhenNil(t *testing.T) {
	myKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	remoteKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	msg, err := MarshalCredential(myKey, remoteKey.PublicKey().String(), CredentialPayload{
		Type:       proto.Body_OFFER,
		Credential: &Credential{UFrag: "u", Pwd: "p"},
		DERPState:  nil,
	})
	if err != nil {
		t.Fatalf("MarshalCredential: %v", err)
	}

	if got := msg.GetBody().GetDerpPeerState(); got != nil {
		t.Fatalf("expected DerpPeerState to be absent for backward compatibility, got %+v", got)
	}
}
