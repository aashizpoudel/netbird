package internal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/derp"
	"github.com/netbirdio/netbird/client/internal/peer"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

func TestConvertDERPConfig_NilYieldsDisabled(t *testing.T) {
	cfg := convertDERPConfig(nil)
	require.NotNil(t, cfg)
	assert.False(t, cfg.Enabled, "nil proto must yield a disabled config")
	assert.Nil(t, cfg.Regions)
	assert.Equal(t, derp.PriorityUnspecified, cfg.Priority)
	assert.Empty(t, cfg.SelectionPolicy.AllowedRegionIDs)
	assert.Empty(t, cfg.SelectionPolicy.DeniedRegionIDs)
}

func TestConvertDERPConfig_FullMapping(t *testing.T) {
	pkA := []byte("pub-key-a")
	pkB := []byte("pub-key-b")

	in := &mgmProto.DERPConfig{
		Enabled: true,
		Regions: []*mgmProto.DERPRegion{
			{
				Id:   10,
				Name: "region-10",
				Nodes: []*mgmProto.DERPNode{
					{
						Id:        "node-10a",
						Url:       "https://derp10a.example",
						PublicKey: pkA,
						Hostname:  "derp10a.example",
						RegionId:  10,
						StunOnly:  false,
					},
				},
			},
			{
				Id:   20,
				Name: "region-20",
				Nodes: []*mgmProto.DERPNode{
					{
						Id:        "node-20stun",
						Url:       "https://derp20stun.example",
						PublicKey: pkB,
						Hostname:  "derp20stun.example",
						RegionId:  20,
						StunOnly:  true,
					},
					{
						Id:        "node-20b",
						Url:       "https://derp20b.example",
						PublicKey: pkB,
						Hostname:  "derp20b.example",
						RegionId:  20,
						StunOnly:  false,
					},
				},
			},
		},
		SelectionPolicy: &mgmProto.DERPSelectionPolicy{
			AllowedRegionIds:  []int32{10, 20},
			DeniedRegionIds:   []int32{30},
			PreferredRegionId: 20,
			AutoSelect:        true,
		},
		Priority: mgmProto.DERPPriority_DERP_PRIORITY_BEFORE_NETBIRD_RELAY,
	}

	cfg := convertDERPConfig(in)
	require.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, derp.PriorityBeforeNetBirdRelay, cfg.Priority)

	require.Len(t, cfg.Regions, 2)
	assert.Equal(t, 10, cfg.Regions[0].ID)
	assert.Equal(t, "region-10", cfg.Regions[0].Name)
	require.Len(t, cfg.Regions[0].Nodes, 1)
	assert.Equal(t, derp.Node{
		ID:        "node-10a",
		URL:       "https://derp10a.example",
		PublicKey: pkA,
		Hostname:  "derp10a.example",
		RegionID:  10,
		STUNOnly:  false,
	}, cfg.Regions[0].Nodes[0])

	require.Len(t, cfg.Regions[1].Nodes, 2)
	assert.Equal(t, "node-20stun", cfg.Regions[1].Nodes[0].ID)
	assert.True(t, cfg.Regions[1].Nodes[0].STUNOnly)
	assert.Equal(t, "node-20b", cfg.Regions[1].Nodes[1].ID)
	assert.False(t, cfg.Regions[1].Nodes[1].STUNOnly)

	assert.Equal(t, []int{10, 20}, cfg.SelectionPolicy.AllowedRegionIDs)
	assert.Equal(t, []int{30}, cfg.SelectionPolicy.DeniedRegionIDs)
	assert.Equal(t, 20, cfg.SelectionPolicy.PreferredRegionID)
	assert.True(t, cfg.SelectionPolicy.AutoSelect)

	// Enum both directions + unspecified.
	tests := []struct {
		in  mgmProto.DERPPriority
		out derp.Priority
	}{
		{mgmProto.DERPPriority_DERP_PRIORITY_UNSPECIFIED, derp.PriorityUnspecified},
		{mgmProto.DERPPriority_DERP_PRIORITY_AFTER_NETBIRD_RELAY, derp.PriorityAfterNetBirdRelay},
		{mgmProto.DERPPriority_DERP_PRIORITY_BEFORE_NETBIRD_RELAY, derp.PriorityBeforeNetBirdRelay},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.out, convertDERPPriority(tt.in))
	}
}

func TestConvertDERPConfig_DeepCopiesByteSlices(t *testing.T) {
	pk := []byte{1, 2, 3, 4}
	in := &mgmProto.DERPConfig{
		Enabled: true,
		Regions: []*mgmProto.DERPRegion{
			{
				Id: 1,
				Nodes: []*mgmProto.DERPNode{
					{Id: "n1", RegionId: 1, PublicKey: pk},
				},
			},
		},
	}

	cfg := convertDERPConfig(in)
	require.Len(t, cfg.Regions, 1)
	require.Len(t, cfg.Regions[0].Nodes, 1)
	got := cfg.Regions[0].Nodes[0].PublicKey
	assert.Equal(t, pk, got)

	// Mutate the proto source and the returned slice; neither must affect the other.
	in.Regions[0].Nodes[0].PublicKey[0] = 9
	assert.Equal(t, byte(1), got[0], "returned PublicKey aliased proto backing array")

	got[0] = 7
	assert.Equal(t, byte(9), in.Regions[0].Nodes[0].PublicKey[0], "proto PublicKey aliased returned slice")
}

func TestDerpManagerAdapter_LocalStateConvertsAndCopies(t *testing.T) {
	pk := []byte{5, 6, 7}
	mgr := derp.NewManager()
	require.NoError(t, mgr.UpdateMap(&derp.Config{
		Enabled: true,
		Regions: []derp.Region{
			{
				ID: 7,
				Nodes: []derp.Node{
					{ID: "node-7", RegionID: 7, PublicKey: pk},
				},
			},
		},
	}))

	adapter := &derpManagerAdapter{manager: mgr}
	assert.True(t, adapter.Ready())

	state, ok := adapter.LocalState()
	require.True(t, ok)
	assert.Equal(t, peer.DERPPeerState{
		Enabled:           true,
		HomeRegionID:      7,
		HomeNodeID:        "node-7",
		HomeNodePublicKey: pk,
		Generation:        1,
	}, state)

	// Mutating the returned public key must not affect subsequent reads.
	state.HomeNodePublicKey[0] = 99
	state2, ok := adapter.LocalState()
	require.True(t, ok)
	assert.Equal(t, byte(5), state2.HomeNodePublicKey[0], "LocalState returned aliased public key")
}

func TestDerpManagerAdapter_NilManagerSafe(t *testing.T) {
	var adapter *derpManagerAdapter
	assert.False(t, adapter.Ready())
	state, ok := adapter.LocalState()
	assert.False(t, ok)
	assert.True(t, state.IsZero(), "nil adapter must yield zero peer state")

	empty := &derpManagerAdapter{}
	assert.False(t, empty.Ready())
	state, ok = empty.LocalState()
	assert.False(t, ok)
	assert.True(t, state.IsZero())

	_, err := empty.OpenPeerConn(context.Background(), "remote", peer.DERPPeerState{Enabled: true})
	assert.Error(t, err)
}

func TestHandleDERPUpdate_NilManagerNoop(t *testing.T) {
	e := &Engine{}
	assert.Nil(t, e.derpManager)

	require.NoError(t, e.handleDERPUpdate(nil))
	require.NoError(t, e.handleDERPUpdate(&mgmProto.DERPConfig{Enabled: true}))
}

func TestHandleDERPUpdate_NilUpdateDisables(t *testing.T) {
	e := &Engine{derpManager: derp.NewManager()}
	require.NoError(t, e.derpManager.UpdateMap(&derp.Config{
		Enabled: true,
		Regions: []derp.Region{
			{ID: 1, Nodes: []derp.Node{{ID: "n1", RegionID: 1, PublicKey: []byte{1}}}},
		},
	}))
	require.True(t, e.derpManager.Ready(), "precondition: manager ready after enabled config")

	require.NoError(t, e.handleDERPUpdate(nil))
	assert.False(t, e.derpManager.Ready(), "nil update must disable DERP")
}

func TestConvertToOfferAnswer_DERPPopulatedFromBody(t *testing.T) {
	pk := []byte{9, 9, 9}
	msg := &sProto.Message{
		Body: &sProto.Body{
			Type:    sProto.Body_OFFER,
			Payload: "ufrag:pwd",
			DerpPeerState: &sProto.DERPPeerState{
				Enabled:           true,
				HomeRegionId:      7,
				HomeNodeId:        "node-7",
				HomeNodePublicKey: pk,
				Generation:        42,
			},
		},
	}

	oa, err := convertToOfferAnswer(msg)
	require.NoError(t, err)
	require.NotNil(t, oa)
	assert.Equal(t, peer.DERPPeerState{
		Enabled:           true,
		HomeRegionID:      7,
		HomeNodeID:        "node-7",
		HomeNodePublicKey: pk,
		Generation:        42,
	}, oa.DERPState)

	// Mutating the proto source after conversion must not leak into the decoded state.
	msg.Body.DerpPeerState.HomeNodePublicKey[0] = 0
	assert.Equal(t, byte(9), oa.DERPState.HomeNodePublicKey[0], "DERPState public key aliased proto backing array")
}

func TestConvertToOfferAnswer_DERPAbsentYieldsZero(t *testing.T) {
	msg := &sProto.Message{
		Body: &sProto.Body{
			Type:    sProto.Body_ANSWER,
			Payload: "ufrag:pwd",
		},
	}

	oa, err := convertToOfferAnswer(msg)
	require.NoError(t, err)
	require.NotNil(t, oa)
	assert.True(t, oa.DERPState.IsZero(), "absent DERP state must decode to zero value")
}
