package derp

import (
	"context"
	"errors"
	"testing"
)

func TestUpdateMapSelectsDeterministicHome(t *testing.T) {
	manager := NewManager()

	err := manager.UpdateMap(&Config{
		Enabled: true,
		Regions: []Region{
			{
				ID: 20,
				Nodes: []Node{
					{ID: "node-z", RegionID: 20, PublicKey: []byte{9}},
				},
			},
			{
				ID: 10,
				Nodes: []Node{
					{ID: "node-b", RegionID: 10, PublicKey: []byte{2}},
					{ID: "node-a", RegionID: 10, PublicKey: []byte{1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("UpdateMap returned error: %v", err)
	}

	state, ok := manager.LocalState()
	if !ok {
		t.Fatal("LocalState returned not ready")
	}
	if !manager.Ready() {
		t.Fatal("manager is not ready")
	}
	if state.HomeRegionID != 10 || state.HomeNodeID != "node-a" {
		t.Fatalf("selected home = region %d node %q, want region 10 node-a", state.HomeRegionID, state.HomeNodeID)
	}
}

func TestUpdateMapDisabledConfigClearsReadiness(t *testing.T) {
	manager := NewManager()
	if err := manager.UpdateMap(oneNodeConfig(1, "node-1")); err != nil {
		t.Fatalf("UpdateMap returned error: %v", err)
	}

	if err := manager.UpdateMap(&Config{Enabled: false}); err != nil {
		t.Fatalf("UpdateMap disabled returned error: %v", err)
	}

	state, ok := manager.LocalState()
	if ok {
		t.Fatal("LocalState returned ready for disabled config")
	}
	if state.Enabled {
		t.Fatal("disabled local state advertised enabled")
	}
	if manager.Ready() {
		t.Fatal("manager is ready after disabled config")
	}
}

func TestPreferredRegionSelection(t *testing.T) {
	manager := NewManager()

	err := manager.UpdateMap(&Config{
		Enabled: true,
		Regions: []Region{
			{ID: 10, Nodes: []Node{{ID: "node-10", RegionID: 10}}},
			{ID: 20, Nodes: []Node{{ID: "node-20", RegionID: 20}}},
		},
		SelectionPolicy: SelectionPolicy{PreferredRegionID: 20},
	})
	if err != nil {
		t.Fatalf("UpdateMap returned error: %v", err)
	}

	state, ok := manager.LocalState()
	if !ok {
		t.Fatal("LocalState returned not ready")
	}
	if state.HomeRegionID != 20 || state.HomeNodeID != "node-20" {
		t.Fatalf("selected home = region %d node %q, want region 20 node-20", state.HomeRegionID, state.HomeNodeID)
	}
}

func TestAllowedRegionFiltering(t *testing.T) {
	manager := NewManager()

	err := manager.UpdateMap(&Config{
		Enabled: true,
		Regions: []Region{
			{ID: 10, Nodes: []Node{{ID: "node-10", RegionID: 10}}},
			{ID: 20, Nodes: []Node{{ID: "node-20", RegionID: 20}}},
			{ID: 30, Nodes: []Node{{ID: "node-30", RegionID: 30}}},
		},
		SelectionPolicy: SelectionPolicy{AllowedRegionIDs: []int{30, 20}},
	})
	if err != nil {
		t.Fatalf("UpdateMap returned error: %v", err)
	}

	state, ok := manager.LocalState()
	if !ok {
		t.Fatal("LocalState returned not ready")
	}
	if state.HomeRegionID != 20 || state.HomeNodeID != "node-20" {
		t.Fatalf("selected home = region %d node %q, want lowest allowed region 20 node-20", state.HomeRegionID, state.HomeNodeID)
	}
}

func TestDeniedRegionFiltering(t *testing.T) {
	manager := NewManager()

	err := manager.UpdateMap(&Config{
		Enabled: true,
		Regions: []Region{
			{ID: 10, Nodes: []Node{{ID: "node-10", RegionID: 10}}},
			{ID: 20, Nodes: []Node{{ID: "node-20", RegionID: 20}}},
			{ID: 30, Nodes: []Node{{ID: "node-30", RegionID: 30}}},
		},
		SelectionPolicy: SelectionPolicy{DeniedRegionIDs: []int{10, 20}},
	})
	if err != nil {
		t.Fatalf("UpdateMap returned error: %v", err)
	}

	state, ok := manager.LocalState()
	if !ok {
		t.Fatal("LocalState returned not ready")
	}
	if state.HomeRegionID != 30 || state.HomeNodeID != "node-30" {
		t.Fatalf("selected home = region %d node %q, want only non-denied region 30 node-30", state.HomeRegionID, state.HomeNodeID)
	}
}

func TestDeniedRegionOverridesPreferred(t *testing.T) {
	manager := NewManager()

	err := manager.UpdateMap(&Config{
		Enabled: true,
		Regions: []Region{
			{ID: 10, Nodes: []Node{{ID: "node-10", RegionID: 10}}},
			{ID: 20, Nodes: []Node{{ID: "node-20", RegionID: 20}}},
		},
		SelectionPolicy: SelectionPolicy{
			DeniedRegionIDs:   []int{10},
			PreferredRegionID: 10,
		},
	})
	if err != nil {
		t.Fatalf("UpdateMap returned error: %v", err)
	}

	state, ok := manager.LocalState()
	if !ok {
		t.Fatal("LocalState returned not ready")
	}
	if state.HomeRegionID != 20 || state.HomeNodeID != "node-20" {
		t.Fatalf("selected home = region %d node %q, want fallback to region 20 when preferred 10 is denied", state.HomeRegionID, state.HomeNodeID)
	}
}

func TestUpdateMapNoNodeError(t *testing.T) {
	manager := NewManager()

	err := manager.UpdateMap(&Config{
		Enabled: true,
		Regions: []Region{
			{ID: 10, Nodes: []Node{{ID: "stun-only", RegionID: 10, STUNOnly: true}}},
		},
	})
	if !errors.Is(err, ErrNoHomeNode) {
		t.Fatalf("UpdateMap error = %v, want ErrNoHomeNode", err)
	}
	if manager.Ready() {
		t.Fatal("manager is ready after no-node error")
	}
}

func TestLocalStateGenerationAndCopy(t *testing.T) {
	manager := NewManager()
	config := oneNodeConfig(7, "node-7")
	config.Regions[0].Nodes[0].PublicKey = []byte{1, 2, 3}

	if err := manager.UpdateMap(config); err != nil {
		t.Fatalf("UpdateMap returned error: %v", err)
	}

	state, ok := manager.LocalState()
	if !ok {
		t.Fatal("LocalState returned not ready")
	}
	if !state.Enabled || state.HomeRegionID != 7 || state.HomeNodeID != "node-7" || state.Generation != 1 {
		t.Fatalf("unexpected local state: %+v", state)
	}

	state.HomeNodePublicKey[0] = 9
	nextState, ok := manager.LocalState()
	if !ok {
		t.Fatal("LocalState returned not ready on second call")
	}
	if nextState.HomeNodePublicKey[0] != 1 {
		t.Fatalf("LocalState returned aliased public key, got %d want 1", nextState.HomeNodePublicKey[0])
	}
}

func TestOpenPeerConnNotConnected(t *testing.T) {
	manager := NewManager()
	if err := manager.UpdateMap(oneNodeConfig(1, "node-1")); err != nil {
		t.Fatalf("UpdateMap returned error: %v", err)
	}

	conn, err := manager.OpenPeerConn(context.Background(), "remote-key", PeerState{Enabled: true, HomeRegionID: 1, HomeNodeID: "remote"})
	if conn != nil {
		t.Fatalf("OpenPeerConn returned conn %v, want nil", conn)
	}
	if !errors.Is(err, ErrNotConnected) || !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("OpenPeerConn error = %v, want ErrNotConnected and ErrNotImplemented", err)
	}
}

func oneNodeConfig(regionID int, nodeID string) *Config {
	return &Config{
		Enabled: true,
		Regions: []Region{
			{
				ID: regionID,
				Nodes: []Node{
					{ID: nodeID, RegionID: regionID},
				},
			},
		},
	}
}
