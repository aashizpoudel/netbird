package config

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateDERPConfig(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString([]byte("derp-node-public-key"))

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "nil config is valid",
			mutate: func(cfg *Config) {
				cfg.DERP = nil
			},
		},
		{
			name: "disabled config is valid",
			mutate: func(cfg *Config) {
				cfg.DERP.Enabled = false
				cfg.DERP.Regions = nil
			},
		},
		{
			name: "valid config decodes public key",
		},
		{
			name: "enabled requires regions",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions = nil
			},
			wantErr: "no regions",
		},
		{
			name: "region id must be positive",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions[0].ID = 0
			},
			wantErr: "id must be positive",
		},
		{
			name: "region id must be unique",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions = append(cfg.DERP.Regions, &DERPRegion{ID: 1, Name: "duplicate"})
			},
			wantErr: "duplicated",
		},
		{
			name: "node id is required",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions[0].Nodes[0].ID = ""
			},
			wantErr: "id is required",
		},
		{
			name: "node url is required",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions[0].Nodes[0].URL = ""
			},
			wantErr: "url is required",
		},
		{
			name: "node hostname is required",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions[0].Nodes[0].Hostname = ""
			},
			wantErr: "hostname is required",
		},
		{
			name: "node region id must be positive",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions[0].Nodes[0].RegionID = 0
			},
			wantErr: "regionId must be positive",
		},
		{
			name: "node region id must match nested region",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions = append(cfg.DERP.Regions, &DERPRegion{ID: 2, Name: "east"})
				cfg.DERP.Regions[0].Nodes[0].RegionID = 2
			},
			wantErr: "must match",
		},
		{
			name: "node public key must be base64",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions[0].Nodes[0].PublicKey = "not base64"
			},
			wantErr: "publicKey must be base64 encoded",
		},
		{
			name: "static node public key is required",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions[0].Nodes[0].PublicKey = ""
			},
			wantErr: "publicKey must be base64 encoded",
		},
		{
			name: "tailscale default map node public key may be empty",
			mutate: func(cfg *Config) {
				cfg.DERP.UseTailscaleDefaultMap = true
				cfg.DERP.Regions[0].Nodes[0].PublicKey = ""
			},
		},
		{
			name: "enabled requires usable non stun only node",
			mutate: func(cfg *Config) {
				cfg.DERP.Regions[0].Nodes[0].STUNOnly = true
			},
			wantErr: "no usable",
		},
		{
			name: "allowed regions must exist",
			mutate: func(cfg *Config) {
				cfg.DERP.SelectionPolicy.AllowedRegionIDs = []int32{99}
			},
			wantErr: "allowed region id 99",
		},
		{
			name: "denied regions must exist",
			mutate: func(cfg *Config) {
				cfg.DERP.SelectionPolicy.DeniedRegionIDs = []int32{99}
			},
			wantErr: "denied region id 99",
		},
		{
			name: "preferred region must exist",
			mutate: func(cfg *Config) {
				cfg.DERP.SelectionPolicy.PreferredRegionID = 99
			},
			wantErr: "preferred region id 99",
		},
		{
			name: "invalid priority fails",
			mutate: func(cfg *Config) {
				cfg.DERP.Priority = "DURING_NETBIRD_RELAY"
			},
			wantErr: "unsupported DERP priority",
		},
		{
			name: "empty priority is valid",
			mutate: func(cfg *Config) {
				cfg.DERP.Priority = ""
			},
		},
		{
			name: "before relay priority is valid",
			mutate: func(cfg *Config) {
				cfg.DERP.Priority = DERPPriorityBeforeNetBirdRelay
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validDERPConfig(validKey)
			if tt.mutate != nil {
				tt.mutate(cfg)
			}

			err := cfg.ValidateDERPConfig()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if cfg.DERP != nil && cfg.DERP.Enabled && len(cfg.DERP.Regions) > 0 && len(cfg.DERP.Regions[0].Nodes) > 0 {
					node := cfg.DERP.Regions[0].Nodes[0]
					if node.PublicKey != "" && len(node.DecodedPublicKey) == 0 {
						t.Fatalf("expected public key to be decoded")
					}
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestResolveDERPMapFromTailscaleDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Err() != nil {
			t.Fatalf("request context is unexpectedly canceled: %v", r.Context().Err())
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"Regions": {
				"2": {
					"RegionID": 2,
					"RegionCode": "nyc",
					"RegionName": "",
					"Nodes": [
						{
							"Name": "2a",
							"RegionID": 2,
							"HostName": "derp2.example.com",
							"DERPPort": 8443
						}
					]
				},
				"1": {
					"RegionID": 1,
					"RegionCode": "sfo",
					"RegionName": "San Francisco",
					"Nodes": [
						{
							"Name": "1a",
							"RegionID": 1,
							"HostName": "derp1.example.com",
							"DERPPort": 443
						},
						{
							"Name": "1b",
							"RegionID": 1,
							"HostName": "derp1b.example.com",
							"STUNOnly": true
						}
					]
				}
			}
		}`))
	}))
	defer server.Close()

	cfg := &Config{
		DERP: &DERPConfig{
			Enabled:                true,
			UseTailscaleDefaultMap: true,
			MapURL:                 server.URL,
			Priority:               DERPPriorityBeforeNetBirdRelay,
			SelectionPolicy: &DERPSelectionPolicy{
				AllowedRegionIDs:  []int32{1, 2},
				PreferredRegionID: 1,
				AutoSelect:        true,
			},
		},
	}

	if err := cfg.ResolveDERPMap(context.Background()); err != nil {
		t.Fatalf("resolve DERP map: %v", err)
	}

	if len(cfg.DERP.Regions) != 2 {
		t.Fatalf("regions length = %d, want 2", len(cfg.DERP.Regions))
	}
	if got := cfg.DERP.Regions[0].ID; got != 1 {
		t.Fatalf("first region id = %d, want 1", got)
	}
	if got := cfg.DERP.Regions[0].Name; got != "San Francisco" {
		t.Fatalf("first region name = %q, want %q", got, "San Francisco")
	}
	if got := cfg.DERP.Regions[1].Name; got != "nyc" {
		t.Fatalf("fallback region name = %q, want %q", got, "nyc")
	}

	node := cfg.DERP.Regions[0].Nodes[0]
	if node.ID != "1a" || node.Hostname != "derp1.example.com" || node.RegionID != 1 {
		t.Fatalf("unexpected normalized node: %+v", node)
	}
	if got := node.URL; got != "https://derp1.example.com/derp" {
		t.Fatalf("node URL = %q, want %q", got, "https://derp1.example.com/derp")
	}
	if cfg.DERP.Regions[0].Nodes[1].STUNOnly != true {
		t.Fatalf("expected STUNOnly to be preserved")
	}
	if got := cfg.DERP.Regions[1].Nodes[0].URL; got != "https://derp2.example.com:8443/derp" {
		t.Fatalf("port node URL = %q, want %q", got, "https://derp2.example.com:8443/derp")
	}
	if cfg.DERP.Priority != DERPPriorityBeforeNetBirdRelay {
		t.Fatalf("priority was not preserved")
	}
	if cfg.DERP.SelectionPolicy == nil || cfg.DERP.SelectionPolicy.PreferredRegionID != 1 {
		t.Fatalf("selection policy was not preserved")
	}

	if err := cfg.ValidateDERPConfig(); err != nil {
		t.Fatalf("validate resolved DERP map: %v", err)
	}
	if got := cfg.DERP.Regions[0].Nodes[0].DecodedPublicKey; len(got) != 0 {
		t.Fatalf("decoded public key length = %d, want 0", len(got))
	}
}

func TestResolveDERPMapNon2xxFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := &Config{DERP: &DERPConfig{
		Enabled:                true,
		UseTailscaleDefaultMap: true,
		MapURL:                 server.URL,
	}}

	err := cfg.ResolveDERPMap(context.Background())
	if err == nil {
		t.Fatalf("expected non-2xx error")
	}
	if !strings.Contains(err.Error(), "unexpected HTTP status 503") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

func TestTailscaleDERPMapDefaultURL(t *testing.T) {
	cfg := &DERPConfig{UseTailscaleDefaultMap: true}
	if got := cfg.tailscaleDERPMapURL(); got != DefaultTailscaleDERPMapURL {
		t.Fatalf("default map URL = %q, want %q", got, DefaultTailscaleDERPMapURL)
	}

	cfg.MapURL = " https://example.com/derpmap "
	if got := cfg.tailscaleDERPMapURL(); got != "https://example.com/derpmap" {
		t.Fatalf("custom map URL = %q, want %q", got, "https://example.com/derpmap")
	}
}

func validDERPConfig(publicKey string) *Config {
	return &Config{
		DERP: &DERPConfig{
			Enabled:  true,
			Priority: DERPPriorityAfterNetBirdRelay,
			Regions: []*DERPRegion{
				{
					ID:   1,
					Name: "central",
					Nodes: []*DERPNode{
						{
							ID:        "central-1",
							URL:       "https://derp.example.com",
							PublicKey: publicKey,
							Hostname:  "derp.example.com",
							RegionID:  1,
						},
					},
				},
			},
			SelectionPolicy: &DERPSelectionPolicy{
				AllowedRegionIDs:  []int32{1},
				PreferredRegionID: 1,
				AutoSelect:        true,
			},
		},
	}
}
