package grpc

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestToNetbirdConfigDERPNilAndDisabled(t *testing.T) {
	t.Run("nil DERP config omits proto DERP config", func(t *testing.T) {
		got := toNetbirdConfig(&nbconfig.Config{}, nil, nil, nil)
		assert.NotNil(t, got)
		assert.Nil(t, got.GetDerp())
	})

	t.Run("disabled DERP config is sent disabled", func(t *testing.T) {
		got := toNetbirdConfig(&nbconfig.Config{DERP: &nbconfig.DERPConfig{}}, nil, nil, nil)
		assert.NotNil(t, got.GetDerp())
		assert.False(t, got.GetDerp().GetEnabled())
		assert.Empty(t, got.GetDerp().GetRegions())
	})
}

func TestToNetbirdConfigDERPMapping(t *testing.T) {
	publicKey := []byte("derp-node-public-key")
	cfg := &nbconfig.Config{
		DERP: &nbconfig.DERPConfig{
			Enabled:  true,
			Priority: nbconfig.DERPPriorityBeforeNetBirdRelay,
			Regions: []*nbconfig.DERPRegion{
				{
					ID:   1,
					Name: "central",
					Nodes: []*nbconfig.DERPNode{
						{
							ID:        "central-1",
							URL:       "https://derp.example.com",
							PublicKey: base64.StdEncoding.EncodeToString(publicKey),
							Hostname:  "derp.example.com",
							RegionID:  1,
						},
						{
							ID:        "central-stun",
							URL:       "stun://derp.example.com:3478",
							PublicKey: base64.StdEncoding.EncodeToString([]byte("stun-key")),
							Hostname:  "derp.example.com",
							RegionID:  1,
							STUNOnly:  true,
						},
					},
				},
			},
			SelectionPolicy: &nbconfig.DERPSelectionPolicy{
				AllowedRegionIDs:  []int32{1},
				DeniedRegionIDs:   []int32{1},
				PreferredRegionID: 1,
				AutoSelect:        true,
			},
		},
	}
	assert.NoError(t, cfg.ValidateDERPConfig())

	got := toNetbirdConfig(cfg, nil, nil, nil)
	derp := got.GetDerp()
	assert.NotNil(t, derp)
	assert.True(t, derp.GetEnabled())
	assert.Equal(t, proto.DERPPriority_DERP_PRIORITY_BEFORE_NETBIRD_RELAY, derp.GetPriority())
	assert.Len(t, derp.GetRegions(), 1)
	assert.Equal(t, int32(1), derp.GetRegions()[0].GetId())
	assert.Equal(t, "central", derp.GetRegions()[0].GetName())
	assert.Len(t, derp.GetRegions()[0].GetNodes(), 2)

	node := derp.GetRegions()[0].GetNodes()[0]
	assert.Equal(t, "central-1", node.GetId())
	assert.Equal(t, "https://derp.example.com", node.GetUrl())
	assert.Equal(t, publicKey, node.GetPublicKey())
	assert.Equal(t, "derp.example.com", node.GetHostname())
	assert.Equal(t, int32(1), node.GetRegionId())
	assert.False(t, node.GetStunOnly())

	stunNode := derp.GetRegions()[0].GetNodes()[1]
	assert.True(t, stunNode.GetStunOnly())

	assert.Equal(t, []int32{1}, derp.GetSelectionPolicy().GetAllowedRegionIds())
	assert.Equal(t, []int32{1}, derp.GetSelectionPolicy().GetDeniedRegionIds())
	assert.Equal(t, int32(1), derp.GetSelectionPolicy().GetPreferredRegionId())
	assert.True(t, derp.GetSelectionPolicy().GetAutoSelect())

	cfg.DERP.Regions[0].Nodes[0].DecodedPublicKey[0] = 0xFF
	assert.Equal(t, publicKey, node.GetPublicKey(), "proto public key must be copied")
}

func TestToProtocolDNSConfigWithCache(t *testing.T) {
	var cache cache.DNSConfigCache

	// Create two different configs
	config1 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.com",
				Records: []nbdns.SimpleRecord{
					{Name: "www", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.1"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group1",
				Name: "Group 1",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.8.8"), Port: 53},
				},
			},
		},
	}

	config2 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.org",
				Records: []nbdns.SimpleRecord{
					{Name: "mail", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.2"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group2",
				Name: "Group 2",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.4.4"), Port: 53},
				},
			},
		},
	}

	// First run with config1
	result1 := toProtocolDNSConfig(config1, &cache, int64(network_map.DnsForwarderPort))

	// Second run with config2
	result2 := toProtocolDNSConfig(config2, &cache, int64(network_map.DnsForwarderPort))

	// Third run with config1 again
	result3 := toProtocolDNSConfig(config1, &cache, int64(network_map.DnsForwarderPort))

	// Verify that result1 and result3 are identical
	if !reflect.DeepEqual(result1, result3) {
		t.Errorf("Results are not identical when run with the same input. Expected %v, got %v", result1, result3)
	}

	// Verify that result2 is different from result1 and result3
	if reflect.DeepEqual(result1, result2) || reflect.DeepEqual(result2, result3) {
		t.Errorf("Results should be different for different inputs")
	}

	if _, exists := cache.GetNameServerGroup("group1"); !exists {
		t.Errorf("Cache should contain name server group 'group1'")
	}

	if _, exists := cache.GetNameServerGroup("group2"); !exists {
		t.Errorf("Cache should contain name server group 'group2'")
	}
}

func BenchmarkToProtocolDNSConfig(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		testData := generateTestData(size)

		b.Run(fmt.Sprintf("WithCache-Size%d", size), func(b *testing.B) {
			cache := &cache.DNSConfigCache{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				toProtocolDNSConfig(testData, cache, int64(network_map.DnsForwarderPort))
			}
		})

		b.Run(fmt.Sprintf("WithoutCache-Size%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cache := &cache.DNSConfigCache{}
				toProtocolDNSConfig(testData, cache, int64(network_map.DnsForwarderPort))
			}
		})
	}
}

func generateTestData(size int) nbdns.Config {
	config := nbdns.Config{
		ServiceEnable:    true,
		CustomZones:      make([]nbdns.CustomZone, size),
		NameServerGroups: make([]*nbdns.NameServerGroup, size),
	}

	for i := 0; i < size; i++ {
		config.CustomZones[i] = nbdns.CustomZone{
			Domain: fmt.Sprintf("domain%d.com", i),
			Records: []nbdns.SimpleRecord{
				{
					Name:  fmt.Sprintf("record%d", i),
					Type:  1,
					Class: "IN",
					TTL:   3600,
					RData: "192.168.1.1",
				},
			},
		}

		config.NameServerGroups[i] = &nbdns.NameServerGroup{
			ID:                   fmt.Sprintf("group%d", i),
			Primary:              i == 0,
			Domains:              []string{fmt.Sprintf("domain%d.com", i)},
			SearchDomainsEnabled: true,
			NameServers: []nbdns.NameServer{
				{
					IP:     netip.MustParseAddr("8.8.8.8"),
					Port:   53,
					NSType: 1,
				},
			},
		}
	}

	return config
}

func TestBuildJWTConfig_Audiences(t *testing.T) {
	tests := []struct {
		name              string
		authAudience      string
		cliAuthAudience   string
		expectedAudiences []string
		expectedAudience  string
	}{
		{
			name:              "only_auth_audience",
			authAudience:      "dashboard-aud",
			cliAuthAudience:   "",
			expectedAudiences: []string{"dashboard-aud"},
			expectedAudience:  "dashboard-aud",
		},
		{
			name:              "both_audiences_different",
			authAudience:      "dashboard-aud",
			cliAuthAudience:   "cli-aud",
			expectedAudiences: []string{"dashboard-aud", "cli-aud"},
			expectedAudience:  "cli-aud",
		},
		{
			name:              "both_audiences_same",
			authAudience:      "same-aud",
			cliAuthAudience:   "same-aud",
			expectedAudiences: []string{"same-aud"},
			expectedAudience:  "same-aud",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &nbconfig.HttpServerConfig{
				AuthIssuer:      "https://issuer.example.com",
				AuthAudience:    tc.authAudience,
				CLIAuthAudience: tc.cliAuthAudience,
			}

			result := buildJWTConfig(config, nil)

			assert.NotNil(t, result)
			assert.Equal(t, tc.expectedAudiences, result.Audiences, "audiences should match expected")
			//nolint:staticcheck // SA1019: Testing backwards compatibility - Audience field must still be populated
			assert.Equal(t, tc.expectedAudience, result.Audience, "audience should match expected")
		})
	}
}

// TestShouldSkipSendingDeprecatedRemotePeers covers the version gate that
// stops populating the deprecated top-level SyncResponse.RemotePeers field for
// peers new enough to read RemotePeers off the NetworkMap. Development builds
// are treated as latest and skip the field. The gate otherwise fails safe: a
// release version older than the boundary, or one that can't be parsed (empty,
// garbage, prereleases of the boundary) still receives the deprecated field so
// older/unknown clients keep working.
func TestShouldSkipSendingDeprecatedRemotePeers(t *testing.T) {
	tests := []struct {
		name        string
		peerVersion string
		wantSkip    bool
	}{
		{"exact boundary skips", "0.29.3", true},
		{"newer patch skips", "0.29.4", true},
		{"newer minor skips", "0.30.0", true},
		{"newer major skips", "1.0.0", true},
		{"v-prefixed newer skips", "v0.30.0", true},
		{"development build skips", "development", true},
		{"development build with commit skips", "development-abc123def456-dirty", true},
		{"older patch keeps field", "0.29.2", false},
		{"older minor keeps field", "0.28.0", false},
		{"prerelease of boundary keeps field", "0.29.3-SNAPSHOT", false},
		{"tagged dev prerelease keeps field", "v0.31.1-dev", false},
		{"empty version keeps field", "", false},
		{"garbage version keeps field", "not-a-version", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipSendingDeprecatedRemotePeers(tc.peerVersion)
			assert.Equal(t, tc.wantSkip, got, "skip decision for peer version %q", tc.peerVersion)
		})
	}
}

// TestEncodeSessionExpiresAt pins the wire encoding the client's
// applySessionDeadline depends on:
//
//   - zero deadline  → &Timestamp{} (seconds=0, nanos=0): the explicit
//     "expiry disabled or peer is not SSO-tracked" sentinel.
//   - non-zero       → timestamppb.New(deadline): the absolute UTC deadline.
//
// The third state (nil pointer = "no info in this snapshot") is the caller's
// responsibility on the Sync path when settings could not be resolved; the
// helper itself never returns nil.
func TestEncodeSessionExpiresAt(t *testing.T) {
	t.Run("zero deadline encodes as explicit-zero sentinel", func(t *testing.T) {
		got := encodeSessionExpiresAt(time.Time{})
		assert.NotNil(t, got, "must not return nil; nil means 'no info', not 'disabled'")
		assert.Equal(t, int64(0), got.GetSeconds())
		assert.Equal(t, int32(0), got.GetNanos())
	})

	t.Run("non-zero deadline round-trips", func(t *testing.T) {
		deadline := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		got := encodeSessionExpiresAt(deadline)
		assert.NotNil(t, got)
		assert.True(t, got.AsTime().Equal(deadline))
	})
}
