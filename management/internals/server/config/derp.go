package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTailscaleDERPMapURL = "https://controlplane.tailscale.com/derpmap/default"
	maxDERPMapResponseSize     = 10 << 20
	derpMapHTTPTimeout         = 10 * time.Second
)

// ResolveDERPMap loads the public Tailscale DERP map when requested.
func (c *Config) ResolveDERPMap(ctx context.Context) error {
	if c == nil || c.DERP == nil || !c.DERP.Enabled || !c.DERP.UseTailscaleDefaultMap {
		return nil
	}

	mapURL := c.DERP.tailscaleDERPMapURL()
	c.DERP.MapURL = mapURL

	derpMap, err := fetchTailscaleDERPMap(ctx, mapURL)
	if err != nil {
		return err
	}

	regions, err := normalizeTailscaleDERPMap(derpMap)
	if err != nil {
		return err
	}
	c.DERP.Regions = regions

	return nil
}

func (c *DERPConfig) tailscaleDERPMapURL() string {
	mapURL := strings.TrimSpace(c.MapURL)
	if mapURL == "" {
		return DefaultTailscaleDERPMapURL
	}
	return mapURL
}

type tailscaleDERPMap struct {
	Regions map[string]*tailscaleDERPRegion
}

type tailscaleDERPRegion struct {
	RegionID   int32
	RegionCode string
	RegionName string
	Nodes      []*tailscaleDERPNode
}

type tailscaleDERPNode struct {
	Name     string
	RegionID int32
	HostName string
	DERPPort int
	STUNOnly bool
}

func fetchTailscaleDERPMap(ctx context.Context, mapURL string) (*tailscaleDERPMap, error) {
	if _, err := url.ParseRequestURI(mapURL); err != nil {
		return nil, fmt.Errorf("invalid Tailscale DERP map URL %q: %w", mapURL, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mapURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create Tailscale DERP map request: %w", err)
	}

	client := &http.Client{Timeout: derpMapHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Tailscale DERP map: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch Tailscale DERP map: unexpected HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDERPMapResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read Tailscale DERP map: %w", err)
	}
	if len(body) > maxDERPMapResponseSize {
		return nil, fmt.Errorf("Tailscale DERP map response exceeds %d bytes", maxDERPMapResponseSize)
	}

	var derpMap tailscaleDERPMap
	if err := json.Unmarshal(body, &derpMap); err != nil {
		return nil, fmt.Errorf("decode Tailscale DERP map: %w", err)
	}

	return &derpMap, nil
}

func normalizeTailscaleDERPMap(derpMap *tailscaleDERPMap) ([]*DERPRegion, error) {
	if derpMap == nil || len(derpMap.Regions) == 0 {
		return nil, fmt.Errorf("Tailscale DERP map has no regions")
	}

	keys := make([]string, 0, len(derpMap.Regions))
	for key := range derpMap.Regions {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := derpMap.Regions[keys[i]]
		right := derpMap.Regions[keys[j]]
		if left == nil || right == nil || left.RegionID == right.RegionID {
			return keys[i] < keys[j]
		}
		return left.RegionID < right.RegionID
	})

	regions := make([]*DERPRegion, 0, len(keys))
	for _, key := range keys {
		region := derpMap.Regions[key]
		if region == nil {
			return nil, fmt.Errorf("Tailscale DERP region %q is nil", key)
		}
		if region.RegionID <= 0 {
			return nil, fmt.Errorf("Tailscale DERP region %q has invalid RegionID %d", key, region.RegionID)
		}

		name := strings.TrimSpace(region.RegionName)
		if name == "" {
			name = strings.TrimSpace(region.RegionCode)
		}
		if name == "" {
			return nil, fmt.Errorf("Tailscale DERP region %d has empty name", region.RegionID)
		}

		nodes := make([]*DERPNode, 0, len(region.Nodes))
		for i, node := range region.Nodes {
			normalized, err := normalizeTailscaleDERPNode(region.RegionID, i, node)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, normalized)
		}

		regions = append(regions, &DERPRegion{
			ID:    region.RegionID,
			Name:  name,
			Nodes: nodes,
		})
	}

	return regions, nil
}

func normalizeTailscaleDERPNode(regionID int32, index int, node *tailscaleDERPNode) (*DERPNode, error) {
	if node == nil {
		return nil, fmt.Errorf("Tailscale DERP region %d node at index %d is nil", regionID, index)
	}

	name := strings.TrimSpace(node.Name)
	if name == "" {
		return nil, fmt.Errorf("Tailscale DERP region %d node at index %d has empty Name", regionID, index)
	}

	hostname := strings.TrimSpace(node.HostName)
	if hostname == "" {
		return nil, fmt.Errorf("Tailscale DERP region %d node %q has empty HostName", regionID, name)
	}

	if node.RegionID <= 0 {
		return nil, fmt.Errorf("Tailscale DERP region %d node %q has invalid RegionID %d", regionID, name, node.RegionID)
	}
	if node.RegionID != regionID {
		return nil, fmt.Errorf("Tailscale DERP region %d node %q has mismatched RegionID %d", regionID, name, node.RegionID)
	}

	return &DERPNode{
		ID:       name,
		URL:      derpNodeURL(hostname, node.DERPPort),
		Hostname: hostname,
		RegionID: node.RegionID,
		STUNOnly: node.STUNOnly,
	}, nil
}

func derpNodeURL(hostname string, derpPort int) string {
	host := hostname
	if derpPort != 0 && derpPort != 443 {
		host = net.JoinHostPort(hostname, strconv.Itoa(derpPort))
	}

	return (&url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/derp",
	}).String()
}

// ValidateDERPConfig validates and normalizes the static DERP map.
func (c *Config) ValidateDERPConfig() error {
	if c == nil || c.DERP == nil || !c.DERP.Enabled {
		return nil
	}

	if err := validateDERPPriority(c.DERP.Priority); err != nil {
		return err
	}

	if len(c.DERP.Regions) == 0 {
		return fmt.Errorf("DERP config is enabled but no regions are configured")
	}

	regionIDs := make(map[int32]struct{}, len(c.DERP.Regions))
	for i, region := range c.DERP.Regions {
		if region == nil {
			return fmt.Errorf("DERP region at index %d is nil", i)
		}
		if region.ID <= 0 {
			return fmt.Errorf("DERP region at index %d has invalid id %d: id must be positive", i, region.ID)
		}
		if _, ok := regionIDs[region.ID]; ok {
			return fmt.Errorf("DERP region id %d is duplicated", region.ID)
		}
		regionIDs[region.ID] = struct{}{}
	}

	usableNodes := 0
	for _, region := range c.DERP.Regions {
		for j, node := range region.Nodes {
			if node == nil {
				return fmt.Errorf("DERP region %d node at index %d is nil", region.ID, j)
			}
			if err := validateDERPNode(region.ID, node, c.DERP.UseTailscaleDefaultMap); err != nil {
				return fmt.Errorf("DERP region %d node %d: %w", region.ID, j, err)
			}
			if _, ok := regionIDs[node.RegionID]; !ok {
				return fmt.Errorf("DERP region %d node %q references unknown region id %d", region.ID, node.ID, node.RegionID)
			}
			if node.RegionID != region.ID {
				return fmt.Errorf("DERP region %d node %q has mismatched region id %d", region.ID, node.ID, node.RegionID)
			}
			if !node.STUNOnly {
				usableNodes++
			}
		}
	}

	if usableNodes == 0 {
		return fmt.Errorf("DERP config is enabled but has no usable non-STUN-only nodes")
	}

	if err := validateDERPSelectionPolicy(c.DERP.SelectionPolicy, regionIDs); err != nil {
		return err
	}

	return nil
}

func validateDERPNode(regionID int32, node *DERPNode, allowEmptyPublicKey bool) error {
	if strings.TrimSpace(node.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(node.URL) == "" {
		return fmt.Errorf("url is required")
	}
	if strings.TrimSpace(node.Hostname) == "" {
		return fmt.Errorf("hostname is required")
	}
	if node.RegionID <= 0 {
		return fmt.Errorf("regionId must be positive")
	}
	if node.RegionID != regionID {
		return fmt.Errorf("regionId must match containing region id %d", regionID)
	}

	publicKey, err := decodeDERPPublicKey(node.PublicKey, allowEmptyPublicKey)
	if err != nil {
		return fmt.Errorf("publicKey must be base64 encoded: %w", err)
	}
	node.DecodedPublicKey = publicKey

	return nil
}

func decodeDERPPublicKey(publicKey string, allowEmpty bool) ([]byte, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		if allowEmpty {
			return nil, nil
		}
		return nil, fmt.Errorf("empty value")
	}

	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err == nil && len(decoded) > 0 {
		return decoded, nil
	}

	decoded, rawErr := base64.RawStdEncoding.DecodeString(publicKey)
	if rawErr == nil && len(decoded) > 0 {
		return decoded, nil
	}

	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("decoded value is empty")
}

func validateDERPSelectionPolicy(policy *DERPSelectionPolicy, regionIDs map[int32]struct{}) error {
	if policy == nil {
		return nil
	}

	for _, id := range policy.AllowedRegionIDs {
		if _, ok := regionIDs[id]; !ok {
			return fmt.Errorf("DERP selection policy allowed region id %d is not configured", id)
		}
	}
	for _, id := range policy.DeniedRegionIDs {
		if _, ok := regionIDs[id]; !ok {
			return fmt.Errorf("DERP selection policy denied region id %d is not configured", id)
		}
	}
	if policy.PreferredRegionID != 0 {
		if _, ok := regionIDs[policy.PreferredRegionID]; !ok {
			return fmt.Errorf("DERP selection policy preferred region id %d is not configured", policy.PreferredRegionID)
		}
	}

	return nil
}

func validateDERPPriority(priority DERPPriority) error {
	switch priority {
	case "", DERPPriorityAfterNetBirdRelay, DERPPriorityBeforeNetBirdRelay:
		return nil
	default:
		return fmt.Errorf("unsupported DERP priority %q", priority)
	}
}
