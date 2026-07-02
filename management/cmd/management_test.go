package cmd

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const (
	exampleConfig = `{
	  "Relay": {
		"Addresses": [
		  "rel://192.168.100.1:8085",
		  "rel://192.168.100.1:8086"
		],
		"CredentialsTTL": "12h0m0s",
		"Secret": "8f7e9d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8"
	  },
	  "HttpConfig": {
		"AuthAudience": "https://stageapp/",
		"AuthIssuer": "https://something.eu.auth0.com/",
		"OIDCConfigEndpoint": "https://something.eu.auth0.com/.well-known/openid-configuration"
	  }
	}`
)

func Test_loadMgmtConfig(t *testing.T) {
	tmpFile, err := createConfig()
	if err != nil {
		t.Fatalf("failed to create config: %s", err)
	}

	cfg, err := LoadMgmtConfig(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("failed to load management config: %s", err)
	}
	if cfg.Relay == nil {
		t.Fatalf("config is nil")
	}
	if len(cfg.Relay.Addresses) == 0 {
		t.Fatalf("relay address is empty")
	}
}

func Test_loadMgmtConfigWithValidDERP(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString([]byte("derp-node-public-key"))
	config := strings.Replace(exampleConfig, `"HttpConfig": {`, `"DERP": {
		"Enabled": true,
		"Priority": "BEFORE_NETBIRD_RELAY",
		"Regions": [
		  {
			"ID": 1,
			"Name": "central",
			"Nodes": [
			  {
				"ID": "central-1",
				"URL": "https://derp.example.com",
				"PublicKey": "`+publicKey+`",
				"Hostname": "derp.example.com",
				"RegionID": 1
			  }
			]
		  }
		],
		"SelectionPolicy": {
		  "AllowedRegionIDs": [1],
		  "PreferredRegionID": 1,
		  "AutoSelect": true
		}
	  },
	  "HttpConfig": {`, 1)

	tmpFile, err := createConfigWithContent(config)
	if err != nil {
		t.Fatalf("failed to create config: %s", err)
	}

	cfg, err := LoadMgmtConfig(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("failed to load management config: %s", err)
	}
	if cfg.DERP == nil || !cfg.DERP.Enabled {
		t.Fatalf("expected DERP config to be enabled")
	}
	if got := cfg.DERP.Regions[0].Nodes[0].DecodedPublicKey; string(got) != "derp-node-public-key" {
		t.Fatalf("decoded public key = %q, want %q", string(got), "derp-node-public-key")
	}
}

func Test_loadMgmtConfigWithInvalidDERP(t *testing.T) {
	config := strings.Replace(exampleConfig, `"HttpConfig": {`, `"DERP": {
		"Enabled": true,
		"Regions": []
	  },
	  "HttpConfig": {`, 1)

	tmpFile, err := createConfigWithContent(config)
	if err != nil {
		t.Fatalf("failed to create config: %s", err)
	}

	_, err = LoadMgmtConfig(context.Background(), tmpFile)
	if err == nil {
		t.Fatalf("expected DERP validation error")
	}
	if !strings.Contains(err.Error(), "no regions") {
		t.Fatalf("expected no regions error, got %v", err)
	}
}

func Test_loadMgmtConfigWithTailscaleDefaultDERPMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"Regions": {
				"10": {
					"RegionID": 10,
					"RegionName": "Test Region",
					"Nodes": [
						{
							"Name": "10a",
							"RegionID": 10,
							"HostName": "derp10.example.com"
						}
					]
				}
			}
		}`))
	}))
	defer server.Close()

	config := strings.Replace(exampleConfig, `"HttpConfig": {`, `"DERP": {
		"Enabled": true,
		"UseTailscaleDefaultMap": true,
		"MapURL": "`+server.URL+`",
		"Priority": "BEFORE_NETBIRD_RELAY",
		"SelectionPolicy": {
		  "AllowedRegionIDs": [10],
		  "PreferredRegionID": 10,
		  "AutoSelect": true
		}
	  },
	  "HttpConfig": {`, 1)

	tmpFile, err := createConfigWithContent(config)
	if err != nil {
		t.Fatalf("failed to create config: %s", err)
	}

	cfg, err := LoadMgmtConfig(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("failed to load management config: %s", err)
	}
	if cfg.DERP == nil || len(cfg.DERP.Regions) != 1 {
		t.Fatalf("expected resolved DERP region, got %+v", cfg.DERP)
	}
	node := cfg.DERP.Regions[0].Nodes[0]
	if got := node.URL; got != "https://derp10.example.com/derp" {
		t.Fatalf("node URL = %q, want %q", got, "https://derp10.example.com/derp")
	}
	if len(node.DecodedPublicKey) != 0 {
		t.Fatalf("decoded public key length = %d, want 0", len(node.DecodedPublicKey))
	}
}

func createConfig() (string, error) {
	return createConfigWithContent(exampleConfig)
}

func createConfigWithContent(content string) (string, error) {
	tmpfile, err := os.CreateTemp("", "config.json")
	if err != nil {
		return "", err
	}
	_, err = tmpfile.Write([]byte(content))
	if err != nil {
		return "", err
	}

	if err := tmpfile.Close(); err != nil {
		return "", err
	}
	return tmpfile.Name(), nil
}
