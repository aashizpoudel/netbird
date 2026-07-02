package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsingOfIP(t *testing.T) {
	InterfaceIP := "192.168.178.123/16"

	parsedIP := parseInterfaceIP(InterfaceIP)

	assert.Equal(t, "192.168.178.123\n", parsedIP)
}

func TestParseFiltersAcceptsDERPConnectionType(t *testing.T) {
	oldConnectionTypeFilter := connectionTypeFilter
	oldDetailFlag := detailFlag
	oldJSONFlag := jsonFlag
	oldYAMLFlag := yamlFlag
	t.Cleanup(func() {
		connectionTypeFilter = oldConnectionTypeFilter
		detailFlag = oldDetailFlag
		jsonFlag = oldJSONFlag
		yamlFlag = oldYAMLFlag
		statusFilter = ""
		ipsFilter = nil
		prefixNamesFilter = nil
		ipsFilterMap = map[string]struct{}{}
		prefixNamesFilterMap = map[string]struct{}{}
	})

	connectionTypeFilter = "DERP"
	statusFilter = ""
	ipsFilter = nil
	prefixNamesFilter = nil
	ipsFilterMap = map[string]struct{}{}
	prefixNamesFilterMap = map[string]struct{}{}
	detailFlag = false
	jsonFlag = false
	yamlFlag = false

	require.NoError(t, parseFilters())
	assert.True(t, detailFlag)
}
