package derp

// Priority controls how DERP should be ordered against the existing NetBird
// relay path once peer integration is added.
type Priority int

const (
	PriorityUnspecified Priority = iota
	PriorityAfterNetBirdRelay
	PriorityBeforeNetBirdRelay
)

// Config is the management-distributed DERP map and selection policy.
type Config struct {
	Enabled         bool
	Regions         []Region
	SelectionPolicy SelectionPolicy
	Priority        Priority
}

// Region groups DERP nodes by region.
type Region struct {
	ID    int
	Name  string
	Nodes []Node
}

// Node describes a single DERP server candidate.
type Node struct {
	ID        string
	URL       string
	PublicKey []byte
	Hostname  string
	RegionID  int
	STUNOnly  bool
}

// SelectionPolicy narrows or biases home node selection.
type SelectionPolicy struct {
	AllowedRegionIDs  []int
	DeniedRegionIDs   []int
	PreferredRegionID int
	AutoSelect        bool
}

// PeerState is the DERP runtime state advertised in peer negotiation.
type PeerState struct {
	Enabled           bool
	HomeRegionID      int
	HomeNodeID        string
	HomeNodePublicKey []byte
	Generation        uint64
}
