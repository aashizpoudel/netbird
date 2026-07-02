package conntype

import (
	"fmt"
)

const (
	None ConnPriority = 0
	// DERP is below the existing NetBird relay for the first coexistence pass.
	// This keeps equal-priority comparisons from accidentally replacing Relay.
	DERP    ConnPriority = 1
	Relay   ConnPriority = 2
	ICETurn ConnPriority = 3
	ICEP2P  ConnPriority = 4
)

type ConnPriority int

func (cp ConnPriority) String() string {
	switch cp {
	case None:
		return "None"
	case DERP:
		return "PriorityDERP"
	case Relay:
		return "PriorityRelay"
	case ICETurn:
		return "PriorityICETurn"
	case ICEP2P:
		return "PriorityICEP2P"
	default:
		return fmt.Sprintf("ConnPriority(%d)", cp)
	}
}
