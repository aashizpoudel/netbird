package conntype

import "testing"

func TestDERPPriorityBelowNetBirdRelay(t *testing.T) {
	if !(DERP < Relay && Relay < ICETurn && ICETurn < ICEP2P) {
		t.Fatalf("unexpected connection priority order: DERP=%d Relay=%d ICETurn=%d ICEP2P=%d", DERP, Relay, ICETurn, ICEP2P)
	}
}
