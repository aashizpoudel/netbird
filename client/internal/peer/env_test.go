package peer

import "testing"

func TestIsForceDERP(t *testing.T) {
	t.Setenv(EnvKeyNBForceDERP, "")
	if IsForceDERP() {
		t.Fatal("expected force DERP to be disabled when env is unset")
	}

	t.Setenv(EnvKeyNBForceDERP, "TrUe")
	if !IsForceDERP() {
		t.Fatal("expected force DERP to be enabled for true value")
	}

	t.Setenv(EnvKeyNBForceDERP, "false")
	if IsForceDERP() {
		t.Fatal("expected force DERP to be disabled for false value")
	}
}
