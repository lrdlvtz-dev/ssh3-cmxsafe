package server_auth

import "testing"

func TestParseAuthorizedKeyOptionsCMXsafePolicy(t *testing.T) {
	policy, err := ParseAuthorizedKeyOptions([]string{
		`command="printf \"safe\""`,
		"no-pty",
		"no-agent-forwarding",
		"no-X11-forwarding",
		`permitopen="[fd00::10]:22"`,
		`permitlisten="[fd00::11]:9450"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Initialized || !policy.HasForceCommand || policy.ForceCommand != `printf "safe"` {
		t.Fatalf("unexpected force command policy: %#v", policy)
	}
	if !policy.NoPTY || !policy.NoAgentForwarding || policy.NoPortForwarding {
		t.Fatalf("unexpected restriction flags: %#v", policy)
	}
	if len(policy.PermitOpen) != 1 || len(policy.PermitListen) != 1 {
		t.Fatalf("unexpected forwarding rules: %#v", policy)
	}
}

func TestParseAuthorizedKeyOptionsRestrictedListener(t *testing.T) {
	policy, err := ParseAuthorizedKeyOptions([]string{
		"restrict",
		"port-forwarding",
		`permitopen="cmxsafe.invalid:1"`,
		`permitlisten="[fd00::11]:9450"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.NoPortForwarding || !policy.NoPTY || !policy.NoAgentForwarding {
		t.Fatalf("unexpected restricted listener policy: %#v", policy)
	}
}

func TestParseAuthorizedKeyOptionsFailsClosed(t *testing.T) {
	tests := [][]string{
		{"environment=FOO=bar"},
		{`command="unterminated`},
		{`permitopen="example.com:22"`},
		{`permitlisten="[fd00::11]:0"`},
		{"port-forwarding", "no-port-forwarding"},
		{`command="one"`, `command="two"`},
	}
	for _, options := range tests {
		if _, err := ParseAuthorizedKeyOptions(options); err == nil {
			t.Fatalf("expected options %#v to fail", options)
		}
	}
}
