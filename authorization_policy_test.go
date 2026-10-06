package ssh3

import (
	"net"
	"testing"
)

func TestParseForwardingPermission(t *testing.T) {
	tests := []struct {
		value   string
		host    string
		port    uint16
		anyPort bool
	}{
		{"[fd00::11]:9450", "fd00::11", 9450, false},
		{"cmxsafe.invalid:1", "cmxsafe.invalid", 1, false},
		{"*:443", "*", 443, false},
		{"*:*", "*", 0, true},
	}
	for _, test := range tests {
		permission, err := ParseForwardingPermission(test.value)
		if err != nil {
			t.Fatalf("ParseForwardingPermission(%q): %v", test.value, err)
		}
		if permission.Host != test.host || permission.Port != test.port || permission.AnyPort != test.anyPort {
			t.Fatalf("ParseForwardingPermission(%q) = %#v", test.value, permission)
		}
	}
}

func TestAuthorizationPolicyForwarding(t *testing.T) {
	ip := net.ParseIP("fd00::11")
	allowed, err := ParseForwardingPermission("[fd00::11]:9450")
	if err != nil {
		t.Fatal(err)
	}
	policy := AuthorizationPolicy{Initialized: true, PermitListen: []ForwardingPermission{allowed}}
	if !policy.CanListen(ip, 9450) {
		t.Fatal("expected exact IPv6 listener to be allowed")
	}
	if policy.CanListen(ip, 9451) || policy.CanListen(net.ParseIP("fd00::12"), 9450) {
		t.Fatal("unexpected listener allowed")
	}
	policy.NoPortForwarding = true
	if policy.CanListen(ip, 9450) {
		t.Fatal("no-port-forwarding must override permitlisten")
	}
}

func TestUninitializedAuthorizationPolicyFailsClosed(t *testing.T) {
	if (AuthorizationPolicy{}).CanOpen(net.ParseIP("fd00::11"), 22) {
		t.Fatal("uninitialized policy must fail closed")
	}
}
