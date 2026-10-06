package cmd

import (
	"net"
	"strings"
	"testing"

	ssh3 "github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

func TestNoPTYDeniedBeforeSessionLookup(t *testing.T) {
	policy := ssh3.UnrestrictedAuthorizationPolicy()
	policy.NoPTY = true
	err := newPtyReq(nil, policy, nil, ssh3Messages.PtyRequest{}, true)
	if err == nil || !strings.Contains(err.Error(), "PTY denied") {
		t.Fatalf("expected policy denial, got %v", err)
	}
}

func TestPermitOpenDeniedBeforeHelper(t *testing.T) {
	allowed, err := ssh3.ParseForwardingPermission("[fd00::10]:22")
	if err != nil {
		t.Fatal(err)
	}
	conversation := &ssh3.Conversation{}
	conversation.SetAuthorizationPolicy(ssh3.AuthorizationPolicy{
		Initialized: true,
		PermitOpen:  []ssh3.ForwardingPermission{allowed},
	})
	deniedIP := net.ParseIP("fd00::11")
	if err := handleTCPForwardingChannel(t.Context(), nil, conversation, &ssh3.TCPForwardingChannelImpl{
		RemoteAddr: &net.TCPAddr{IP: deniedIP, Port: 22},
	}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected TCP forwarding policy denial, got %v", err)
	}
	if err := handleUDPForwardingChannel(t.Context(), nil, conversation, &ssh3.UDPForwardingChannelImpl{
		RemoteAddr: &net.UDPAddr{IP: deniedIP, Port: 22},
	}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected UDP forwarding policy denial, got %v", err)
	}
}
