package ssh3

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ForwardingPermission is one permitopen or permitlisten destination.
// Hosts are either a canonical IP address, a case-insensitive hostname, or
// "*". Ports are concrete unless AnyPort is set.
type ForwardingPermission struct {
	Host    string
	Port    uint16
	AnyPort bool
}

func ParseForwardingPermission(value string) (ForwardingPermission, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return ForwardingPermission{}, fmt.Errorf("invalid forwarding destination %q: %w", value, err)
	}
	if host == "" {
		return ForwardingPermission{}, fmt.Errorf("forwarding destination %q has an empty host", value)
	}
	permission := ForwardingPermission{Host: strings.ToLower(host)}
	if ip := net.ParseIP(host); ip != nil {
		permission.Host = ip.String()
	} else if permission.Host != "*" && permission.Host != "cmxsafe.invalid" {
		return ForwardingPermission{}, fmt.Errorf("forwarding destination %q must use an IP literal or wildcard", value)
	}
	if portText == "*" {
		permission.AnyPort = true
		return permission, nil
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return ForwardingPermission{}, fmt.Errorf("forwarding destination %q has an invalid port", value)
	}
	permission.Port = uint16(port)
	return permission, nil
}

func (p ForwardingPermission) Matches(ip net.IP, port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	if !p.AnyPort && int(p.Port) != port {
		return false
	}
	if p.Host == "*" {
		return true
	}
	return ip != nil && p.Host == ip.String()
}

// AuthorizationPolicy contains the restrictions attached to the identity
// that authenticated a conversation. The zero value is intentionally
// unrestricted for password and OIDC authentication.
type AuthorizationPolicy struct {
	Initialized       bool
	ForceCommand      string
	HasForceCommand   bool
	NoPTY             bool
	NoPortForwarding  bool
	NoAgentForwarding bool
	PermitOpen        []ForwardingPermission
	PermitListen      []ForwardingPermission
}

func UnrestrictedAuthorizationPolicy() AuthorizationPolicy {
	return AuthorizationPolicy{Initialized: true}
}

func (p AuthorizationPolicy) CanOpen(ip net.IP, port int) bool {
	return p.canForward(p.PermitOpen, ip, port)
}

func (p AuthorizationPolicy) CanListen(ip net.IP, port int) bool {
	return p.canForward(p.PermitListen, ip, port)
}

func (p AuthorizationPolicy) canForward(permissions []ForwardingPermission, ip net.IP, port int) bool {
	if !p.Initialized || p.NoPortForwarding {
		return false
	}
	if len(permissions) == 0 {
		return true
	}
	for _, permission := range permissions {
		if permission.Matches(ip, port) {
			return true
		}
	}
	return false
}
