// SPDX-License-Identifier: Apache-2.0
package ssh3

import (
	"bytes"
	"net"
	"testing"
)

func TestCMXsafeDirectHeaderRoundTrip(t *testing.T) {
	wire, err := buildCMXsafeDirectAdditionalBytes(49152, net.ParseIP("2001:db8::20"), 443)
	if err != nil {
		t.Fatal(err)
	}
	source, ip, port, err := parseCMXsafeDirectHeader(7, bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if source != 49152 || !ip.Equal(net.ParseIP("2001:db8::20")) || port != 443 {
		t.Fatalf("round trip = source %d, destination [%s]:%d", source, ip, port)
	}
}

func TestCMXsafeDirectHeaderRejectsLegacy(t *testing.T) {
	legacy := buildForwardingChannelAdditionalBytes(net.ParseIP("2001:db8::20"), 443)
	if _, _, _, err := parseCMXsafeDirectHeader(7, bytes.NewReader(legacy)); err == nil {
		t.Fatal("legacy direct header accepted")
	}
}

func TestCMXsafeReverseOpenRoundTrip(t *testing.T) {
	wire, err := buildCMXsafeReverseOpenAdditionalBytes(net.ParseIP("2001:db8::10"), 8443, net.ParseIP("2001:db8::99"), 53000)
	if err != nil {
		t.Fatal(err)
	}
	bindIP, bindPort, peerIP, peerPort, err := parseCMXsafeReverseOpenHeader(9, bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if !bindIP.Equal(net.ParseIP("2001:db8::10")) || bindPort != 8443 || !peerIP.Equal(net.ParseIP("2001:db8::99")) || peerPort != 53000 {
		t.Fatalf("bad reverse tuples: [%s]:%d [%s]:%d", bindIP, bindPort, peerIP, peerPort)
	}
}

func TestCMXsafeReverseOpenRejectsIPv4Peer(t *testing.T) {
	if _, err := buildCMXsafeReverseOpenAdditionalBytes(net.ParseIP("2001:db8::10"), 8443, net.ParseIP("192.0.2.1"), 53000); err == nil {
		t.Fatal("IPv4 mirror peer accepted")
	}
}
