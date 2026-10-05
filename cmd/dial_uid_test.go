// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestHelperV2CarriesObservedSourcePort(t *testing.T) {
	request, _, _, err := buildHelperRequest(1007, "tcp6", 49152, &net.UDPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(request[4:6]); got != 2 {
		t.Fatalf("version=%d", got)
	}
	if got := binary.BigEndian.Uint16(request[22:24]); got != 49152 {
		t.Fatalf("source port=%d", got)
	}
}

func TestHelperV2RejectsPrivilegedSourcePort(t *testing.T) {
	if _, _, _, err := buildHelperRequest(1007, "udp6", 53, &net.UDPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443}); err == nil {
		t.Fatal("privileged source port accepted")
	}
}
