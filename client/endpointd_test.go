// SPDX-License-Identifier: Apache-2.0
package client

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMirrorPeer(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		port int
	}{{"192.0.2.1", 50000}, {"::1", 50000}, {"2001:db8::1", 80}, {"2001:db8::1", 0}} {
		if err := validateMirrorPeer(net.ParseIP(tc.ip), tc.port); err == nil {
			t.Fatalf("accepted %s:%d", tc.ip, tc.port)
		}
	}
	if err := validateMirrorPeer(net.ParseIP("2001:db8::1"), 50000); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointdVersionedEnsureReleaseWithoutCallerOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpointd.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("CMXSAFE_ENDPOINTD_SOCK", path)
	requests := make(chan string, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadString('\n')
			requests <- line
			_, _ = conn.Write([]byte("{\"ok\":true}\n"))
			conn.Close()
		}
	}()
	ip := net.ParseIP("2001:db8::42")
	if err := endpointdPeer("ensure", 42, ip); err != nil {
		t.Fatal(err)
	}
	if err := endpointdPeer("release", 42, ip); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"v1\tensure\tpeer\t42\t2001:db8::42\n", "v1\trelease\tpeer\t42\t2001:db8::42\n"} {
		if got := <-requests; got != want || strings.Contains(got, "pid:") {
			t.Fatalf("request %q, want %q", got, want)
		}
	}
}

func TestEndpointdRejectsZeroLeaseIDBeforeDial(t *testing.T) {
	t.Setenv("CMXSAFE_ENDPOINTD_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	if err := endpointdPeer("ensure", 0, net.ParseIP("2001:db8::42")); err == nil || !strings.Contains(err.Error(), "lease id") {
		t.Fatalf("zero lease id error = %v", err)
	}
}
