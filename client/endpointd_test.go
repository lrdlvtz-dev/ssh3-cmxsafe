// SPDX-License-Identifier: Apache-2.0
package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixedSSH3Channel uint64

func (channel fixedSSH3Channel) ChannelID() uint64 { return uint64(channel) }

func TestEndpointdDefaultSocketMatchesDaemon(t *testing.T) {
	t.Setenv("CMXSAFE_ENDPOINTD_SOCK", "")
	if got, want := endpointdSocketPath(), "/run/cmxsafe/endpointd.sock"; got != want {
		t.Fatalf("endpointd socket = %q, want %q", got, want)
	}
}

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

func TestDialReusableMirrorTCPWithSequentialIdenticalTuple(t *testing.T) {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()

	// Reserve a free source port without creating a TCP connection or TIME_WAIT.
	probe, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Fatal(err)
	}
	sourcePort := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	const iterations = 250
	serverErr := make(chan error, 1)
	go func() {
		for i := 0; i < iterations; i++ {
			conn, acceptErr := listener.AcceptTCP()
			if acceptErr != nil {
				serverErr <- acceptErr
				return
			}
			request, readErr := io.ReadAll(conn)
			if readErr == nil && !bytes.Equal(request, []byte("request")) {
				readErr = errors.New("unexpected mirror TCP request")
			}
			if readErr == nil {
				_, readErr = conn.Write([]byte("response"))
			}
			if closeErr := conn.Close(); readErr == nil {
				readErr = closeErr
			}
			if readErr != nil {
				serverErr <- readErr
				return
			}
		}
		serverErr <- nil
	}()

	peer := &net.TCPAddr{IP: net.ParseIP("::1"), Port: sourcePort}
	target := listener.Addr().(*net.TCPAddr)
	for i := 0; i < iterations; i++ {
		conn, dialErr := dialReusableMirrorTCP(context.Background(), peer, target)
		if dialErr != nil {
			t.Fatalf("iteration %d: %v", i, dialErr)
		}
		if _, err := conn.Write([]byte("request")); err != nil {
			t.Fatal(err)
		}
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(response, []byte("response")) {
			t.Fatalf("iteration %d: response = %q", i, response)
		}
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDialReusableMirrorTCPWithConcurrentDistinctTargets(t *testing.T) {
	listeners := make([]*net.TCPListener, 2)
	for i := range listeners {
		listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		listeners[i] = listener
		defer listener.Close()
	}
	probe, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Fatal(err)
	}
	sourcePort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	accepted := make(chan struct{}, 2)
	releaseServers := make(chan struct{})
	serverErr := make(chan error, 2)
	for _, listener := range listeners {
		go func(listener *net.TCPListener) {
			conn, err := listener.AcceptTCP()
			if err != nil {
				serverErr <- err
				return
			}
			defer conn.Close()
			accepted <- struct{}{}
			<-releaseServers
			request, err := io.ReadAll(conn)
			if err == nil {
				_, err = conn.Write(request)
			}
			serverErr <- err
		}(listener)
	}

	peer := &net.TCPAddr{IP: net.ParseIP("::1"), Port: sourcePort}
	clientErr := make(chan error, 2)
	var clients sync.WaitGroup
	clients.Add(2)
	for i, listener := range listeners {
		go func(i int, target *net.TCPAddr) {
			defer clients.Done()
			conn, err := dialReusableMirrorTCP(context.Background(), peer, target)
			if err != nil {
				clientErr <- err
				return
			}
			defer conn.Close()
			payload := []byte{byte('a' + i)}
			if _, err = conn.Write(payload); err == nil {
				err = conn.CloseWrite()
			}
			var response []byte
			if err == nil {
				response, err = io.ReadAll(conn)
			}
			if err == nil && !bytes.Equal(response, payload) {
				err = errors.New("concurrent mirror TCP response mismatch")
			}
			clientErr <- err
		}(i, listener.Addr().(*net.TCPAddr))
	}
	for range listeners {
		select {
		case <-accepted:
		case err := <-clientErr:
			t.Fatalf("concurrent dial failed before both targets accepted: %v", err)
		}
	}
	close(releaseServers)
	clients.Wait()
	for range listeners {
		if err := <-clientErr; err != nil {
			t.Fatal(err)
		}
		if err := <-serverErr; err != nil {
			t.Fatal(err)
		}
	}
}

func TestDialReusableMirrorTCPRejectsConcurrentIdenticalTuple(t *testing.T) {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()
	probe, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Fatal(err)
	}
	sourcePort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	peer := &net.TCPAddr{IP: net.ParseIP("::1"), Port: sourcePort}
	target := listener.Addr().(*net.TCPAddr)
	first, err := dialReusableMirrorTCP(context.Background(), peer, target)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var server *net.TCPConn
	select {
	case server = <-accepted:
		defer server.Close()
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("first connection was not established")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	second, err := dialReusableMirrorTCP(ctx, peer, target)
	if second != nil {
		second.Close()
		t.Fatal("second connection unexpectedly reused an established TCP 4-tuple")
	}
	if err == nil {
		t.Fatal("second connection unexpectedly succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second connection error = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("context cancellation took %v", elapsed)
	}

	// The rejected connection must not disturb the original established flow.
	payload := []byte("still-established")
	if _, err := first.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("first connection payload = %q", got)
	}
}

func TestDialMirrorTCPReleasesLeaseOnceAndReportsReleaseFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpointd.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("CMXSAFE_ENDPOINTD_SOCK", path)

	requests := make(chan string, 2)
	serverErr := make(chan error, 1)
	go func() {
		for _, reply := range []string{"{\"ok\":true}\n", "{\"ok\":false,\"error\":\"release_failed\"}\n"} {
			conn, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				serverErr <- acceptErr
				return
			}
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			if readErr == nil {
				requests <- line
				_, readErr = conn.Write([]byte(reply))
			}
			if closeErr := conn.Close(); readErr == nil {
				readErr = closeErr
			}
			if readErr != nil {
				serverErr <- readErr
				return
			}
		}
		serverErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	conn, cleanup, err := dialMirrorTCP(
		ctx,
		fixedSSH3Channel(42),
		&net.TCPAddr{IP: net.ParseIP("2001:db8::42"), Port: 4242},
		&net.TCPAddr{IP: net.ParseIP("::1"), Port: 9},
	)
	if conn != nil || cleanup != nil {
		t.Fatalf("terminal dial failure returned conn=%v cleanup_present=%t", conn, cleanup != nil)
	}
	if err == nil {
		t.Fatal("terminal dial failure unexpectedly succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("terminal dial error = %v, want context deadline", err)
	}
	for _, want := range []string{"dial TCP mirror socket", "release mirror TCP endpoint lease", "release_failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("terminal dial error %q does not contain %q", err, want)
		}
	}

	for _, want := range []string{
		"v1\tensure\tpeer\t42\t2001:db8::42\n",
		"v1\trelease\tpeer\t42\t2001:db8::42\n",
	} {
		select {
		case got := <-requests:
			if got != want {
				t.Fatalf("endpointd request = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for endpointd request %q", want)
		}
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}

	if err := listener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	extra, err := listener.AcceptUnix()
	if extra != nil {
		extra.Close()
		t.Fatal("endpointd received a duplicate release request")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("checking for duplicate release: %v", err)
	}
}
