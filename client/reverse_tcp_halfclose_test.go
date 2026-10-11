// SPDX-License-Identifier: Apache-2.0
package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

type testReverseTCPChannel struct {
	inbound    chan ssh3Messages.Message
	canceled   chan struct{}
	cancelOnce sync.Once
	closed     chan struct{}
	closeOnce  sync.Once
	mu         sync.Mutex
	outbound   bytes.Buffer
}

func newTestReverseTCPChannel() *testReverseTCPChannel {
	return &testReverseTCPChannel{
		inbound:  make(chan ssh3Messages.Message, 1),
		canceled: make(chan struct{}),
		closed:   make(chan struct{}),
	}
}

func (c *testReverseTCPChannel) ChannelID() util.ChannelID { return 42 }
func (c *testReverseTCPChannel) NextMessage() (ssh3Messages.Message, error) {
	select {
	case message, ok := <-c.inbound:
		if !ok {
			return nil, io.EOF
		}
		return message, nil
	case <-c.canceled:
		return nil, io.EOF
	}
}
func (c *testReverseTCPChannel) CancelRead() {
	c.cancelOnce.Do(func() { close(c.canceled) })
}
func (c *testReverseTCPChannel) Close() {
	c.closeOnce.Do(func() { close(c.closed) })
}
func (c *testReverseTCPChannel) MaxPacketSize() uint64 { return 32 * 1024 }
func (c *testReverseTCPChannel) WriteData(data []byte, _ ssh3Messages.SSHDataType) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.outbound.Write(data)
}
func (c *testReverseTCPChannel) output() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.outbound.Bytes())
}

func TestReverseTCPHalfCloseDrainsResponseBeforeCleanup(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientConn, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	request := []byte("GET / HTTP/1.1\r\nHost: service\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	originDone := make(chan error, 1)
	go func() {
		got, readErr := io.ReadAll(serverConn)
		if readErr != nil {
			originDone <- readErr
			return
		}
		if !bytes.Equal(got, request) {
			originDone <- fmt.Errorf("origin request = %q, want %q", got, request)
			return
		}
		// Make the response strictly depend on receiving the request-side EOF.
		time.Sleep(25 * time.Millisecond)
		_, writeErr := serverConn.Write(response)
		if writeErr == nil {
			writeErr = serverConn.CloseWrite()
		}
		originDone <- writeErr
	}()

	channel := newTestReverseTCPChannel()
	channel.inbound <- &ssh3Messages.DataOrExtendedDataMessage{
		DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE,
		Data:     string(request),
	}
	close(channel.inbound) // The remote half-closes after its HTTP request.

	var cleanupCalls atomic.Int32
	cleaned := make(chan struct{})
	forwardReverseTCPInBackground(context.Background(), channel, clientConn, func() {
		cleanupCalls.Add(1)
		close(cleaned)
	})

	select {
	case err := <-originDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin did not observe half-close and send its response")
	}
	select {
	case <-cleaned:
	case <-time.After(2 * time.Second):
		t.Fatal("reverse TCP cleanup did not complete")
	}
	if got := channel.output(); !bytes.Equal(got, response) {
		t.Fatalf("response was truncated after half-close: got %q, want %q", got, response)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup called %d times, want exactly once", got)
	}
	select {
	case <-channel.closed:
	default:
		t.Fatal("channel send side was not closed after draining the response")
	}
}

func TestReverseTCPCancelCleansUpExactlyOnce(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientConn, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	channel := newTestReverseTCPChannel()
	var cleanupCalls atomic.Int32
	cleaned := make(chan struct{})
	forwardReverseTCPInBackground(ctx, channel, clientConn, func() {
		cleanupCalls.Add(1)
		close(cleaned)
	})
	cancel()

	select {
	case <-cleaned:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not release the reverse TCP connection")
	}
	select {
	case <-channel.closed:
	default:
		t.Fatal("cancel did not close the channel send side")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup called %d times, want exactly once", got)
	}
}
