package cmd

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingReverseTCPListener struct {
	acceptStarted chan struct{}
	closed        chan struct{}
	closeOnce     sync.Once
	closeCalls    atomic.Int32
}

func newBlockingReverseTCPListener() *blockingReverseTCPListener {
	return &blockingReverseTCPListener{
		acceptStarted: make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

func (l *blockingReverseTCPListener) AcceptTCP() (*net.TCPConn, error) {
	select {
	case <-l.acceptStarted:
	default:
		close(l.acceptStarted)
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingReverseTCPListener) Close() error {
	l.closeCalls.Add(1)
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func TestServeTCPReverseListenerClosesOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	listener := newBlockingReverseTCPListener()
	done := make(chan struct{})
	go func() {
		serveTCPReverseListener(ctx, &net.TCPAddr{IP: net.IPv6loopback, Port: 9000}, listener, func(*net.TCPConn) error {
			t.Fatal("connection handler must not run")
			return nil
		})
		close(done)
	}()

	select {
	case <-listener.acceptStarted:
	case <-time.After(time.Second):
		t.Fatal("listener did not start accepting")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listener remained blocked after context cancellation")
	}
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("listener Close called %d times, want exactly once", got)
	}
}

func TestServeTCPReverseListenerReleasesBoundPortOnContextCancellation(t *testing.T) {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		serveTCPReverseListener(ctx, addr, listener, func(conn *net.TCPConn) error {
			conn.Close()
			return nil
		})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("real TCP listener remained blocked after context cancellation")
	}

	rebound, err := net.ListenTCP("tcp6", addr)
	if err != nil {
		t.Fatalf("reverse listener did not release %s after cancellation: %v", addr, err)
	}
	rebound.Close()
}

func TestServeTCPReverseListenerClosesOnceOnAcceptFailure(t *testing.T) {
	listener := &failingReverseTCPListener{}
	serveTCPReverseListener(context.Background(), &net.TCPAddr{IP: net.IPv6loopback, Port: 9000}, listener, func(*net.TCPConn) error {
		t.Fatal("connection handler must not run")
		return nil
	})
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("listener Close called %d times, want exactly once", got)
	}
}

type failingReverseTCPListener struct {
	closeCalls atomic.Int32
}

func (*failingReverseTCPListener) AcceptTCP() (*net.TCPConn, error) {
	return nil, errors.New("accept failed")
}

func (l *failingReverseTCPListener) Close() error {
	l.closeCalls.Add(1)
	return nil
}
