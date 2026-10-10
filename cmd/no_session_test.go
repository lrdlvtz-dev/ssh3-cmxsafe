package cmd

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestValidateNoSessionOptions(t *testing.T) {
	tests := []struct {
		name         string
		noSession    bool
		forwardAgent bool
		command      []string
		wantError    string
	}{
		{name: "default behavior accepts command", command: []string{"true"}},
		{name: "forwarding only", noSession: true},
		{name: "rejects command", noSession: true, command: []string{"true"}, wantError: "remote command"},
		{name: "rejects agent forwarding", noSession: true, forwardAgent: true, wantError: "session channel"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNoSessionOptions(tt.noSession, tt.forwardAgent, tt.command)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !contains(err.Error(), tt.wantError) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantError)
			}
		})
	}
}

func TestWaitWithoutSessionStopsCleanlyOnShutdown(t *testing.T) {
	connectionCtx, cancelConnection := context.WithCancelCause(context.Background())
	defer cancelConnection(errors.New("test cleanup"))
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	shutdown()

	if err := waitWithoutSession(connectionCtx, shutdownCtx); err != nil {
		t.Fatalf("waitWithoutSession returned error for local shutdown: %v", err)
	}
}

func TestWaitWithoutSessionReportsConnectionLoss(t *testing.T) {
	want := errors.New("transport lost")
	connectionCtx, cancelConnection := context.WithCancelCause(context.Background())
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	cancelConnection(want)

	err := waitWithoutSession(connectionCtx, shutdownCtx)
	if !errors.Is(err, want) {
		t.Fatalf("waitWithoutSession error = %v, want wrapped %v", err, want)
	}
}

func TestWaitWithoutSessionRemainsActive(t *testing.T) {
	connectionCtx, cancelConnection := context.WithCancelCause(context.Background())
	defer cancelConnection(errors.New("test cleanup"))
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	done := make(chan error, 1)
	go func() { done <- waitWithoutSession(connectionCtx, shutdownCtx) }()

	select {
	case err := <-done:
		t.Fatalf("waitWithoutSession returned before shutdown: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
