package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func hookEnvValue(environment []string, name string) string {
	prefix := name + "="
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func TestCMXsafeSessionHooksRunInLifecycleOrder(t *testing.T) {
	var events []string
	var startID string
	var hooks *cmxsafeSessionHooks
	hooks = &cmxsafeSessionHooks{
		startPath: "/hooks/start",
		endPath:   "/hooks/end",
		timeout:   time.Second,
		random:    bytes.NewReader(bytes.Repeat([]byte{0xa5}, cmxsafeSessionIDLen)),
		run: func(_ context.Context, path string, environment []string) error {
			if got := hookEnvValue(environment, cmxsafeUsernameEnv); got != "identity-user" {
				t.Fatalf("username environment = %q", got)
			}
			sessionID := hookEnvValue(environment, cmxsafeSessionIDEnv)
			if _, err := hex.DecodeString(sessionID); err != nil || len(sessionID) != cmxsafeSessionIDLen*2 {
				t.Fatalf("invalid session ID %q", sessionID)
			}
			if path == hooks.startPath {
				startID = sessionID
				events = append(events, "start")
			} else {
				if sessionID != startID {
					t.Fatalf("end session ID %q differs from start %q", sessionID, startID)
				}
				events = append(events, "end")
			}
			return nil
		},
	}

	err := hooks.runConversation(context.Background(), "identity-user", func() error {
		events = append(events, "accept-channels")
		return nil
	})
	if err != nil {
		t.Fatalf("run conversation: %v", err)
	}
	if got, want := strings.Join(events, ","), "start,accept-channels,end"; got != want {
		t.Fatalf("events = %q, want %q", got, want)
	}
}

func TestCMXsafeSessionStartFailureIsClosedAndRunsEndOnce(t *testing.T) {
	var startCalls, endCalls, conversationCalls int
	hooks := &cmxsafeSessionHooks{
		startPath: "/hooks/start",
		endPath:   "/hooks/end",
		timeout:   time.Second,
		random:    bytes.NewReader(bytes.Repeat([]byte{1}, cmxsafeSessionIDLen)),
		run: func(_ context.Context, path string, _ []string) error {
			switch path {
			case "/hooks/start":
				startCalls++
				return errors.New("secret hook failure details")
			case "/hooks/end":
				endCalls++
			}
			return nil
		},
	}

	err := hooks.runConversation(context.Background(), "identity-user", func() error {
		conversationCalls++
		return nil
	})
	if err == nil || err.Error() != "CMXsafe session start hook failed" {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("hook error leaked details")
	}
	if startCalls != 1 || endCalls != 1 || conversationCalls != 0 {
		t.Fatalf("calls: start=%d end=%d conversation=%d", startCalls, endCalls, conversationCalls)
	}
}

func TestCMXsafeSessionStartTimeoutIsClosed(t *testing.T) {
	var endCalls int
	hooks := &cmxsafeSessionHooks{
		startPath: "/hooks/start",
		endPath:   "/hooks/end",
		timeout:   10 * time.Millisecond,
		random:    bytes.NewReader(bytes.Repeat([]byte{2}, cmxsafeSessionIDLen)),
		run: func(ctx context.Context, path string, _ []string) error {
			if path == "/hooks/end" {
				endCalls++
				return nil
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}

	err := hooks.runConversation(context.Background(), "identity-user", func() error {
		t.Fatal("conversation ran after start timeout")
		return nil
	})
	if err == nil || err.Error() != "CMXsafe session start hook timed out" {
		t.Fatalf("error = %v", err)
	}
	if endCalls != 1 {
		t.Fatalf("end calls = %d", endCalls)
	}
}

func TestCMXsafeSessionIDsAreUnique(t *testing.T) {
	var mutex sync.Mutex
	ids := make(map[string]bool)
	hooks := newCMXsafeSessionHooks("/hooks/start", "", time.Second)
	hooks.run = func(_ context.Context, _ string, environment []string) error {
		mutex.Lock()
		defer mutex.Unlock()
		id := hookEnvValue(environment, cmxsafeSessionIDEnv)
		if ids[id] {
			t.Fatalf("duplicate session ID %q", id)
		}
		ids[id] = true
		return nil
	}

	for i := 0; i < 128; i++ {
		if err := hooks.runConversation(context.Background(), "identity-user", func() error { return nil }); err != nil {
			t.Fatalf("conversation %d: %v", i, err)
		}
	}
	if len(ids) != 128 {
		t.Fatalf("unique session IDs = %d", len(ids))
	}
}

func TestCMXsafeSessionEndTimeoutRunsOnceAndDoesNotReplaceConversationResult(t *testing.T) {
	var endCalls int
	conversationError := errors.New("conversation ended")
	hooks := &cmxsafeSessionHooks{
		endPath: "/hooks/end",
		timeout: 10 * time.Millisecond,
		random:  bytes.NewReader(bytes.Repeat([]byte{3}, cmxsafeSessionIDLen)),
		run: func(ctx context.Context, _ string, _ []string) error {
			endCalls++
			<-ctx.Done()
			return ctx.Err()
		},
	}

	started := time.Now()
	err := hooks.runConversation(context.Background(), "identity-user", func() error {
		return conversationError
	})
	if !errors.Is(err, conversationError) {
		t.Fatalf("conversation error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("end hook timeout took %s", elapsed)
	}
	if endCalls != 1 {
		t.Fatalf("end calls = %d", endCalls)
	}
}

func TestCMXsafeSessionFinishIsIdempotent(t *testing.T) {
	var endCalls int
	hooks := &cmxsafeSessionHooks{
		endPath: "/hooks/end",
		timeout: time.Second,
		random:  bytes.NewReader(bytes.Repeat([]byte{4}, cmxsafeSessionIDLen)),
		run: func(_ context.Context, _ string, _ []string) error {
			endCalls++
			return nil
		},
	}

	finish, err := hooks.begin(context.Background(), "identity-user")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	finish()
	finish()
	if endCalls != 1 {
		t.Fatalf("end calls = %d", endCalls)
	}
}

func TestCMXsafeSessionHooksAreOptIn(t *testing.T) {
	called := false
	var hooks *cmxsafeSessionHooks
	if err := hooks.runConversation(context.Background(), "identity-user", func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("conversation: %v", err)
	}
	if !called {
		t.Fatal("conversation was not called")
	}
	if err := validateCMXsafeSessionHookConfiguration("", "/hooks/start", "", time.Second); err == nil {
		t.Fatal("hook was accepted outside CMXsafe mode")
	}
	if err := validateCMXsafeSessionHookConfiguration("gateway.example", "/hooks/start", "", 0); err == nil {
		t.Fatal("zero hook timeout was accepted")
	}
	if err := validateCMXsafeSessionHookConfiguration("gateway.example", "relative/start", "", time.Second); err == nil {
		t.Fatal("relative hook path was accepted")
	}
}
