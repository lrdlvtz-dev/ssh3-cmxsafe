package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

const testServerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
		serverID:  testServerID,
		run: func(_ context.Context, path string, environment []string) error {
			if got := hookEnvValue(environment, cmxsafeUsernameEnv); got != "identity-user" {
				t.Fatalf("username environment = %q", got)
			}
			if got := hookEnvValue(environment, cmxsafeServerIDEnv); got != testServerID {
				t.Fatalf("server ID environment = %q", got)
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
		serverID:  testServerID,
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
		serverID:  testServerID,
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
	hooks, err := newCMXsafeSessionHooks("/hooks/start", "", time.Second)
	if err != nil {
		t.Fatalf("new hooks: %v", err)
	}
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
		endPath:  "/hooks/end",
		timeout:  10 * time.Millisecond,
		random:   bytes.NewReader(bytes.Repeat([]byte{3}, cmxsafeSessionIDLen)),
		serverID: testServerID,
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
		endPath:  "/hooks/end",
		timeout:  time.Second,
		random:   bytes.NewReader(bytes.Repeat([]byte{4}, cmxsafeSessionIDLen)),
		serverID: testServerID,
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

func TestCMXsafeServerIDIsStableAcrossSessionsAndUniqueAcrossInstances(t *testing.T) {
	instanceAEntropy := make([]byte, 0, cmxsafeSessionIDLen*3)
	instanceAEntropy = append(instanceAEntropy, bytes.Repeat([]byte{0x10}, cmxsafeSessionIDLen)...)
	instanceAEntropy = append(instanceAEntropy, bytes.Repeat([]byte{0x11}, cmxsafeSessionIDLen)...)
	instanceAEntropy = append(instanceAEntropy, bytes.Repeat([]byte{0x12}, cmxsafeSessionIDLen)...)
	hooksA, err := newCMXsafeSessionHooksWithRandom(
		"/hooks/start", "", time.Second, bytes.NewReader(instanceAEntropy),
	)
	if err != nil {
		t.Fatalf("new instance A: %v", err)
	}
	var serverIDs, sessionIDs []string
	hooksA.run = func(_ context.Context, _ string, environment []string) error {
		serverIDs = append(serverIDs, hookEnvValue(environment, cmxsafeServerIDEnv))
		sessionIDs = append(sessionIDs, hookEnvValue(environment, cmxsafeSessionIDEnv))
		return nil
	}
	for i := 0; i < 2; i++ {
		if err := hooksA.runConversation(context.Background(), "identity-user", func() error { return nil }); err != nil {
			t.Fatalf("instance A session %d: %v", i, err)
		}
	}
	if serverIDs[0] != serverIDs[1] || serverIDs[0] != hooksA.serverID {
		t.Fatalf("server IDs were not stable: %q", serverIDs)
	}
	if sessionIDs[0] == sessionIDs[1] {
		t.Fatalf("session IDs were not unique: %q", sessionIDs)
	}

	hooksB, err := newCMXsafeSessionHooksWithRandom(
		"/hooks/start", "", time.Second,
		bytes.NewReader(bytes.Repeat([]byte{0x20}, cmxsafeSessionIDLen)),
	)
	if err != nil {
		t.Fatalf("new instance B: %v", err)
	}
	if hooksA.serverID == hooksB.serverID {
		t.Fatalf("server IDs match across instances: %q", hooksA.serverID)
	}
}

func TestCMXsafeServerIDGenerationFailureIsClosed(t *testing.T) {
	hooks, err := newCMXsafeSessionHooksWithRandom(
		"/hooks/start", "", time.Second, iotest.ErrReader(errors.New("entropy unavailable")),
	)
	if err == nil || err.Error() != "could not create CMXsafe server identifier" {
		t.Fatalf("error = %v", err)
	}
	if hooks != nil {
		t.Fatal("hooks returned after server ID generation failure")
	}
}

func TestCMXsafeHookEnvironmentReplacesInheritedIdentifiers(t *testing.T) {
	t.Setenv(cmxsafeUsernameEnv, "inherited-user")
	t.Setenv(cmxsafeSessionIDEnv, "inherited-session")
	t.Setenv(cmxsafeServerIDEnv, "inherited-server")
	environment := sessionHookEnvironment("current-user", "current-session", "current-server")

	for name, want := range map[string]string{
		cmxsafeUsernameEnv:  "current-user",
		cmxsafeSessionIDEnv: "current-session",
		cmxsafeServerIDEnv:  "current-server",
	} {
		if got := hookEnvValue(environment, name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
		count := 0
		for _, entry := range environment {
			if strings.HasPrefix(entry, name+"=") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s entries = %d", name, count)
		}
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
	disabledHooks, err := newCMXsafeSessionHooksWithRandom(
		"", "", time.Second, iotest.ErrReader(errors.New("must not read entropy")),
	)
	if err != nil || disabledHooks != nil {
		t.Fatalf("disabled hooks = %v, error = %v", disabledHooks, err)
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
