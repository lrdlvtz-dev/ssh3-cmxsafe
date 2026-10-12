package server_pubkey_authentication

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestVerifier(t *testing.T) (*PubkeyJWTIdentityVerifier, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &PubkeyJWTIdentityVerifier{username: "device", pubkey: publicKey}, privateKey
}

func signedRequest(t *testing.T, key ed25519.PrivateKey, claims jwt.MapClaims) *http.Request {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	request, err := http.NewRequest(http.MethodConnect, "https://gateway.example/ssh3", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+signed)
	return request
}

func pubkeyClaims(issuedAt, expiresAt time.Time, conversationID string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":       "device",
		"iat":       jwt.NewNumericDate(issuedAt),
		"exp":       jwt.NewNumericDate(expiresAt),
		"sub":       "ssh3",
		"aud":       "unused",
		"client_id": "ssh3-device",
		"jti":       conversationID,
	}
}

func TestPubkeyAuthenticationDoesNotDependOnWallClock(t *testing.T) {
	verifier, privateKey := newTestVerifier(t)
	now := time.Now()
	tests := []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
	}{
		{name: "client clock one day behind", issuedAt: now.Add(-24 * time.Hour), expiresAt: now.Add(-24*time.Hour + 10*time.Second)},
		{name: "client clock one day ahead", issuedAt: now.Add(24 * time.Hour), expiresAt: now.Add(24*time.Hour + 10*time.Second)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := signedRequest(t, privateKey, pubkeyClaims(test.issuedAt, test.expiresAt, "conversation-a"))
			if !verifier.Verify(request, "conversation-a") {
				t.Fatal("valid session-bound signature was rejected because of wall-clock skew")
			}
		})
	}
}

func TestPubkeyAuthenticationRejectsReplayInAnotherConversation(t *testing.T) {
	verifier, privateKey := newTestVerifier(t)
	now := time.Now()
	request := signedRequest(t, privateKey, pubkeyClaims(now, now.Add(10*time.Second), "conversation-a"))
	if !verifier.Verify(request, "conversation-a") {
		t.Fatal("valid token rejected in its bound conversation")
	}
	if verifier.Verify(request, "conversation-b") {
		t.Fatal("token replayed successfully in a different conversation")
	}
}

func TestPubkeyAuthenticationStillRejectsInvalidProofs(t *testing.T) {
	verifier, privateKey := newTestVerifier(t)
	now := time.Now()
	base := pubkeyClaims(now, now.Add(10*time.Second), "conversation-a")

	tests := []struct {
		name   string
		claims jwt.MapClaims
		key    ed25519.PrivateKey
	}{
		{name: "wrong issuer", claims: cloneClaims(base, "iss", "other"), key: privateKey},
		{name: "wrong subject", claims: cloneClaims(base, "sub", "other"), key: privateKey},
		{name: "wrong audience", claims: cloneClaims(base, "aud", "other"), key: privateKey},
		{name: "wrong client id", claims: cloneClaims(base, "client_id", "ssh3-other"), key: privateKey},
		{name: "missing issued at", claims: cloneClaims(base, "iat", nil), key: privateKey},
		{name: "missing expiration", claims: cloneClaims(base, "exp", nil), key: privateKey},
		{name: "invalid declared interval", claims: cloneClaims(base, "exp", jwt.NewNumericDate(now.Add(-time.Second))), key: privateKey},
		{name: "excessive declared interval", claims: cloneClaims(base, "exp", jwt.NewNumericDate(now.Add(time.Minute))), key: privateKey},
	}

	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	tests = append(tests, struct {
		name   string
		claims jwt.MapClaims
		key    ed25519.PrivateKey
	}{name: "wrong signature", claims: base, key: wrongKey})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := signedRequest(t, test.key, test.claims)
			if verifier.Verify(request, "conversation-a") {
				t.Fatal("invalid public-key proof was accepted")
			}
		})
	}
}

func cloneClaims(source jwt.MapClaims, key string, value any) jwt.MapClaims {
	copy := make(jwt.MapClaims, len(source))
	for claim, claimValue := range source {
		copy[claim] = claimValue
	}
	if value == nil {
		delete(copy, key)
	} else {
		copy[key] = value
	}
	return copy
}
