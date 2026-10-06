package server_auth

import (
	"net/http"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/util"
)

type FinishAuthenticationFunc func(username string, policy ssh3.AuthorizationPolicy, w http.ResponseWriter, r *http.Request)

// BearerAuth returns the bearer token
// Authorization header, if the request uses HTTP Basic Authentication.
// See RFC 2617, Section 2.
func BearerAuth(r *http.Request) (bearer string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	return ParseBearerAuth(auth)
}

// ParseBearerAuth parses an HTTP Bearer Authentication string.
func ParseBearerAuth(auth string) (bearer string, ok bool) {
	const prefix = "Bearer "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !util.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}
	// TODO: maybe validate the encoding format of the JWT token (at least verify that
	// it is base64-encoded)
	return string(auth[len(prefix):]), true
}

func HandleBearerAuth(username string, base64ConversationID string, handlerFunc ssh3.UnauthenticatedBearerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerString, ok := BearerAuth(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(bearerString, base64ConversationID, w, r)
	}
}

// currently only supports RS256 and EdDSA signing algorithms
func HandleJWTAuth(username string, identities []IdentityVerifier, handlerFunc FinishAuthenticationFunc) ssh3.UnauthenticatedBearerFunc {
	return func(unauthenticatedBearerString string, base64ConversationID string, w http.ResponseWriter, r *http.Request) {
		for _, identity := range identities {
			verified := identity.Verify(util.JWTTokenString{Token: unauthenticatedBearerString}, base64ConversationID)
			if verified {
				// authentication successful
				handlerFunc(username, identity.AuthorizationPolicy(), w, r)
				return
			}
		}

		// TODO: logging
		w.WriteHeader(http.StatusUnauthorized)
	}
}
