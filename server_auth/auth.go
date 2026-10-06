package server_auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/util/unix_util"

	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

func HandleAuths(ctx context.Context, enablePasswordLogin bool, defaultMaxPacketSize uint64, handlerFunc ssh3.AuthenticatedHandlerFunc) (http.HandlerFunc, error) {
	if runtime.GOOS != "linux" && enablePasswordLogin {
		return nil, fmt.Errorf("password login not supported on %s/%s systems", runtime.GOOS, runtime.GOARCH)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", ssh3.GetCurrentVersionString())
		peerVersion, err := ssh3.ParseVersionString(r.UserAgent())
		log.Debug().Msgf("received request from User-Agent %s", r.UserAgent())
		log.Debug().Msgf("peer version: protocol version %s, software version %s", peerVersion.GetProtocolVersion(), peerVersion.GetSoftwareVersion())
		// currently apply strict version rules
		if err != nil {
			userAgent := r.UserAgent()
			if len(userAgent) > 100 {
				userAgent = userAgent[:100]
			}
			http.Error(w, fmt.Sprintf("Unsupported user-agent: %s", userAgent), http.StatusForbidden)
			return
		}
		if !ssh3.IsVersionSupported(peerVersion) {
			http.Error(w, fmt.Sprintf("Unsupported version: %s not supported by server with version %s", peerVersion.GetProtocolVersion(), ssh3.ThisVersion().GetProtocolVersion()), http.StatusForbidden)
			return
		}
		// Only call Flush() here, as calling flush prevents from adding the Content-Length header to the response
		// The Content-Length can be useful upon receiving an error response
		defer w.(http.Flusher).Flush()
		httpStreamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			log.Error().Msgf("failed to take over HTTP/3 stream")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		qconn, ok := ssh3.ConnectionFromContext(r.Context())
		if !ok {
			log.Error().Msgf("missing QUIC connection in request context")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !qconn.ConnectionState().TLS.HandshakeComplete {
			// do not process early data (0-RTT) when performing authorization
			// to avoid replay attacks
			w.WriteHeader(http.StatusTooEarly)
			return
		}
		tlsState := qconn.ConnectionState().TLS
		convID, err := ssh3.GenerateConversationID(&tlsState)
		if err != nil {
			log.Error().Msgf("could not generate conversation ID")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		base64ConvID := base64.StdEncoding.EncodeToString(convID[:])
		finishAuthentication := func(username string, policy ssh3.AuthorizationPolicy, responseWriter http.ResponseWriter, request *http.Request) {
			conversation, err := ssh3.NewServerConversation(ctx, nil, qconn, nil, defaultMaxPacketSize, peerVersion)
			if err != nil {
				log.Error().Err(err).Msg("could not create authenticated server conversation")
				responseWriter.WriteHeader(http.StatusInternalServerError)
				return
			}
			conversation.SetAuthorizationPolicy(policy)
			conversation.AttachServerControlStream(httpStreamer.HTTPStream())
			handlerFunc(username, conversation, responseWriter, request)
		}

		username := r.URL.User.Username()
		if username == "" {
			username = r.URL.Query().Get("user")
		}
		user, err := unix_util.GetUser(username)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identityVerifiers, err := GetAuthorizedIdentities(user)
		if err != nil {
			log.Error().Msgf("error in JWT auth handling when retrieving authorized identities: %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// first, handle the HTTP request verifiers (often plugins)
		for _, abstractVerifier := range identityVerifiers {
			switch verifier := abstractVerifier.(type) {
			case *WrappedPluginVerifier:
				if verifier.Verify(r, base64ConvID) {
					log.Debug().Msgf("request for user %s successfully verified by plugin", username)
					finishAuthentication(username, verifier.AuthorizationPolicy(), w, r)
					return
				}
			}
		}

		log.Debug().Msgf("no suitable plugin found to authenticate the request")

		authorization := r.Header.Get("Authorization")
		if enablePasswordLogin && strings.HasPrefix(authorization, "Basic ") {
			HandleBasicAuth(finishAuthentication)(w, r)
		} else if strings.HasPrefix(authorization, "Bearer ") {
			HandleBearerAuth(username, base64ConvID, HandleJWTAuth(username, identityVerifiers, finishAuthentication))(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}, nil
}

func HandleBasicAuth(handlerFunc FinishAuthenticationFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ok, err := unix_util.UserPasswordAuthentication(username, password)
		if err != nil || !ok {
			if err != nil {
				log.Error().Msgf("user authentication failed: %s", err)
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(username, unrestrictedPolicy(), w, r)
	}
}
