package server_pubkey_authentication

import (
	"crypto"
	"fmt"
	"net/http"
	"time"

	ssh3 "github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/plugins"
	"github.com/francoismichel/ssh3/server_auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// impements server-side pubkey-based authentication

const PLUGIN_NAME = "github.com/francoismichel/ssh3-server_pubkey_auth"

// The timestamps remain part of the public-key JWT wire format, but freshness
// comes from the signed TLS-exporter-derived conversation ID.  Checking iat or
// exp against the verifier's wall clock would add an NTP-dependent denial of
// service without preventing replay in another conversation.  Keep a bounded,
// internally consistent declared interval so malformed tokens still fail
// closed, while authentication itself remains independent of clock skew.
const maxPubkeyTokenDeclaredLifetime = 30 * time.Second

func init() {
	if err := plugins.RegisterServerAuthPlugin(PLUGIN_NAME, PubkeyAuthPlugin); err != nil {
		log.Error().Msgf("could not register plugin %s: %s", PLUGIN_NAME, err)
	}
}

type PubkeyJWTIdentityVerifier struct {
	username string
	pubkey   crypto.PublicKey
	policy   ssh3.AuthorizationPolicy
	keyID    string
}

func (v *PubkeyJWTIdentityVerifier) AuthorizationPolicy() ssh3.AuthorizationPolicy {
	return v.policy
}

func (v *PubkeyJWTIdentityVerifier) CredentialID() string {
	return v.keyID
}

func (v *PubkeyJWTIdentityVerifier) Verify(request *http.Request, base64ConversationID string) bool {
	jwtToken, wellFormattedB64Token := server_auth.ParseBearerAuth(request.Header.Get("Authorization"))
	if !wellFormattedB64Token {
		return false
	}

	token, err := jwt.Parse(jwtToken,
		func(unvalidatedToken *jwt.Token) (interface{}, error) {
			log.Debug().Msgf("token method: %s, pubkey = %T %+v", unvalidatedToken.Method.Alg(), v.pubkey, v.pubkey)
			switch unvalidatedToken.Method.Alg() {
			case "RS256", "EdDSA", "ES256":
				return v.pubkey, nil
			}
			return nil, fmt.Errorf("unsupported signature algorithm '%s' for %T", unvalidatedToken.Method.Alg(), v)
		},
		jwt.WithoutClaimsValidation(),
		jwt.WithValidMethods([]string{"RS256", "EdDSA", "ES256"}))
	if err != nil || !token.Valid {
		log.Error().Msgf("invalid private key token: %s", err)
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Error().Msgf("bad JWT claims type: %T", token.Claims)
		return false
	}
	issuer, err := claims.GetIssuer()
	if err != nil || issuer != v.username {
		return false
	}
	subject, err := claims.GetSubject()
	if err != nil || subject != "ssh3" {
		return false
	}
	audiences, err := claims.GetAudience()
	if err != nil || !containsAudience(audiences, "unused") {
		return false
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return false
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return false
	}
	declaredLifetime := expiresAt.Time.Sub(issuedAt.Time)
	if declaredLifetime <= 0 || declaredLifetime > maxPubkeyTokenDeclaredLifetime {
		return false
	}
	if clientID, ok := claims["client_id"]; !ok || clientID != fmt.Sprintf("ssh3-%s", v.username) {
		return false
	}
	if jti, ok := claims["jti"]; !ok || jti != base64ConversationID {
		log.Error().Msg("public-key verification failed: jti is not bound to this conversation")
		return false
	}

	return true
}

func containsAudience(audiences jwt.ClaimStrings, expected string) bool {
	for _, audience := range audiences {
		if audience == expected {
			return true
		}
	}
	return false
}

func PubkeyAuthPlugin(username string, identityStr string) (auth.RequestIdentityVerifier, error) {
	log.Debug().Msgf("pubkey auth plugin: parse identity string")
	pubkey, _, options, _, err := ssh.ParseAuthorizedKey([]byte(identityStr))
	// we should not return an error when the format does not match a public key, we should just return a nil RequestIdentityVerifier
	if err != nil {
		log.Debug().Msgf("the identity string is not a compatible pubkey string")
		return nil, nil
	}

	log.Debug().Msg("parsing ssh authorized key")
	switch pubkey.Type() {
	case "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519":
		policy, err := server_auth.ParseAuthorizedKeyOptions(options)
		if err != nil {
			return nil, fmt.Errorf("invalid authorized key restrictions: %w", err)
		}
		log.Debug().Msgf("parsing %s identity", pubkey.Type())
		cryptoPublicKey := pubkey.(ssh.CryptoPublicKey)
		return &PubkeyJWTIdentityVerifier{
			pubkey:   cryptoPublicKey.CryptoPublicKey(),
			username: username,
			policy:   policy,
			keyID:    ssh.FingerprintSHA256(pubkey),
		}, nil

	default:
		return nil, fmt.Errorf("SSH authorized identity \"%s\" not implemented", pubkey.Type())
	}
}
