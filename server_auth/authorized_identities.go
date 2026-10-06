package server_auth

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"reflect"
	"strings"

	ssh3 "github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/oidc"
	"github.com/francoismichel/ssh3/internal"
	"github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/unix_util"

	"github.com/rs/zerolog/log"
)

type IdentityVerifier interface {
	// returns whether the provided candidate contains a sufficient proof to
	// be considered as equivalent to this identity
	Verify(candidate interface{}, base64ConversationID string) bool
	AuthorizationPolicy() ssh3.AuthorizationPolicy
}

func unrestrictedPolicy() ssh3.AuthorizationPolicy {
	return ssh3.UnrestrictedAuthorizationPolicy()
}

func DefaultIdentitiesFileNames(user *unix_util.User) []string {
	return []string{path.Join(user.Dir, ".ssh3", "authorized_identities"), path.Join(user.Dir, ".ssh", "authorized_keys")}
}

type OpenIDConnectIdentity struct {
	clientID  string
	issuerURL string
	email     string
}

func (i *OpenIDConnectIdentity) Verify(genericCandidate interface{}, base64ConversationID string) bool {
	// TODO: verify that the base64ConversationID is also present in the token
	log.Debug().Msgf("verifying openid connect idenitity")
	switch candidate := genericCandidate.(type) {
	case util.JWTTokenString:
		token, err := oidc.VerifyRawToken(context.Background(), i.clientID, i.issuerURL, candidate.Token)
		if err != nil {
			log.Error().Msgf("cannot verify raw token: %s", err.Error())
			return false
		}

		log.Debug().Msgf("token signature verification successful")

		if token.Issuer != i.issuerURL {
			log.Error().Msgf("cannot verify idendity: bad issuer: %s != %s", token.Issuer, i.issuerURL)
			return false
		}

		var claims struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err := token.Claims(&claims); err != nil {
			log.Error().Msgf("error verifying claims: %s", err)
			return false
		}

		valid := token != nil && claims.EmailVerified && claims.Email == i.email

		if !valid {
			log.Error().Msgf("invalid token: email should be: %s received claims: %+v", i.email, claims)
		}

		return valid
	default:
		return false
	}
}

func (i *OpenIDConnectIdentity) AuthorizationPolicy() ssh3.AuthorizationPolicy {
	return unrestrictedPolicy()
}

type WrappedPluginVerifier struct {
	auth.RequestIdentityVerifier
}

func (w *WrappedPluginVerifier) Verify(genericCandidate interface{}, base64ConversationID string) bool {
	switch candidate := genericCandidate.(type) {
	case *http.Request:
		return w.RequestIdentityVerifier.Verify(candidate, base64ConversationID)
	}
	return false
}

func (w *WrappedPluginVerifier) AuthorizationPolicy() ssh3.AuthorizationPolicy {
	if verifier, ok := w.RequestIdentityVerifier.(interface {
		AuthorizationPolicy() ssh3.AuthorizationPolicy
	}); ok {
		return verifier.AuthorizationPolicy()
	}
	return unrestrictedPolicy()
}

func (w *WrappedPluginVerifier) CredentialID() string {
	if verifier, ok := w.RequestIdentityVerifier.(interface{ CredentialID() string }); ok {
		return verifier.CredentialID()
	}
	return ""
}

func unquoteAuthorizedKeyOption(value string) (string, error) {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", fmt.Errorf("authorized key option value must be quoted")
	}
	value = value[1 : len(value)-1]
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			result.WriteByte(value[i])
			continue
		}
		i++
		if i >= len(value) || (value[i] != '\\' && value[i] != '"') {
			return "", fmt.Errorf("invalid escape in authorized key option")
		}
		result.WriteByte(value[i])
	}
	if strings.IndexByte(result.String(), 0) >= 0 {
		return "", fmt.Errorf("authorized key option contains NUL")
	}
	return result.String(), nil
}

func ParseAuthorizedKeyOptions(options []string) (ssh3.AuthorizationPolicy, error) {
	policy := ssh3.AuthorizationPolicy{Initialized: true}
	var restrictAll, enablePortForwarding, disablePortForwarding bool
	for _, option := range options {
		switch option {
		case "restrict":
			restrictAll = true
		case "port-forwarding":
			enablePortForwarding = true
		case "no-port-forwarding":
			disablePortForwarding = true
		case "no-pty":
			policy.NoPTY = true
		case "no-agent-forwarding":
			policy.NoAgentForwarding = true
		case "no-X11-forwarding":
			// X11 forwarding is not implemented, so it is already denied.
		default:
			name, rawValue, hasValue := strings.Cut(option, "=")
			if !hasValue {
				return ssh3.AuthorizationPolicy{}, fmt.Errorf("unsupported authorized key option %q", option)
			}
			value, err := unquoteAuthorizedKeyOption(rawValue)
			if err != nil {
				return ssh3.AuthorizationPolicy{}, fmt.Errorf("parse %s: %w", name, err)
			}
			switch name {
			case "command":
				if policy.HasForceCommand {
					return ssh3.AuthorizationPolicy{}, fmt.Errorf("duplicate command option")
				}
				policy.HasForceCommand = true
				policy.ForceCommand = value
			case "permitopen":
				permission, err := ssh3.ParseForwardingPermission(value)
				if err != nil {
					return ssh3.AuthorizationPolicy{}, err
				}
				policy.PermitOpen = append(policy.PermitOpen, permission)
			case "permitlisten":
				permission, err := ssh3.ParseForwardingPermission(value)
				if err != nil {
					return ssh3.AuthorizationPolicy{}, err
				}
				policy.PermitListen = append(policy.PermitListen, permission)
			default:
				return ssh3.AuthorizationPolicy{}, fmt.Errorf("unsupported authorized key option %q", name)
			}
		}
	}
	if enablePortForwarding && disablePortForwarding {
		return ssh3.AuthorizationPolicy{}, fmt.Errorf("conflicting port-forwarding and no-port-forwarding options")
	}
	policy.NoPTY = policy.NoPTY || restrictAll
	policy.NoAgentForwarding = policy.NoAgentForwarding || restrictAll
	policy.NoPortForwarding = disablePortForwarding || (restrictAll && !enablePortForwarding)
	return policy, nil
}

func ParseIdentity(user *unix_util.User, identityStr string) (ret []IdentityVerifier, err error) {
	pluginIdentities := internal.FindIdentitiesFromAuthorizedIdentityString(user.Username, identityStr)
	log.Debug().Msgf("found %d identities from plugins", len(pluginIdentities))
	for _, pluginIdentity := range pluginIdentities {
		ret = append(ret, &WrappedPluginVerifier{RequestIdentityVerifier: pluginIdentity})
	}
	// now parse the oidc identity which is not implemented by a plugin yet
	if strings.HasPrefix(identityStr, "oidc") {
		nExpectedTokens := 4
		log.Debug().Msg("parsing oidc identity")
		tokens := strings.Fields(identityStr)
		if len(tokens) != nExpectedTokens {
			return nil, fmt.Errorf("bad identity format for oidc identity, %d tokens instead of the %d expected tokens, identity: %s",
				len(tokens),
				nExpectedTokens,
				identityStr)
		}
		clientID := tokens[1]
		issuerURL := tokens[2]
		email := tokens[3]
		log.Debug().Msgf("oidc identity parsing success: client_id: %s, issuer_url: %s, email: %s", clientID, issuerURL, email)
		ret = append(ret, &OpenIDConnectIdentity{
			clientID:  clientID,
			issuerURL: issuerURL,
			email:     email,
		})
	}
	if len(ret) == 0 {
		// either error or identity not implemented
		return nil, fmt.Errorf("unknown identity format")
	}
	return ret, nil
}

func ParseAuthorizedIdentitiesFile(user *unix_util.User, file *os.File) (identities []IdentityVerifier, err error) {
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber += 1
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			log.Info().Msgf("%s:%d: skip empty line", file.Name(), lineNumber)
			continue
		} else if line[0] == '#' {
			// commented line
			log.Info().Msgf("%s:%d: skip commented identity", file.Name(), lineNumber)
			continue
		}
		parsedIdentities, err := ParseIdentity(user, line)
		if err == nil {
			identities = append(identities, parsedIdentities...)
		} else {
			return nil, fmt.Errorf("%s:%d: cannot parse identity: %w", file.Name(), lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", file.Name(), err)
	}
	return identities, nil
}

func GetAuthorizedIdentities(user *unix_util.User) ([]IdentityVerifier, error) {
	filenames := DefaultIdentitiesFileNames(user)
	var identities []IdentityVerifier
	policiesByCredential := make(map[string]ssh3.AuthorizationPolicy)
	for _, filename := range filenames {
		identitiesFile, err := os.Open(filename)
		if err == nil {
			newIdentities, parseErr := ParseAuthorizedIdentitiesFile(user, identitiesFile)
			closeErr := identitiesFile.Close()
			if parseErr != nil {
				// TODO: logging
				log.Error().Msgf("error when parsing authorized identities: %s", parseErr)
				return nil, parseErr
			}
			if closeErr != nil {
				return nil, fmt.Errorf("close %s: %w", filename, closeErr)
			}
			for _, identity := range newIdentities {
				credential, ok := identity.(interface{ CredentialID() string })
				if !ok || credential.CredentialID() == "" {
					identities = append(identities, identity)
					continue
				}
				credentialID := credential.CredentialID()
				if previous, exists := policiesByCredential[credentialID]; exists {
					if !reflect.DeepEqual(previous, identity.AuthorizationPolicy()) {
						return nil, fmt.Errorf("credential %s appears with conflicting authorization policies", credentialID)
					}
					continue
				}
				policiesByCredential[credentialID] = identity.AuthorizationPolicy()
				identities = append(identities, identity)
			}
		} else if !os.IsNotExist(err) {
			log.Error().Msgf("error could not open %s: %s", filename, err)
			return nil, err
		}
	}
	return identities, nil
}
