package apple

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ParseServerNotification verifies and parses the JWT sent by Apple's server-to-server
// notification system, returning the typed event payload.
//
// Apple sends these notifications when a user deletes their account or revokes Sign in with Apple
// access. The webhook URL is configured in the Apple Developer portal.
// See https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
//
// The JWT signature is verified against Apple's public JWKS using the same cached key set as
// VerifyIDToken. When ClientOptions.SkipIDTokenVerification is true, signature verification
// is skipped (for use in tests only).
func (c *Client) ParseServerNotification(ctx context.Context, jwtPayload string) (*ServerNotificationClaims, error) {
	var m jwt.MapClaims

	if c.skipVerify {
		token, _, err := new(jwt.Parser).ParseUnverified(jwtPayload, jwt.MapClaims{})
		if err != nil {
			return nil, err
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("invalid token claims")
		}
		m = claims
	} else {
		token, err := jwt.ParseWithClaims(jwtPayload, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("missing kid in token header")
			}
			return c.getPublicKey(ctx, kid)
		},
			jwt.WithIssuer(AppleIssuer),
			jwt.WithExpirationRequired(),
		)
		if err != nil {
			return nil, err
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			return nil, fmt.Errorf("invalid token")
		}
		m = claims
	}

	return serverNotificationClaimsFromMap(m)
}

func serverNotificationClaimsFromMap(m jwt.MapClaims) (*ServerNotificationClaims, error) {
	claims := &ServerNotificationClaims{}

	if v, ok := m["iss"].(string); ok {
		claims.Issuer = v
	}
	if v, ok := m["aud"].(string); ok {
		claims.Audience = v
	}
	if v, ok := m["jti"].(string); ok {
		claims.JTI = v
	}
	if v, ok := m["exp"].(float64); ok {
		claims.ExpiresAt = int64(v)
	}
	if v, ok := m["iat"].(float64); ok {
		claims.IssuedAt = int64(v)
	}

	// Apple embeds the events payload as a JSON-encoded string within the JWT claims
	eventsStr, ok := m["events"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid events claim in notification")
	}
	if err := json.Unmarshal([]byte(eventsStr), &claims.Events); err != nil {
		return nil, fmt.Errorf("failed to parse events payload: %w", err)
	}

	return claims, nil
}
