package apple

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ParseServerNotification parses the JWT sent by Apple's server-to-server notification
// system and returns the typed event payload.
//
// Apple sends these notifications when a user deletes their account or revokes Sign in with Apple
// access. The webhook URL is configured in the Apple Developer portal.
// See https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
//
// Note: signature verification against Apple's public keys is not yet implemented.
func (c *Client) ParseServerNotification(_ context.Context, jwtPayload string) (*ServerNotificationClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(jwtPayload, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	m, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
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
