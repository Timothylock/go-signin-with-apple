package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeNotificationToken(t *testing.T, privKey *rsa.PrivateKey, kid string, baseClaims jwt.MapClaims, events interface{}) string {
	t.Helper()
	eventsJSON, err := json.Marshal(events)
	require.NoError(t, err)
	baseClaims["events"] = string(eventsJSON)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, baseClaims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(privKey)
	require.NoError(t, err)
	return signed
}

func TestParseAndVerifyServerNotification(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	validBaseClaims := jwt.MapClaims{
		"iss": AppleIssuer,
		"aud": "com.example.app",
		"jti": "abc123",
		"iat": float64(time.Now().Unix()),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	validEvents := map[string]interface{}{
		"type":       "consent-revoked",
		"sub":        "user789",
		"event_time": float64(time.Now().Unix()),
	}

	t.Run("valid notification is parsed correctly", func(t *testing.T) {
		payload := makeNotificationToken(t, privKey, "test-kid", validBaseClaims, validEvents)

		c := New()
		claims, err := c.ParseAndVerifyServerNotification(context.Background(), payload)
		require.NoError(t, err)

		assert.Equal(t, AppleIssuer, claims.Issuer)
		assert.Equal(t, "abc123", claims.JTI)
		assert.Equal(t, "consent-revoked", claims.Events.Type)
		assert.Equal(t, "user789", claims.Events.Sub)
	})

	t.Run("account-delete event type is parsed", func(t *testing.T) {
		deleteEvents := map[string]interface{}{
			"type":       "account-delete",
			"sub":        "user000",
			"event_time": float64(time.Now().Unix()),
		}
		payload := makeNotificationToken(t, privKey, "test-kid", validBaseClaims, deleteEvents)

		c := New()
		claims, err := c.ParseAndVerifyServerNotification(context.Background(), payload)
		require.NoError(t, err)
		assert.Equal(t, "account-delete", claims.Events.Type)
	})

	t.Run("notification without events claim returns error", func(t *testing.T) {
		noEventsClaims := jwt.MapClaims{
			"iss": AppleIssuer,
			"aud": "com.example.app",
			"iat": float64(time.Now().Unix()),
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, noEventsClaims)
		token.Header["kid"] = "test-kid"
		payload, err := token.SignedString(privKey)
		require.NoError(t, err)

		c := New()
		_, err = c.ParseAndVerifyServerNotification(context.Background(), payload)
		assert.Error(t, err)
	})

	t.Run("malformed jwt returns error", func(t *testing.T) {
		c := New()
		_, err := c.ParseAndVerifyServerNotification(context.Background(), "not.a.jwt")
		assert.Error(t, err)
	})
}
