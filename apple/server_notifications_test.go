package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeNotificationToken(t *testing.T, privKey *rsa.PrivateKey, kid string, baseClaims jwt.MapClaims, events interface{}) string {
	t.Helper()

	// Copy baseClaims to avoid mutating the caller's map across subtests
	claims := make(jwt.MapClaims, len(baseClaims)+1)
	for k, v := range baseClaims {
		claims[k] = v
	}
	eventsJSON, err := json.Marshal(events)
	require.NoError(t, err)
	claims["events"] = string(eventsJSON)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(privKey)
	require.NoError(t, err)
	return signed
}

func TestParseServerNotification(t *testing.T) {
	privKey, jwksHandler := generateTestKey(t)
	jwksSrv := httptest.NewServer(http.HandlerFunc(jwksHandler))
	defer jwksSrv.Close()

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

	t.Run("valid notification passes verification and parses correctly", func(t *testing.T) {
		payload := makeNotificationToken(t, privKey, testKID, validBaseClaims, validEvents)

		c := NewWithOptions(ClientOptions{AppleKeysURL: jwksSrv.URL})
		claims, err := c.ParseServerNotification(context.Background(), payload)
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
		payload := makeNotificationToken(t, privKey, testKID, validBaseClaims, deleteEvents)

		c := NewWithOptions(ClientOptions{AppleKeysURL: jwksSrv.URL})
		claims, err := c.ParseServerNotification(context.Background(), payload)
		require.NoError(t, err)
		assert.Equal(t, "account-delete", claims.Events.Type)
	})

	t.Run("tampered payload is rejected", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		payload := makeNotificationToken(t, otherKey, testKID, validBaseClaims, validEvents)

		c := NewWithOptions(ClientOptions{AppleKeysURL: jwksSrv.URL})
		_, err = c.ParseServerNotification(context.Background(), payload)
		assert.Error(t, err)
	})

	t.Run("expired notification is rejected", func(t *testing.T) {
		expiredClaims := jwt.MapClaims{
			"iss": AppleIssuer,
			"aud": "com.example.app",
			"iat": float64(time.Now().Add(-2 * time.Hour).Unix()),
			"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
		}
		payload := makeNotificationToken(t, privKey, testKID, expiredClaims, validEvents)

		c := NewWithOptions(ClientOptions{AppleKeysURL: jwksSrv.URL})
		_, err := c.ParseServerNotification(context.Background(), payload)
		assert.Error(t, err)
	})

	t.Run("notification without events claim returns error", func(t *testing.T) {
		noEventsClaims := jwt.MapClaims{
			"iss": AppleIssuer,
			"aud": "com.example.app",
			"iat": float64(time.Now().Unix()),
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, noEventsClaims)
		token.Header["kid"] = testKID
		payload, err := token.SignedString(privKey)
		require.NoError(t, err)

		c := NewWithOptions(ClientOptions{AppleKeysURL: jwksSrv.URL})
		_, err = c.ParseServerNotification(context.Background(), payload)
		assert.Error(t, err)
	})

	t.Run("skip verification bypasses signature check", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		payload := makeNotificationToken(t, otherKey, testKID, validBaseClaims, validEvents)

		c := NewWithOptions(ClientOptions{
			SkipIDTokenVerification: true,
			AppleKeysURL:            "http://should-not-be-called.invalid",
		})
		claims, err := c.ParseServerNotification(context.Background(), payload)
		require.NoError(t, err)
		assert.Equal(t, "consent-revoked", claims.Events.Type)
	})

	t.Run("malformed jwt returns error", func(t *testing.T) {
		c := NewWithOptions(ClientOptions{SkipIDTokenVerification: true})
		_, err := c.ParseServerNotification(context.Background(), "not.a.jwt")
		assert.Error(t, err)
	})
}
