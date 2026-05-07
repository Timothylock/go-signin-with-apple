package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKID = "test-key-id"

// generateTestKey creates an RSA key pair and a JWKS handler for use in tests.
func generateTestKey(t *testing.T) (*rsa.PrivateKey, http.HandlerFunc) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	nB64 := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.PublicKey.E)).Bytes())

	jwksBody, err := json.Marshal(map[string]interface{}{
		"keys": []map[string]interface{}{
			{"kty": "RSA", "kid": testKID, "use": "sig", "alg": "RS256", "n": nB64, "e": eB64},
		},
	})
	require.NoError(t, err)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	}
	return privKey, handler
}

// makeIDToken creates a signed Apple-style ID token for testing.
func makeIDToken(t *testing.T, privKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID
	signed, err := token.SignedString(privKey)
	require.NoError(t, err)
	return signed
}

func TestVerifyIDToken(t *testing.T) {
	privKey, jwksHandler := generateTestKey(t)
	jwksSrv := httptest.NewServer(http.HandlerFunc(jwksHandler))
	defer jwksSrv.Close()

	clientID := "com.example.app"

	validClaims := jwt.MapClaims{
		"iss":              AppleIssuer,
		"aud":              clientID,
		"sub":              "user123",
		"email":            "user@example.com",
		"email_verified":   true,
		"is_private_email": false,
		"real_user_status": float64(2),
		"auth_time":        float64(time.Now().Unix()),
		"iat":              float64(time.Now().Unix()),
		"exp":              float64(time.Now().Add(time.Hour).Unix()),
	}

	tests := []struct {
		name       string
		buildToken func() string
		clientID   string
		wantErr    bool
		check      func(t *testing.T, claims *IDTokenClaims)
	}{
		{
			name:       "valid token returns correct typed claims",
			buildToken: func() string { return makeIDToken(t, privKey, validClaims) },
			clientID:   clientID,
			wantErr:    false,
			check: func(t *testing.T, c *IDTokenClaims) {
				assert.Equal(t, "user123", c.Subject)
				assert.Equal(t, "user@example.com", c.Email)
				assert.True(t, c.EmailVerified)
				assert.Equal(t, 2, c.RealUserStatus)
				assert.Equal(t, AppleIssuer, c.Issuer)
				assert.Equal(t, clientID, c.Audience)
			},
		},
		{
			name:       "wrong audience is rejected",
			buildToken: func() string { return makeIDToken(t, privKey, validClaims) },
			clientID:   "com.other.app",
			wantErr:    true,
		},
		{
			name: "expired token is rejected",
			buildToken: func() string {
				return makeIDToken(t, privKey, jwt.MapClaims{
					"iss": AppleIssuer,
					"aud": clientID,
					"sub": "user123",
					"iat": float64(time.Now().Add(-2 * time.Hour).Unix()),
					"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
				})
			},
			clientID: clientID,
			wantErr:  true,
		},
		{
			name: "wrong issuer is rejected",
			buildToken: func() string {
				return makeIDToken(t, privKey, jwt.MapClaims{
					"iss": "https://evil.example.com",
					"aud": clientID,
					"sub": "user123",
					"iat": float64(time.Now().Unix()),
					"exp": float64(time.Now().Add(time.Hour).Unix()),
				})
			},
			clientID: clientID,
			wantErr:  true,
		},
		{
			name: "token signed by unknown key is rejected",
			buildToken: func() string {
				otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims)
				token.Header["kid"] = testKID
				signed, err := token.SignedString(otherKey)
				require.NoError(t, err)
				return signed
			},
			clientID: clientID,
			wantErr:  true,
		},
		{
			name: "token with unknown kid triggers cache refresh and fails",
			buildToken: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims)
				token.Header["kid"] = "unknown-kid"
				signed, err := token.SignedString(privKey)
				require.NoError(t, err)
				return signed
			},
			clientID: clientID,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewWithOptions(ClientOptions{AppleKeysURL: jwksSrv.URL})
			claims, err := c.VerifyIDToken(context.Background(), tt.buildToken(), tt.clientID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, claims)
			}
		})
	}
}

func TestVerifyIDTokenSkipVerification(t *testing.T) {
	// Sign with a key that is NOT in any JWKS server
	unregisteredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"iss":   AppleIssuer,
		"aud":   "com.example.app",
		"sub":   "user456",
		"email": "test@example.com",
		"iat":   float64(time.Now().Unix()),
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID
	signed, err := token.SignedString(unregisteredKey)
	require.NoError(t, err)

	c := NewWithOptions(ClientOptions{
		SkipIDTokenVerification: true,
		AppleKeysURL:            "http://should-not-be-called.invalid",
	})
	result, err := c.VerifyIDToken(context.Background(), signed, "com.example.app")
	require.NoError(t, err)
	assert.Equal(t, "user456", result.Subject)
	assert.Equal(t, "test@example.com", result.Email)
}

func TestJWKSCacheIsTimed(t *testing.T) {
	privKey, jwksHandler := generateTestKey(t)

	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		jwksHandler(w, r)
	}))
	defer srv.Close()

	// TTL of 100ms with a 200ms sleep gives ample headroom on loaded CI runners.
	c := NewWithOptions(ClientOptions{
		AppleKeysURL: srv.URL,
		JWKSCacheTTL: 100 * time.Millisecond,
	})

	claims := jwt.MapClaims{
		"iss": AppleIssuer,
		"aud": "com.example.app",
		"sub": "u1",
		"iat": float64(time.Now().Unix()),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := makeIDToken(t, privKey, claims)

	_, err := c.VerifyIDToken(context.Background(), token, "com.example.app")
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load(), "JWKS should be fetched once")

	// Second call within TTL — served from cache
	_, err = c.VerifyIDToken(context.Background(), token, "com.example.app")
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load(), "JWKS should be cached on second call")

	// Wait for TTL to expire, then verify cache is refreshed
	time.Sleep(200 * time.Millisecond)
	_, err = c.VerifyIDToken(context.Background(), token, "com.example.app")
	require.NoError(t, err)
	assert.Equal(t, int32(2), callCount.Load(), "JWKS should be refreshed after TTL expires")
}

func TestJWKSCacheRefreshesOnUnknownKID(t *testing.T) {
	privKey, jwksHandler := generateTestKey(t)

	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		jwksHandler(w, r)
	}))
	defer srv.Close()

	// Long TTL — cache won't expire, but an unknown kid should still trigger a refresh
	c := NewWithOptions(ClientOptions{
		AppleKeysURL: srv.URL,
		JWKSCacheTTL: time.Hour,
	})

	validClaims := jwt.MapClaims{
		"iss": AppleIssuer, "aud": "com.example.app", "sub": "u1",
		"iat": float64(time.Now().Unix()),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}

	// First call — fetches JWKS
	_, err := c.VerifyIDToken(context.Background(), makeIDToken(t, privKey, validClaims), "com.example.app")
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load())

	// Token with an unknown kid — should trigger a second JWKS fetch then fail
	unknownKIDToken := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims)
		tok.Header["kid"] = "unknown-kid"
		s, _ := tok.SignedString(privKey)
		return s
	}()
	_, err = c.VerifyIDToken(context.Background(), unknownKIDToken, "com.example.app")
	assert.Error(t, err)
	assert.Equal(t, int32(2), callCount.Load(), "unknown kid should trigger a JWKS refresh")
}

func TestGetTypedClaims(t *testing.T) {
	// Token where email_verified and is_private_email are strings (older Apple format)
	// Payload: {"iss":"https://appleid.apple.com","aud":"com.example.app","exp":1568395678,
	// "iat":1568395078,"sub":"082649.93391d8e1192f56b8c1ch39gs2a47e2.9732",
	// "email":"foo@bar.com","email_verified":"true","is_private_email":"true","auth_time":1568395076}
	oldFormatToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmV4YW1wbGUuYXBwIiwiZXhwIjoxNTY4Mzk1Njc4LCJpYXQiOjE1NjgzOTUwNzgsInN1YiI6IjA4MjY0OS45MzM5MWQ4ZTExOTJmNTZiOGMxY2gzOWdzMmE0N2UyLjk3MzIiLCJhdF9oYXNoIjoickU3b3Brb1BSeVBseV9Pc2Rhc2RFQ1ZnIiwiZW1haWwiOiJmb29AYmFyLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNTY4Mzk1MDc2fQ.yPyUS_5k8RMvfowGylHqiCJqYwe-AOGtpBnjvqP4Na8"

	claims, err := GetTypedClaims(oldFormatToken)
	require.NoError(t, err)

	assert.Equal(t, "foo@bar.com", claims.Email)
	assert.Equal(t, "082649.93391d8e1192f56b8c1ch39gs2a47e2.9732", claims.Subject)
	assert.Equal(t, AppleIssuer, claims.Issuer)
	assert.Equal(t, "com.example.app", claims.Audience)
	assert.True(t, claims.EmailVerified, "email_verified string 'true' should parse as true")
	assert.True(t, claims.IsPrivateEmail, "is_private_email string 'true' should parse as true")
	assert.Equal(t, int64(1568395076), claims.AuthTime)
}

func TestGetTypedClaimsInvalidToken(t *testing.T) {
	_, err := GetTypedClaims("not.a.token")
	assert.Error(t, err)
}
