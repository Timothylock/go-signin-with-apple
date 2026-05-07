package apple

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// AppleKeysURL is the endpoint that serves Apple's public JWKS for token signature verification.
	AppleKeysURL = "https://appleid.apple.com/auth/keys"
)

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// VerifyIDToken fetches Apple's public JWKS (with caching), verifies the RS256 signature
// on the id_token, validates the issuer, audience, and expiration, and returns typed claims.
//
// The JWKS is cached for JWKSCacheTTL (default 15 minutes). On a cache miss for a specific
// key ID the cache is refreshed immediately to handle key rotation.
//
// When ClientOptions.SkipIDTokenVerification is true, signature verification is skipped and
// claims are decoded without validation. For use in tests only.
func (c *Client) VerifyIDToken(ctx context.Context, idToken, clientID string) (*IDTokenClaims, error) {
	if c.skipVerify {
		return GetTypedClaims(idToken)
	}

	token, err := jwt.ParseWithClaims(idToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
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
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	m, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return idTokenClaimsFromMap(m), nil
}

// getPublicKey returns the RSA public key for the given kid.
// It uses the in-memory JWKS cache, refreshing when the cache is stale or the kid is unknown.
func (c *Client) getPublicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.jwksMu.RLock()
	key, found := c.jwksCache[kid]
	stale := time.Since(c.jwksFetchedAt) > c.jwksCacheTTL
	c.jwksMu.RUnlock()

	if found && !stale {
		return key, nil
	}

	// Cache is stale or kid not found — refresh from Apple
	if err := c.refreshJWKS(ctx); err != nil {
		return nil, err
	}

	c.jwksMu.RLock()
	key, found = c.jwksCache[kid]
	c.jwksMu.RUnlock()

	if !found {
		return nil, fmt.Errorf("public key with kid %q not found in Apple JWKS", kid)
	}
	return key, nil
}

// refreshJWKS fetches the current key set from Apple and replaces the in-memory cache.
func (c *Client) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.keysURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("user-agent", UserAgent)

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var jwks jwksResponse
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode Apple JWKS: %w", err)
	}

	newCache := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(key)
		if err != nil {
			return fmt.Errorf("invalid JWK with kid %q: %w", key.Kid, err)
		}
		newCache[key.Kid] = pubKey
	}

	c.jwksMu.Lock()
	c.jwksCache = newCache
	c.jwksFetchedAt = time.Now()
	c.jwksMu.Unlock()

	return nil
}

func jwkToRSAPublicKey(key jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	return &rsa.PublicKey{N: n, E: e}, nil
}
