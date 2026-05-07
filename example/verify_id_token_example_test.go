package example

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Timothylock/go-signin-with-apple/apple"
)

/*
This example shows how to verify an ID token received directly from a client device
(iOS, macOS, or web). VerifyIDToken fetches Apple's public JWKS, verifies the RS256
signature, and validates iss/aud/exp in a single call.

Use this when the client sends you an id_token and you need to trust it without first
calling VerifyAppToken. The JWKS is cached for JWKSCacheTTL (default 15 minutes) and
refreshed automatically when Apple rotates keys.
*/

func TestVerifyIDToken(t *testing.T) {
	// ClientID is the "Services ID" value for web flows, or bundle ID for iOS.
	clientID := "com.your.app"

	// The id_token sent by the client after a successful Sign in with Apple.
	idToken := "the_id_token_from_the_client"

	// Create a client with the default JWKS cache TTL of 15 minutes.
	// Use NewWithOptions to tune the TTL or supply a custom HTTP client.
	client := apple.NewWithOptions(apple.ClientOptions{
		JWKSCacheTTL: 30 * time.Minute,
	})

	claims, err := client.VerifyIDToken(context.Background(), idToken, clientID)
	if err != nil {
		// Token is invalid, expired, or the signature does not match Apple's keys.
		fmt.Println("token verification failed: " + err.Error())
		return
	}

	fmt.Println(claims.Subject)        // stable unique user ID — use this as your primary key
	fmt.Println(claims.Email)          // present only if the user shared their email
	fmt.Println(claims.EmailVerified)  // bool
	fmt.Println(claims.IsPrivateEmail) // true if Apple private relay address
	fmt.Println(claims.RealUserStatus) // 2 = likelyReal (iOS 14+)
}
