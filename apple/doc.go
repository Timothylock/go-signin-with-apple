// Package apple provides a client for Apple's Sign in with Apple REST API.
//
// It covers the full lifecycle of Sign in with Apple on your server:
//
//   - Validating authorization codes from iOS apps and web flows
//   - Verifying ID token signatures against Apple's JWKS with automatic caching
//   - Refreshing and revoking access tokens
//   - Parsing ID token claims into typed Go structs
//   - Migrating user identifiers when an app transfers between developer teams
//   - Parsing and verifying server-to-server event notifications (account deletion, consent revoked)
//
// # Getting Started
//
// Create a client and generate a client secret, then validate the authorization
// code your app received from Apple:
//
//	secret, err := apple.GenerateClientSecret(signingKey, teamID, clientID, keyID)
//
//	client := apple.New()
//
//	var resp apple.ValidationResponse
//	err = client.VerifyAppToken(ctx, apple.AppValidationTokenRequest{
//	    ClientID:     clientID,
//	    ClientSecret: secret,
//	    Code:         authorizationCode,
//	}, &resp)
//
// # ID Token Verification
//
// [Client.VerifyIDToken] fetches Apple's public JWKS, verifies the RS256 signature,
// and validates iss/aud/exp in one call. This is the recommended way to verify an
// id_token received directly from a client device:
//
//	claims, err := client.VerifyIDToken(ctx, idToken, clientID)
//	fmt.Println(claims.Subject)        // stable unique user ID
//	fmt.Println(claims.Email)
//	fmt.Println(claims.RealUserStatus) // 2 = likelyReal (iOS 14+)
//
// The JWKS is cached in memory (default 15 minutes) and refreshed automatically
// when a new key ID is encountered, handling Apple key rotations transparently.
//
// # ID Token Claims Without Signature Verification
//
// [GetTypedClaims] decodes the id_token JWT into an [IDTokenClaims] struct without
// verifying the signature. This is safe when the token was obtained via a server-side
// call to [Client.VerifyAppToken] or [Client.VerifyWebToken] over TLS.
// It handles Apple's quirk of encoding email_verified as either a JSON boolean
// or the string "true"/"false" depending on the token version.
//
// # User Migration
//
// When an app transfers to a new developer team, use [Client.GetUserMigrationInfo]
// to exchange the transfer_sub provided by the original team for the user's new
// identifier under your team. See Apple's TN3159 for the full migration flow.
//
// # Server Notifications
//
// Apple sends a signed JWT to a registered webhook URL when a user revokes access
// or deletes their Apple ID. Use [Client.ParseServerNotification] to verify the
// RS256 signature and parse the event. You must delete all user data within 30 days
// of an account-delete event. See Apple's TN3194 for details.
//
// # Customisation
//
// Use [NewWithOptions] to supply a custom HTTP client, timeout, JWKS cache TTL,
// or override individual endpoint URLs (useful for testing against a mock server).
package apple
