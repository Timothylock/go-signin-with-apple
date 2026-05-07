// Package apple provides a client for Apple's Sign in with Apple REST API.
//
// It covers the full lifecycle of Sign in with Apple on your server:
//
//   - Validating authorization codes from iOS apps and web flows
//   - Refreshing and revoking access tokens
//   - Parsing ID token claims into typed Go structs
//   - Migrating user identifiers when an app transfers between developer teams
//   - Parsing server-to-server event notifications (account deletion, consent revoked)
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
//	claims, err := apple.GetTypedClaims(resp.IDToken)
//	fmt.Println(claims.Subject) // stable unique user ID
//
// # ID Token Claims
//
// [GetTypedClaims] decodes the id_token JWT into an [IDTokenClaims] struct.
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
// or deletes their Apple ID. Use [Client.ParseAndVerifyServerNotification] to parse
// the event. You must delete all user data within 30 days of an account-delete event.
// See Apple's TN3194 for details.
//
// # Customisation
//
// Use [NewWithOptions] to supply a custom HTTP client, timeout, or override
// individual endpoint URLs (useful for testing against a mock server).
package apple
