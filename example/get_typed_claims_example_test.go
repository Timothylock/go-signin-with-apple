package example

import (
	"context"
	"fmt"
	"testing"

	"github.com/Timothylock/go-signin-with-apple/apple"
)

/*
This example shows you how to get typed claims from an ID token after validation.
GetTypedClaims handles Apple's quirk of returning email_verified as either a
boolean or the string "true"/"false" depending on the token version.
*/

func TestGetTypedClaims(t *testing.T) {
	// Your 10-character Team ID
	teamID := "XXXXXXXXXX"

	// ClientID is the "Services ID" value that you get when navigating to your "sign in with Apple"-enabled service ID
	clientID := "com.your.app"

	// Find the 10-char Key ID value from the portal
	keyID := "XXXXXXXXXX"

	// The contents of the p8 file/key you downloaded when you made the key in the portal
	secret := `-----BEGIN PRIVATE KEY-----
YOUR_SECRET_PRIVATE_KEY
-----END PRIVATE KEY-----`

	// Generate the client secret used to authenticate with Apple's validation servers
	secret, err := apple.GenerateClientSecret(secret, teamID, clientID, keyID)
	if err != nil {
		fmt.Println("error generating secret: " + err.Error())
		return
	}

	// Generate a new validation client
	client := apple.New()

	vReq := apple.AppValidationTokenRequest{
		ClientID:     clientID,
		ClientSecret: secret,
		Code:         "the_authorization_code_to_validate",
	}

	var resp apple.ValidationResponse

	// Do the verification
	err = client.VerifyAppToken(context.Background(), vReq, &resp)
	if err != nil {
		fmt.Println("error verifying: " + err.Error())
		return
	}

	if resp.Error != "" {
		fmt.Printf("apple returned an error: %s - %s\n", resp.Error, resp.ErrorDescription)
		return
	}

	// Parse the ID token into a typed struct — no unsafe map lookups or type assertions needed
	claims, err := apple.GetTypedClaims(resp.IDToken)
	if err != nil {
		fmt.Println("failed to get claims: " + err.Error())
		return
	}

	// Voila!
	fmt.Println(claims.Subject)
	fmt.Println(claims.Email)
	fmt.Println(claims.EmailVerified)
	fmt.Println(claims.IsPrivateEmail)
	fmt.Println(claims.RealUserStatus)
}
