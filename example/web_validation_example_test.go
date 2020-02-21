package example

import (
	"context"
	"fmt"
	"testing"

	"github.com/Timothylock/go-signin-with-apple/apple"
)

/*
This example shows you how to validate a web token for the first time
*/

func TestValidatingWebTokenAndObtainingID(t *testing.T) {
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

	vReq := apple.WebValidationTokenRequest{
		ClientID:     clientID,
		ClientSecret: secret,
		Code:         "the_token_to_validate",
		RedirectURI:  "https://example.com", // This URL must be validated with apple in your service
	}

	var resp apple.ValidationResponse

	// Do the verification
	err = client.VerifyWebToken(context.Background(), vReq, &resp)
	if err != nil {
		fmt.Println("error verifying: " + err.Error())
		return
	}

	if resp.Error != "" {
		fmt.Println("apple returned an error: " + resp.Error)
		return
	}

	// Get the unique user ID
	unique, err := apple.GetUniqueID(resp.IDToken)
	if err != nil {
		fmt.Println("failed to get unique ID: " + err.Error())
		return
	}

	// Get the email
	claim, err := apple.GetClaims(resp.IDToken)
	if err != nil {
		fmt.Println("failed to get claims: " + err.Error())
		return
	}

	email := (*claim)["email"]
	emailVerified := (*claim)["email_verified"]
	isPrivateEmail := (*claim)["is_private_email"]

	// Voila!
	fmt.Println(unique)
	fmt.Println(email)
	fmt.Println(emailVerified)
	fmt.Println(isPrivateEmail)
}
