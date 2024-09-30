package example

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/steptospace/go-signin-with-apple/apple/apple"
)

/*
This example shows you how to validate a refresh token
*/

func TestValidatingRefreshToken(t *testing.T) {
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
	client := apple.New(http.DefaultClient)

	vReq := apple.ValidationRefreshRequest{
		ClientID:     clientID,
		ClientSecret: secret,
		RefreshToken: "the_refresh_code_to_validate",
	}

	var resp apple.RefreshResponse

	// Do the verification
	err = client.VerifyRefreshToken(context.Background(), vReq, &resp)
	if err != nil {
		fmt.Println("error verifying: " + err.Error())
		return
	}

	if resp.Error != "" {
		fmt.Printf("apple returned an error: %s - %s\n", resp.Error, resp.ErrorDescription)
		return
	}

	// Voila!
	fmt.Println(resp)
}
