package example

import (
	"context"
	"fmt"
	"testing"

	"github.com/Timothylock/go-signin-with-apple/apple"
)

/*
This example shows you how to revoke an refresh token
*/

func TestRevokeRefreshToken(t *testing.T) {
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

	vReq := apple.RevokeRefreshTokenRequest{
		ClientID:     clientID,
		ClientSecret: secret,
		RefreshToken: "the_refresh_code_to_revoke",
	}

	var resp apple.RevokeResponse

	// Revoke the token
	err = client.RevokeRefreshToken(context.Background(), vReq, &resp)
	if err != nil {
		fmt.Println("error revoking: " + err.Error())
		return
	}

	if resp.Error != "" {
		fmt.Printf("apple returned an error: %s - %s\n", resp.Error, resp.ErrorDescription)
		return
	}

	// Voila!
	fmt.Println("token revoked")
}
