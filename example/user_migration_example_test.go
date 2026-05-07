package example

import (
	"context"
	"fmt"
	"testing"

	"github.com/Timothylock/go-signin-with-apple/apple"
)

/*
This example shows you how to migrate a user's identifier when your app transfers
to a new developer team. Apple issues a transfer_sub to the original team; the
recipient team exchanges it for the user's new identifier using this endpoint.
See https://developer.apple.com/documentation/technotes/tn3159-migrating-sign-in-with-apple-users-for-an-app-transfer
*/

func TestUserMigration(t *testing.T) {
	// Your 10-character Team ID (recipient team)
	teamID := "XXXXXXXXXX"

	// ClientID is the "Services ID" of the recipient team's app
	clientID := "com.your.app"

	// Find the 10-char Key ID value from the portal
	keyID := "XXXXXXXXXX"

	// The contents of the p8 file/key downloaded from the recipient team's portal
	secret := `-----BEGIN PRIVATE KEY-----
YOUR_SECRET_PRIVATE_KEY
-----END PRIVATE KEY-----`

	// Generate the client secret used to authenticate with Apple's servers
	secret, err := apple.GenerateClientSecret(secret, teamID, clientID, keyID)
	if err != nil {
		fmt.Println("error generating secret: " + err.Error())
		return
	}

	// Generate a new validation client
	client := apple.New()

	// transfer_sub is the identifier provided by the original developer team
	mReq := apple.UserMigrationRequest{
		ClientID:     clientID,
		ClientSecret: secret,
		TransferSub:  "the_transfer_sub_from_original_team",
	}

	var resp apple.UserMigrationResponse

	// Exchange the transfer_sub for the user's new identifier on the recipient team
	err = client.GetUserMigrationInfo(context.Background(), mReq, &resp)
	if err != nil {
		fmt.Println("error fetching migration info: " + err.Error())
		return
	}

	if resp.Error != "" {
		fmt.Printf("apple returned an error: %s - %s\n", resp.Error, resp.ErrorDescription)
		return
	}

	// Voila! Use resp.Sub to link the transferred user to their existing account
	fmt.Println(resp.Sub)
	fmt.Println(resp.Email)
	fmt.Println(resp.EmailVerified)
}
