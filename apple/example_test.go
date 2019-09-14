package apple

import (
	"context"
	"fmt"
	"testing"

	applesignin "github.com/Timothylock/go-signin-with-apple"
)

/*
Here are some examples on how to call the code and in what order to do so
*/

func TestValidatingTokenAndObtainingID(t *testing.T) {
	// Your 10-character Team ID
	team_id := "XXXXXXXXXX"

	// ClientID is the "Services ID" value that you get when navigating to your "sign in with Apple"-enabled service ID
	client_id := "com.your.app"

	// Find the 10-char Key ID value from the portal
	key_id := "XXXXXXXXXX"

	// The contents of the p8 file/key you downloaded when you made the key in the portal
	secret := `-----BEGIN PRIVATE KEY-----
	YOUR_SECRET_PRIVATE_KEY
	-----END PRIVATE KEY-----`

	// Generate the client secret used to authenticate with Apple's validation servers
	secret, err := applesignin.GenerateClientSecret(secret, team_id, client_id, key_id)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Generate a new validation client
	client := applesignin.New()

	vReq := applesignin.ValidationRequest{
		ClientID:     client_id,
		ClientSecret: secret,
		Code:         "the_token_to_validatte",
		RedirectURI:  "https://example.com", // This URL must be validated with apple in your service
		GrantType:    "authorization_code",
	}

	var resp ValidationResponse

	// Do the verification
	err = client.Verify(context.Background(), vReq, &resp)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	unique, err := GetUniqueID(resp.IdToken)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Voila!
	fmt.Println(unique)
}
