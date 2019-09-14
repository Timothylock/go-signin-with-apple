package apple

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/tideland/gorest/jwt"
)

const (
	// ValidationURL is the endpoint for verifying tokens
	ValidationURL string = "https://appleid.apple.com/auth/token"
	// ContentType is the request content-type for apple store.
	ContentType string = "application/json; charset=utf-8"
)

// ValidationClient is an interface to call the validation API
type ValidationClient interface {
	Verify(ctx context.Context, token string, resp interface{}) error
}

// Client implements ValidationClient
type Client struct {
	validationURL string
	client        *http.Client
}

// New creates a Client object
func New() *Client {
	client := &Client{
		validationURL: ValidationURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return client
}

// Verify sends the ValidationRequest and gets validation result
func (c *Client) Verify(ctx context.Context, reqBody ValidationRequest, result interface{}) error {
	data := url.Values{}
	data.Set("client_id", reqBody.ClientID)
	data.Set("client_secret", reqBody.ClientSecret)
	data.Set("code", reqBody.Code)
	data.Set("refresh_token", reqBody.RefreshToken)
	data.Set("redirect_uri", reqBody.RedirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequest("POST", c.validationURL+"?"+data.Encode(), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", ContentType)
	req = req.WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(result)
}

// GetUniqueID decodes the id_token response and returns the unique subject ID to identify the user
func GetUniqueID(idToken string) (string, error) {
	j, err := jwt.Decode(idToken)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", j.Claims()["sub"]), nil
}
