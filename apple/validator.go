package apple

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tideland/gorest/jwt"
)

const (
	// ValidationURL is the endpoint for verifying tokens
	ValidationURL string = "https://appleid.apple.com/auth/token"
)

// ValidationClient is an interface to call the validation API
type ValidationClient interface {
	VerifyNonAppToken(ctx context.Context, token string, resp interface{}) error
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

// NewWithURL creates a Client object with a custom URL provided
func NewWithURL(url string) *Client {
	client := &Client{
		validationURL: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return client
}

// VerifyNonAppToken sends the ValidationRequest and gets validation result
func (c *Client) VerifyNonAppToken(ctx context.Context, reqBody ValidationRequest, result interface{}) error {
	data := url.Values{}
	data.Set("client_id", reqBody.ClientID)
	data.Set("client_secret", reqBody.ClientSecret)
	data.Set("code", reqBody.Code)
	data.Set("redirect_uri", reqBody.RedirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequest("POST", c.validationURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("accept", "application/json")
	req.Header.Add("user-agent", "go-signin-with-apple") // apple requires a user agent

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(result)
}

// GetUniqueID decodes the id_token response and returns the unique subject ID to identify the user
func GetUniqueID(idToken string) (string, error) {
	j, err := jwt.Decode(idToken)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", j.Claims()["sub"]), nil
}
