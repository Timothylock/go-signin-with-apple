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
	// ContentType is the one expected by Apple
	ContentType string = "application/x-www-form-urlencoded"
	// UserAgent is required by Apple or the request will fail
	UserAgent string = "go-signin-with-apple"
	// AcceptHeader is the content that we are willing to accept
	AcceptHeader string = "application/json"
)

// ValidationClient is an interface to call the validation API
type ValidationClient interface {
	VerifyWebToken(ctx context.Context, reqBody WebValidationTokenRequest, result interface{}) error
	VerifyAppToken(ctx context.Context, reqBody AppValidationTokenRequest, result interface{}) error
	VerifyRefreshToken(ctx context.Context, reqBody ValidationRefreshRequest, result interface{}) error
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

// VerifyWebToken sends the WebValidationTokenRequest and gets validation result
func (c *Client) VerifyWebToken(ctx context.Context, reqBody WebValidationTokenRequest, result interface{}) error {
	data := url.Values{}
	data.Set("client_id", reqBody.ClientID)
	data.Set("client_secret", reqBody.ClientSecret)
	data.Set("code", reqBody.Code)
	data.Set("redirect_uri", reqBody.RedirectURI)
	data.Set("grant_type", "authorization_code")

	return doRequest(ctx, c.client, &result, c.validationURL, data)
}

// VerifyAppToken sends the AppValidationTokenRequest and gets validation result
func (c *Client) VerifyAppToken(ctx context.Context, reqBody AppValidationTokenRequest, result interface{}) error {
	data := url.Values{}
	data.Set("client_id", reqBody.ClientID)
	data.Set("client_secret", reqBody.ClientSecret)
	data.Set("code", reqBody.Code)
	data.Set("grant_type", "authorization_code")

	return doRequest(ctx, c.client, &result, c.validationURL, data)
}

// VerifyRefreshToken sends the WebValidationTokenRequest and gets validation result
func (c *Client) VerifyRefreshToken(ctx context.Context, reqBody ValidationRefreshRequest, result interface{}) error {
	data := url.Values{}
	data.Set("client_id", reqBody.ClientID)
	data.Set("client_secret", reqBody.ClientSecret)
	data.Set("refresh_token", reqBody.RefreshToken)
	data.Set("grant_type", "refresh_token")

	return doRequest(ctx, c.client, &result, c.validationURL, data)
}

// GetUniqueID decodes the id_token response and returns the unique subject ID to identify the user
func GetUniqueID(idToken string) (string, error) {
	j, err := jwt.Decode(idToken)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", j.Claims()["sub"]), nil
}

// GetClaims decodes the id_token response and returns the JWT claims to identify the user
func GetClaims(idToken string) (*jwt.Claims, error) {
	j, err := jwt.Decode(idToken)
	if err != nil {
		return nil, err
	}

	claim := j.Claims()
	return &claim, nil
}

func doRequest(ctx context.Context, client *http.Client, result interface{}, url string, data url.Values) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("content-type", ContentType)
	req.Header.Add("accept", AcceptHeader)
	req.Header.Add("user-agent", UserAgent) // apple requires a user agent

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(result)
}
