package apple

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// ValidationURL is the endpoint for verifying tokens
	ValidationURL string = "https://appleid.apple.com/auth/token"
	// RevokeURL is the endpoint for revoking tokens
	RevokeURL string = "https://appleid.apple.com/auth/revoke"
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
	RevokeAccessToken(ctx context.Context, reqBody RevokeAccessTokenRequest, result interface{}) error
	RevokeRefreshToken(ctx context.Context, reqBody RevokeRefreshTokenRequest, result interface{}) error
}

// Client implements ValidationClient
type Client struct {
	validationURL string
	revokeURL     string
	client        *http.Client
}

// New creates a Client object
func New() *Client {
	client := &Client{
		validationURL: ValidationURL,
		revokeURL:     RevokeURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return client
}

// NewWithURL creates a Client object with a custom URL provided
func NewWithURL(validationURL string, revokeURL string) *Client {
	client := &Client{
		validationURL: validationURL,
		revokeURL:     revokeURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return client
}

// VerifyWebToken sends the WebValidationTokenRequest and gets validation result
func (c *Client) VerifyWebToken(ctx context.Context, reqBody WebValidationTokenRequest, result interface{}) error {
	data := url.Values{
		"client_id":     {reqBody.ClientID},
		"client_secret": {reqBody.ClientSecret},
		"code":          {reqBody.Code},
		"redirect_uri":  {reqBody.RedirectURI},
		"grant_type":    {"authorization_code"},
	}

	return doRequest(ctx, c.client, &result, c.validationURL, data)
}

// VerifyAppToken sends the AppValidationTokenRequest and gets validation result
func (c *Client) VerifyAppToken(ctx context.Context, reqBody AppValidationTokenRequest, result interface{}) error {
	data := url.Values{
		"client_id":     {reqBody.ClientID},
		"client_secret": {reqBody.ClientSecret},
		"code":          {reqBody.Code},
		"grant_type":    {"authorization_code"},
	}

	return doRequest(ctx, c.client, &result, c.validationURL, data)
}

// VerifyRefreshToken sends the WebValidationTokenRequest and gets validation result
func (c *Client) VerifyRefreshToken(ctx context.Context, reqBody ValidationRefreshRequest, result interface{}) error {
	data := url.Values{
		"client_id":     {reqBody.ClientID},
		"client_secret": {reqBody.ClientSecret},
		"refresh_token": {reqBody.RefreshToken},
		"grant_type":    {"refresh_token"},
	}

	return doRequest(ctx, c.client, &result, c.validationURL, data)
}

// RevokeRefreshToken revokes the Refresh Token and gets the revoke result
func (c *Client) RevokeRefreshToken(ctx context.Context, reqBody RevokeRefreshTokenRequest, result interface{}) error {
	data := url.Values{
		"client_id":       {reqBody.ClientID},
		"client_secret":   {reqBody.ClientSecret},
		"token":           {reqBody.RefreshToken},
		"token_type_hint": {"refresh_token"},
	}

	return doRequest(ctx, c.client, &result, c.revokeURL, data)
}

// RevokeAccessToken revokes the Access Token and gets the revoke result
func (c *Client) RevokeAccessToken(ctx context.Context, reqBody RevokeAccessTokenRequest, result interface{}) error {
	data := url.Values{
		"client_id":       {reqBody.ClientID},
		"client_secret":   {reqBody.ClientSecret},
		"token":           {reqBody.AccessToken},
		"token_type_hint": {"access_token"},
	}

	return doRequest(ctx, c.client, &result, c.revokeURL, data)
}

// GetUniqueID decodes the id_token response and returns the unique subject ID to identify the user
func GetUniqueID(idToken string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	return fmt.Sprintf("%v", claims["sub"]), nil
}

// GetClaims decodes the id_token response and returns the JWT claims to identify the user
func GetClaims(idToken string) (*jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return &claims, nil
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
