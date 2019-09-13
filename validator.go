package applesignin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
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
	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(reqBody); err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.validationURL, b)
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
