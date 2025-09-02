package apple

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	c := New()

	assert.IsType(t, &Client{}, c, "expected New to return a Client type")
	assert.Equal(t, ValidationURL, c.validationURL, "expected the client's validation url to be %s, but got %s", ValidationURL, c.validationURL)
	assert.Equal(t, RevokeURL, c.revokeURL, "expected the client's revoke url to be %s, but got %s", RevokeURL, c.revokeURL)
	assert.NotNil(t, c.client, "the client's http client should not be empty")
}

func TestNewWithURL(t *testing.T) {
	c := NewWithOptions(ClientOptions{
		ValidationURL: "validationURL",
		RevokeURL:     "revokeURL",
	})

	assert.IsType(t, &Client{}, c, "expected New to return a Client type")
	assert.Equal(t, "validationURL", c.validationURL, "expected the client's validation url to be %s, but got %s", "validationURL", c.validationURL)
	assert.Equal(t, "revokeURL", c.revokeURL, "expected the client's revoke url to be %s, but got %s", "revokeURL", c.revokeURL)
	assert.NotNil(t, c.client, "the client's http client should not be empty")
}

func TestNewWithOptions(t *testing.T) {
	tests := []struct {
		name                  string
		opts                  ClientOptions
		expectedValidationURL string
		expectedRevokeURL     string
		expectedClientTimeout time.Duration
	}{
		{
			name:                  "no options should use defaults",
			opts:                  ClientOptions{},
			expectedValidationURL: ValidationURL,
			expectedRevokeURL:     RevokeURL,
			expectedClientTimeout: 5 * time.Second,
		},
		{
			name: "custom validation url",
			opts: ClientOptions{
				ValidationURL: "customValidationURL",
			},
			expectedValidationURL: "customValidationURL",
			expectedRevokeURL:     RevokeURL,
			expectedClientTimeout: 5 * time.Second,
		},
		{
			name: "custom revoke url",
			opts: ClientOptions{
				RevokeURL: "customRevokeURL",
			},
			expectedValidationURL: ValidationURL,
			expectedRevokeURL:     "customRevokeURL",
			expectedClientTimeout: 5 * time.Second,
		},
		{
			name: "custom client timeout",
			opts: ClientOptions{
				Client: &http.Client{
					Timeout: 10 * time.Second,
				},
			},
			expectedValidationURL: ValidationURL,
			expectedRevokeURL:     RevokeURL,
			expectedClientTimeout: 10 * time.Second,
		},
		{
			name: "all custom options",
			opts: ClientOptions{
				ValidationURL: "customValidationURL",
				RevokeURL:     "customRevokeURL",
				Client: &http.Client{
					Timeout: 10 * time.Second,
				},
			},
			expectedValidationURL: "customValidationURL",
			expectedRevokeURL:     "customRevokeURL",
			expectedClientTimeout: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewWithOptions(tt.opts)

			assert.IsType(t, &Client{}, c, "expected New to return a Client type")
			assert.Equal(t, tt.expectedValidationURL, c.validationURL, "expected the client's validation url to be %s, but got %s", tt.expectedValidationURL, c.validationURL)
			assert.Equal(t, tt.expectedRevokeURL, c.revokeURL, "expected the client's revoke url to be %s, but got %s", tt.expectedRevokeURL, c.revokeURL)
			assert.NotNil(t, c.client, "the client's http client should not be empty")

			httpClient, ok := c.client.(*http.Client)
			require.True(t, ok, "the client's http client should be of type *http.Client")
			assert.Equal(t, tt.expectedClientTimeout, httpClient.Timeout, "expected the client's timeout to be %s, but got %s", tt.expectedClientTimeout, httpClient.Timeout)
		})
	}
}

func TestGetUniqueID(t *testing.T) {
	tests := []struct {
		name    string
		idToken string
		want    string
		wantErr bool
	}{
		{
			name:    "successful decode",
			idToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmV4YW1wbGUuYXBwIiwiZXhwIjoxNTY4Mzk1Njc4LCJpYXQiOjE1NjgzOTUwNzgsInN1YiI6IjA4MjY0OS45MzM5MWQ4ZTExOTJmNTZiOGMxY2gzOWdzMmE0N2UyLjk3MzIiLCJhdF9oYXNoIjoickU3b3Brb1BSeVBseV9Pc2Rhc2RFQ1ZnIiwiYXV0aF90aW1lIjoxNTY4Mzk1MDc2fQ.PR3mMoVMdJo8EGPy6_aJ3sJGwAgcnnFjt9UCRXqWerI",
			want:    "082649.93391d8e1192f56b8c1ch39gs2a47e2.9732",
			wantErr: false,
		},
		{
			name:    "bad token",
			idToken: "badtoken",
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUniqueID(tt.idToken)
			if !tt.wantErr {
				assert.NoError(t, err, "expected no error but received %s", err)
			}

			if tt.want != "" {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestGetClaims(t *testing.T) {
	tests := []struct {
		name      string
		idToken   string
		wantEmail string
		wantErr   bool
	}{
		{
			name:      "successful decode",
			idToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmV4YW1wbGUuYXBwIiwiZXhwIjoxNTY4Mzk1Njc4LCJpYXQiOjE1NjgzOTUwNzgsInN1YiI6IjA4MjY0OS45MzM5MWQ4ZTExOTJmNTZiOGMxY2gzOWdzMmE0N2UyLjk3MzIiLCJhdF9oYXNoIjoickU3b3Brb1BSeVBseV9Pc2Rhc2RFQ1ZnIiwiZW1haWwiOiJmb29AYmFyLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNTY4Mzk1MDc2fQ.yPyUS_5k8RMvfowGylHqiCJqYwe-AOGtpBnjvqP4Na8",
			wantEmail: "foo@bar.com",
			wantErr:   false,
		},
		{
			name:      "bad token",
			idToken:   "badtoken",
			wantEmail: "",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetClaims(tt.idToken)
			if !tt.wantErr {
				assert.NoError(t, err, "expected no error but received %s", err)
			}

			if tt.wantEmail != "" {
				assert.Equal(t, tt.wantEmail, (*got)["email"])
			}
		})
	}
}

func TestDoRequestSuccess(t *testing.T) {
	s, err := json.Marshal(ValidationResponse{
		IDToken: "123",
	})
	assert.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, ContentType, r.Header.Get("content-type"))
		assert.Equal(t, AcceptHeader, r.Header.Get("accept"))
		assert.Equal(t, UserAgent, r.Header.Get("user-agent"))

		w.WriteHeader(200)
		w.Write([]byte(s))
	}))
	defer srv.Close()

	var actual ValidationResponse

	c := NewWithOptions(ClientOptions{
		ValidationURL: srv.URL,
		RevokeURL:     "revokeUrl",
	})
	assert.NoError(t, doRequest(context.Background(), c.client, &actual, c.validationURL, url.Values{}, false))
	assert.Equal(t, "123", actual.IDToken)
}

func TestDoRequestBadServer(t *testing.T) {
	var actual ValidationResponse
	c := NewWithOptions(ClientOptions{
		ValidationURL: "foo.test",
		RevokeURL:     "revokeUrl",
	})
	assert.Error(t, doRequest(context.Background(), c.client, &actual, c.validationURL, url.Values{}, false))
}

func TestDoRequestNewRequestFail(t *testing.T) {
	var actual ValidationResponse
	c := NewWithOptions(ClientOptions{
		ValidationURL: "http://fo  o.test",
		RevokeURL:     "revokeUrl",
	})
	assert.Error(t, doRequest(context.Background(), c.client, &actual, c.validationURL, nil, false))
}

func TestVerifyAppToken(t *testing.T) {
	tests := []struct {
		name           string
		req            AppValidationTokenRequest
		serverResponse string
		serverStatus   int
		expectedError  bool
		expectedResp   ValidationResponse
	}{
		{
			name: "successful validation",
			req: AppValidationTokenRequest{
				ClientID:     "com.example.app",
				ClientSecret: "secret123",
				Code:         "auth_code_123",
			},
			serverResponse: `{
				"access_token": "access_token_123",
				"token_type": "bearer",
				"expires_in": 3600,
				"refresh_token": "refresh_token_123",
				"id_token": "id_token_123"
			}`,
			serverStatus:  200,
			expectedError: false,
			expectedResp: ValidationResponse{
				AccessToken:  "access_token_123",
				TokenType:    "bearer",
				ExpiresIn:    3600,
				RefreshToken: "refresh_token_123",
				IDToken:      "id_token_123",
			},
		},
		{
			name: "server error with JSON error response - validation functions always decode JSON",
			req: AppValidationTokenRequest{
				ClientID:     "invalid_client",
				ClientSecret: "invalid_secret",
				Code:         "auth_code_123",
			},
			serverResponse: `{
				"error": "invalid_client",
				"error_description": "Invalid client credentials"
			}`,
			serverStatus:  400,
			expectedError: false, // No error because JSON was successfully decoded
			expectedResp: ValidationResponse{
				Error:            "invalid_client",
				ErrorDescription: "Invalid client credentials",
			},
		},
		{
			name: "malformed JSON response causes decode error",
			req: AppValidationTokenRequest{
				ClientID:     "com.example.app",
				ClientSecret: "secret123",
				Code:         "auth_code_123",
			},
			serverResponse: "invalid json response",
			serverStatus:   200,
			expectedError:  true, // JSON decode error
		},
		{
			name: "empty response body causes decode error",
			req: AppValidationTokenRequest{
				ClientID:     "com.example.app",
				ClientSecret: "secret123",
				Code:         "auth_code_123",
			},
			serverResponse: "",
			serverStatus:   500,
			expectedError:  true, // EOF error from empty JSON
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, ContentType, r.Header.Get("content-type"))
				assert.Equal(t, AcceptHeader, r.Header.Get("accept"))
				assert.Equal(t, UserAgent, r.Header.Get("user-agent"))
				body, err := ioutil.ReadAll(r.Body)
				assert.NoError(t, err)
				expectedBody := "client_id=123&client_secret=foo&code=bar&grant_type=authorization_code"
				expectedBody = fmt.Sprintf("client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code",
					tt.req.ClientID, tt.req.ClientSecret, tt.req.Code)
				assert.Equal(t, expectedBody, string(body))

				w.WriteHeader(tt.serverStatus)
				if tt.serverResponse != "" {
					w.Write([]byte(tt.serverResponse))
				}
			}))
			defer srv.Close()

			c := NewWithOptions(ClientOptions{
				ValidationURL: srv.URL,
				RevokeURL:     "revokeUrl",
			})
			var resp ValidationResponse
			err := c.VerifyAppToken(context.Background(), tt.req, &resp)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp.AccessToken, resp.AccessToken)
				assert.Equal(t, tt.expectedResp.TokenType, resp.TokenType)
				assert.Equal(t, tt.expectedResp.ExpiresIn, resp.ExpiresIn)
				assert.Equal(t, tt.expectedResp.RefreshToken, resp.RefreshToken)
				assert.Equal(t, tt.expectedResp.IDToken, resp.IDToken)
				assert.Equal(t, tt.expectedResp.Error, resp.Error)
				assert.Equal(t, tt.expectedResp.ErrorDescription, resp.ErrorDescription)
			}
		})
	}
}

func TestVerifyNonAppToken(t *testing.T) {
	tests := []struct {
		name           string
		req            WebValidationTokenRequest
		serverResponse string
		serverStatus   int
		expectedError  bool
		expectedResp   ValidationResponse
	}{
		{
			name: "successful web token validation",
			req: WebValidationTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "web_secret123",
				Code:         "web_auth_code_456",
				RedirectURI:  "https://example.com/callback",
			},
			serverResponse: `{
				"access_token": "web_access_token_456",
				"token_type": "bearer",
				"expires_in": 7200,
				"refresh_token": "web_refresh_token_456",
				"id_token": "web_id_token_456"
			}`,
			serverStatus:  200,
			expectedError: false,
			expectedResp: ValidationResponse{
				AccessToken:  "web_access_token_456",
				TokenType:    "bearer",
				ExpiresIn:    7200,
				RefreshToken: "web_refresh_token_456",
				IDToken:      "web_id_token_456",
			},
		},
		{
			name: "invalid authorization code with JSON error - validation always decodes",
			req: WebValidationTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "web_secret123",
				Code:         "expired_code",
				RedirectURI:  "https://example.com/callback",
			},
			serverResponse: `{
				"error": "invalid_grant",
				"error_description": "The authorization code is invalid or has expired"
			}`,
			serverStatus:  400,
			expectedError: false, // No error because JSON was successfully decoded
			expectedResp: ValidationResponse{
				Error:            "invalid_grant",
				ErrorDescription: "The authorization code is invalid or has expired",
			},
		},
		{
			name: "redirect URI mismatch with error response",
			req: WebValidationTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "web_secret123",
				Code:         "valid_code",
				RedirectURI:  "https://wrong-domain.com/callback",
			},
			serverResponse: `{
				"error": "invalid_request",
				"error_description": "Redirect URI mismatch"
			}`,
			serverStatus:  400,
			expectedError: false,
			expectedResp: ValidationResponse{
				Error:            "invalid_request",
				ErrorDescription: "Redirect URI mismatch",
			},
		},
		{
			name: "network timeout simulation with malformed response",
			req: WebValidationTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "web_secret123",
				Code:         "auth_code_789",
				RedirectURI:  "https://example.com/callback",
			},
			serverResponse: "timeout error html page",
			serverStatus:   504,
			expectedError:  true, // JSON decode error from HTML response
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, ContentType, r.Header.Get("content-type"))
				assert.Equal(t, AcceptHeader, r.Header.Get("accept"))
				assert.Equal(t, UserAgent, r.Header.Get("user-agent"))

				body, err := ioutil.ReadAll(r.Body)
				assert.NoError(t, err)
				expectedBody := fmt.Sprintf("client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s",
					tt.req.ClientID, tt.req.ClientSecret, tt.req.Code, url.QueryEscape(tt.req.RedirectURI))
				assert.Equal(t, expectedBody, string(body))

				w.WriteHeader(tt.serverStatus)
				if tt.serverResponse != "" {
					w.Write([]byte(tt.serverResponse))
				}
			}))
			defer srv.Close()

			c := NewWithOptions(ClientOptions{
				ValidationURL: srv.URL,
				RevokeURL:     "revokeUrl",
			})
			var resp ValidationResponse
			err := c.VerifyWebToken(context.Background(), tt.req, &resp)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp.AccessToken, resp.AccessToken)
				assert.Equal(t, tt.expectedResp.TokenType, resp.TokenType)
				assert.Equal(t, tt.expectedResp.ExpiresIn, resp.ExpiresIn)
				assert.Equal(t, tt.expectedResp.RefreshToken, resp.RefreshToken)
				assert.Equal(t, tt.expectedResp.IDToken, resp.IDToken)
				assert.Equal(t, tt.expectedResp.Error, resp.Error)
				assert.Equal(t, tt.expectedResp.ErrorDescription, resp.ErrorDescription)
			}
		})
	}
}

func TestVerifyRefreshToken(t *testing.T) {
	tests := []struct {
		name           string
		req            ValidationRefreshRequest
		serverResponse string
		serverStatus   int
		expectedError  bool
		expectedResp   ValidationResponse
	}{
		{
			name: "successful refresh token validation",
			req: ValidationRefreshRequest{
				ClientID:     "com.example.service",
				ClientSecret: "refresh_secret123",
				RefreshToken: "valid_refresh_token_789",
			},
			serverResponse: `{
				"access_token": "new_access_token_789",
				"token_type": "bearer",
				"expires_in": 3600
			}`,
			serverStatus:  200,
			expectedError: false,
			expectedResp: ValidationResponse{
				AccessToken: "new_access_token_789",
				TokenType:   "bearer",
				ExpiresIn:   3600,
			},
		},
		{
			name: "expired refresh token with error response",
			req: ValidationRefreshRequest{
				ClientID:     "com.example.service",
				ClientSecret: "refresh_secret123",
				RefreshToken: "expired_refresh_token",
			},
			serverResponse: `{
				"error": "invalid_grant",
				"error_description": "The refresh token is invalid, expired, or revoked"
			}`,
			serverStatus:  400,
			expectedError: false, // Validation functions always decode JSON
			expectedResp: ValidationResponse{
				Error:            "invalid_grant",
				ErrorDescription: "The refresh token is invalid, expired, or revoked",
			},
		},
		{
			name: "unauthorized client error",
			req: ValidationRefreshRequest{
				ClientID:     "invalid_client_id",
				ClientSecret: "wrong_secret",
				RefreshToken: "valid_refresh_token_789",
			},
			serverResponse: `{
				"error": "invalid_client",
				"error_description": "Client authentication failed"
			}`,
			serverStatus:  401,
			expectedError: false,
			expectedResp: ValidationResponse{
				Error:            "invalid_client",
				ErrorDescription: "Client authentication failed",
			},
		},
		{
			name: "server error with malformed response",
			req: ValidationRefreshRequest{
				ClientID:     "com.example.service",
				ClientSecret: "refresh_secret123",
				RefreshToken: "valid_refresh_token_789",
			},
			serverResponse: "<html>Internal Server Error</html>",
			serverStatus:   500,
			expectedError:  true, // JSON decode error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, ContentType, r.Header.Get("content-type"))
				assert.Equal(t, AcceptHeader, r.Header.Get("accept"))
				assert.Equal(t, UserAgent, r.Header.Get("user-agent"))
				body, err := ioutil.ReadAll(r.Body)
				assert.NoError(t, err)
				expectedBody := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s",
					tt.req.ClientID, tt.req.ClientSecret, tt.req.RefreshToken)
				assert.Equal(t, expectedBody, string(body))

				w.WriteHeader(tt.serverStatus)
				if tt.serverResponse != "" {
					w.Write([]byte(tt.serverResponse))
				}
			}))
			defer srv.Close()

			c := NewWithOptions(ClientOptions{
				ValidationURL: srv.URL,
				RevokeURL:     "revokeUrl",
			})
			var resp ValidationResponse
			err := c.VerifyRefreshToken(context.Background(), tt.req, &resp)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp.AccessToken, resp.AccessToken)
				assert.Equal(t, tt.expectedResp.TokenType, resp.TokenType)
				assert.Equal(t, tt.expectedResp.ExpiresIn, resp.ExpiresIn)
				assert.Equal(t, tt.expectedResp.RefreshToken, resp.RefreshToken)
				assert.Equal(t, tt.expectedResp.IDToken, resp.IDToken)
				assert.Equal(t, tt.expectedResp.Error, resp.Error)
				assert.Equal(t, tt.expectedResp.ErrorDescription, resp.ErrorDescription)
			}
		})
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	tests := []struct {
		name          string
		req           RevokeRefreshTokenRequest
		serverStatus  int
		expectedError bool
		errorContains string
	}{
		{
			name: "successful revocation",
			req: RevokeRefreshTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "revoke_secret123",
				RefreshToken: "token_to_revoke_123",
			},
			serverStatus:  200,
			expectedError: false,
		},
		{
			name: "successful revocation with 204 No Content",
			req: RevokeRefreshTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "revoke_secret123",
				RefreshToken: "token_to_revoke_456",
			},
			serverStatus:  204,
			expectedError: false,
		},
		{
			name: "token not found - revoke functions return error for non-2xx status",
			req: RevokeRefreshTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "revoke_secret123",
				RefreshToken: "non_existent_token",
			},
			serverStatus:  400,
			expectedError: true,
			errorContains: "apple returned a bad status and response was not decoded: 400 Bad Request",
		},
		{
			name: "unauthorized client - revoke functions return error for non-2xx status",
			req: RevokeRefreshTokenRequest{
				ClientID:     "invalid_client",
				ClientSecret: "wrong_secret",
				RefreshToken: "token_to_revoke_123",
			},
			serverStatus:  401,
			expectedError: true,
			errorContains: "apple returned a bad status and response was not decoded: 401 Unauthorized",
		},
		{
			name: "server error - revoke functions return error for non-2xx status",
			req: RevokeRefreshTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "revoke_secret123",
				RefreshToken: "token_to_revoke_789",
			},
			serverStatus:  500,
			expectedError: true,
			errorContains: "apple returned a bad status and response was not decoded: 500 Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, ContentType, r.Header.Get("content-type"))
				assert.Equal(t, AcceptHeader, r.Header.Get("accept"))
				assert.Equal(t, UserAgent, r.Header.Get("user-agent"))
				body, err := ioutil.ReadAll(r.Body)
				assert.NoError(t, err)
				expectedBody := fmt.Sprintf("client_id=%s&client_secret=%s&token=%s&token_type_hint=refresh_token",
					tt.req.ClientID, tt.req.ClientSecret, tt.req.RefreshToken)
				assert.Equal(t, expectedBody, string(body))

				w.WriteHeader(tt.serverStatus)
			}))
			defer srv.Close()

			c := NewWithOptions(ClientOptions{
				ValidationURL: "validationUrl",
				RevokeURL:     srv.URL,
			})
			var resp ValidationResponse
			err := c.RevokeRefreshToken(context.Background(), tt.req, &resp)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRevokeAccessToken(t *testing.T) {
	tests := []struct {
		name          string
		req           RevokeAccessTokenRequest
		serverStatus  int
		expectedError bool
		errorContains string
	}{
		{
			name: "successful access token revocation",
			req: RevokeAccessTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "revoke_secret123",
				AccessToken:  "access_token_to_revoke_123",
			},
			serverStatus:  200,
			expectedError: false,
		},
		{
			name: "token already revoked - still returns error for non-2xx",
			req: RevokeAccessTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "revoke_secret123",
				AccessToken:  "already_revoked_token",
			},
			serverStatus:  400,
			expectedError: true,
			errorContains: "apple returned a bad status and response was not decoded: 400 Bad Request",
		},
		{
			name: "invalid token format",
			req: RevokeAccessTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "revoke_secret123",
				AccessToken:  "malformed_token",
			},
			serverStatus:  400,
			expectedError: true,
			errorContains: "apple returned a bad status and response was not decoded: 400 Bad Request",
		},
		{
			name: "rate limit exceeded",
			req: RevokeAccessTokenRequest{
				ClientID:     "com.example.service",
				ClientSecret: "revoke_secret123",
				AccessToken:  "access_token_to_revoke_456",
			},
			serverStatus:  429,
			expectedError: true,
			errorContains: "apple returned a bad status and response was not decoded: 429 Too Many Requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, ContentType, r.Header.Get("content-type"))
				assert.Equal(t, AcceptHeader, r.Header.Get("accept"))
				assert.Equal(t, UserAgent, r.Header.Get("user-agent"))
				body, err := ioutil.ReadAll(r.Body)
				assert.NoError(t, err)
				expectedBody := fmt.Sprintf("client_id=%s&client_secret=%s&token=%s&token_type_hint=access_token",
					tt.req.ClientID, tt.req.ClientSecret, tt.req.AccessToken)
				assert.Equal(t, expectedBody, string(body))

				w.WriteHeader(tt.serverStatus)
			}))
			defer srv.Close()

			c := NewWithOptions(ClientOptions{
				ValidationURL: "validationUrl",
				RevokeURL:     srv.URL,
			})
			var resp ValidationResponse
			err := c.RevokeAccessToken(context.Background(), tt.req, &resp)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// setupServerCompareURL sets up an httptest server to compare the given URLs. You must close the server
// yourself when done
func setupServerCompareURL(t *testing.T, expectedBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := ioutil.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, expectedBody, string(s))
	}))
}
