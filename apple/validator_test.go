package apple

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	c := New()

	assert.IsType(t, &Client{}, c, "expected New to return a Client type")
	assert.Equal(t, ValidationURL, c.validationURL, "expected the client's url to be %s, but got %s", ValidationURL, c.validationURL)
	assert.NotNil(t, c.client, "the client's http client should not be empty")
}

func TestNewWithURL(t *testing.T) {
	c := NewWithURL("someURL")

	assert.IsType(t, &Client{}, c, "expected New to return a Client type")
	assert.Equal(t, "someURL", c.validationURL, "expected the client's url to be %s, but got %s", "someURL", c.validationURL)
	assert.NotNil(t, c.client, "the client's http client should not be empty")
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

	c := NewWithURL(srv.URL)
	assert.NoError(t, doRequest(context.Background(), c.client, &actual, c.validationURL, url.Values{}))
	assert.Equal(t, "123", actual.IDToken)
}

func TestDoRequestBadServer(t *testing.T) {
	var actual ValidationResponse
	c := NewWithURL("foo.test")
	assert.Error(t, doRequest(context.Background(), c.client, &actual, c.validationURL, url.Values{}))
}

func TestDoRequestNewRequestFail(t *testing.T) {
	var actual ValidationResponse
	c := NewWithURL("http://fo  o.test")
	assert.Error(t, doRequest(context.Background(), c.client, &actual, c.validationURL, nil))
}

func TestVerifyAppToken(t *testing.T) {
	req := AppValidationTokenRequest{
		ClientID:     "123",
		ClientSecret: "foo",
		Code:         "bar",
	}
	var resp ValidationResponse

	srv := setupServerCompareURL(t, "client_id=123&client_secret=foo&code=bar&grant_type=authorization_code")
	c := NewWithURL(srv.URL)
	c.VerifyAppToken(context.Background(), req, resp) // We aren't testing whether this will error
}

func TestVerifyNonAppToken(t *testing.T) {
	req := WebValidationTokenRequest{
		ClientID:     "123",
		ClientSecret: "foo",
		Code:         "bar",
		RedirectURI:  "http://foo.test",
	}
	var resp ValidationResponse

	srv := setupServerCompareURL(t, "client_id=123&client_secret=foo&code=bar&grant_type=authorization_code&redirect_uri=http%3A%2F%2Ffoo.test")
	c := NewWithURL(srv.URL)
	c.VerifyWebToken(context.Background(), req, resp) // We aren't testing whether this will error
}

func TestVerifyRefreshToken(t *testing.T) {
	req := ValidationRefreshRequest{
		ClientID:     "123",
		ClientSecret: "foo",
		RefreshToken: "bar",
	}
	var resp ValidationResponse

	srv := setupServerCompareURL(t, "client_id=123&client_secret=foo&grant_type=refresh_token&refresh_token=bar")
	c := NewWithURL(srv.URL)
	c.VerifyRefreshToken(context.Background(), req, resp) // We aren't testing whether this will error
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
