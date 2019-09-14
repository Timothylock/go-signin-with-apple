package apple

import (
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
