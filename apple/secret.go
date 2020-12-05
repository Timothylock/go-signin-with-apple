package apple

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

/*
GenerateClientSecret generates the client secret used to make requests to the validation server.
The secret expires after max 6 months
*/
func GenerateClientSecret(signingKey, teamID, clientID, keyID string) (string, error) {
	return generateSecret(signingKey, teamID, clientID, keyID, 180)
}


/*
GenerateClientSecretCustomTTL generated client secret with specific TTL.
Will not allow more than 180 days as that is max expiration allowed by apple
*/
func GenerateClientSecretCustomTTL(signingKey, teamID, clientID, keyID string, ttlDays int) (string, error){
	if ttlDays > 180 {
		return "", errors.New("ttl cannot be longer than 180 days")
	}
	return generateSecret(signingKey, teamID, clientID, keyID, ttlDays)
}

/*
signingKey - Private key from Apple obtained by going to the keys section of the developer section
teamID - Your 10-character Team ID
clientID - Your Services ID, e.g. com.aaronparecki.services
keyID - Find the 10-char Key ID value from the portal
*/
func generateSecret(signingKey, teamID, clientID, keyID string, ttlDays int) (string, error) {
	block, _ := pem.Decode([]byte(signingKey))
	if block == nil {
		return "", errors.New("empty block after decoding")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	// Create the Claims
	now := time.Now()
	claims := &jwt.StandardClaims{
		Issuer:    teamID,
		IssuedAt:  now.Unix(),
		ExpiresAt: time.Now().AddDate(0,0,ttlDays).Unix(), // ttlDays days
		Audience:  "https://appleid.apple.com",
		Subject:   clientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["alg"] = "ES256"
	token.Header["kid"] = keyID

	return token.SignedString(privKey)
}