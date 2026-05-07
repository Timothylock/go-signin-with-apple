Go Sign In With Apple
======

![](https://img.shields.io/badge/golang-1.21-blue.svg?style=flat) [![codecov](https://codecov.io/gh/Timothylock/go-signin-with-apple/branch/master/graph/badge.svg)](https://codecov.io/gh/Timothylock/go-signin-with-apple) [![CI](https://github.com/Timothylock/go-signin-with-apple/actions/workflows/ci.yml/badge.svg)](https://github.com/Timothylock/go-signin-with-apple/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/Timothylock/go-signin-with-apple/apple.svg)](https://pkg.go.dev/github.com/Timothylock/go-signin-with-apple/apple)

A Go library for working with Apple's Sign in with Apple REST API. It handles token validation and revocation, ID token claim parsing, user migration across developer teams, and server-to-server event notifications.

## Installation

```
go get github.com/Timothylock/go-signin-with-apple
```

```go
import "github.com/Timothylock/go-signin-with-apple/apple"
```

## Usage

Full working examples can be found in the [example/](example/) directory:

| Example | File |
|---------|------|
| Validate an iOS app token | [app_validation_example_test.go](example/app_validation_example_test.go) |
| Validate a web token | [web_validation_example_test.go](example/web_validation_example_test.go) |
| Validate a refresh token | [refresh_validation_example_test.go](example/refresh_validation_example_test.go) |
| Revoke an access token | [revoke_access_token_example_test.go](example/revoke_access_token_example_test.go) |
| Revoke a refresh token | [revoke_refresh_token_example_test.go](example/revoke_refresh_token_example_test.go) |
| Verify an ID token (with signature check) | [verify_id_token_example_test.go](example/verify_id_token_example_test.go) |
| Get typed ID token claims (no signature check) | [get_typed_claims_example_test.go](example/get_typed_claims_example_test.go) |
| Migrate users across developer teams | [user_migration_example_test.go](example/user_migration_example_test.go) |
| Handle server-to-server notifications | [server_notification_example_test.go](example/server_notification_example_test.go) |

---

### Generating a Client Secret

Apple requires a signed JWT as your client secret on every request. Generate one with `GenerateClientSecret`. You will need your Team ID, Services ID, and a private key downloaded from the Apple Developer portal.

```go
secret, err := apple.GenerateClientSecret(signingKey, teamID, clientID, keyID)
```

- `signingKey` — contents of the `.p8` file downloaded from the portal (the full PEM block)
- `teamID` — your 10-character Team ID
- `clientID` — your Services ID (e.g. `com.example.app`) for web flows, or bundle ID for iOS
- `keyID` — the 10-character Key ID shown in the portal

The secret is a JWT valid for 180 days. Generate a new one before it expires.

---

### Validating a Token

Create a `Client` and call the appropriate `Verify` method with the authorization code your app received from Apple.

```go
client := apple.New()

// iOS app token
err := client.VerifyAppToken(ctx, apple.AppValidationTokenRequest{
    ClientID:     clientID,
    ClientSecret: secret,
    Code:         authorizationCode,
}, &resp)

// Web token
err := client.VerifyWebToken(ctx, apple.WebValidationTokenRequest{
    ClientID:     clientID,
    ClientSecret: secret,
    Code:         authorizationCode,
    RedirectURI:  "https://example.com/callback",
}, &resp)
```

Check `resp.Error` before using the response — Apple returns errors in the body with a 400 status rather than causing a Go error.

---

### Which ID token method should I use?

The right choice depends on **who gave you the token**:

| Token source | Method | Why |
|---|---|---|
| Client device (iOS app, web browser) | `VerifyIDToken` | Token passed through the client — signature must be checked |
| Apple's API response (`VerifyAppToken` / `VerifyWebToken`) | `GetTypedClaims` | Your server fetched it over TLS directly from Apple — no tampering possible |

### Verifying an ID Token from a Client Device

When an iOS app or browser completes Sign in with Apple, the Apple SDK hands the client an `id_token`. The client sends that token to your server. Because it traveled through the client it could have been swapped, so you must verify the RS256 signature before trusting it.

```go
client := apple.New()

claims, err := client.VerifyIDToken(ctx, idToken, clientID)
if err != nil {
    // token is invalid, expired, or not from Apple
}

fmt.Println(claims.Subject)        // stable unique user ID
fmt.Println(claims.Email)          // user's email (if requested)
fmt.Println(claims.EmailVerified)  // bool
fmt.Println(claims.IsPrivateEmail) // bool — true if Apple private relay address
fmt.Println(claims.RealUserStatus) // 0=unsupported, 1=unknown, 2=likelyReal (iOS 14+)
```

`VerifyIDToken` fetches Apple's public JWKS, verifies the RS256 signature, and validates that `iss`, `aud`, and `exp` are all correct. The JWKS is cached for 15 minutes by default and refreshed automatically on key rotation.

Tune the cache TTL via `ClientOptions`:

```go
client := apple.NewWithOptions(apple.ClientOptions{
    JWKSCacheTTL: 30 * time.Minute,
})
```

### Reading ID Token Claims from Apple's API Response

When your server calls `VerifyAppToken` or `VerifyWebToken`, Apple returns an `id_token` directly to you over TLS. Because your server made the request, the token never passed through any client and cannot have been tampered with. Signature verification is redundant — use `GetTypedClaims` to decode the claims directly:

```go
claims, err := apple.GetTypedClaims(resp.IDToken)
```

`GetTypedClaims` handles Apple's older token format where `email_verified` is returned as the string `"true"` instead of a JSON boolean.

---

### Revoking a Token

Call `RevokeAccessToken` or `RevokeRefreshToken` to invalidate a token, for example when a user signs out or deletes their account.

```go
err := client.RevokeAccessToken(ctx, apple.RevokeAccessTokenRequest{
    ClientID:     clientID,
    ClientSecret: secret,
    AccessToken:  accessToken,
}, &resp)
```

A successful revocation returns HTTP 200 with no body. Check `resp.Error` for failures.

---

### Refreshing a Token

Exchange a refresh token for a new access token:

```go
err := client.VerifyRefreshToken(ctx, apple.ValidationRefreshRequest{
    ClientID:     clientID,
    ClientSecret: secret,
    RefreshToken: refreshToken,
}, &resp)
```

---

### User Migration (App Transfers)

When your app transfers to a new developer team, Apple provides a `transfer_sub` identifier for each user. Exchange it for the user's new identifier under your team:

```go
var resp apple.UserMigrationResponse

err := client.GetUserMigrationInfo(ctx, apple.UserMigrationRequest{
    ClientID:     clientID,     // recipient team's Services ID
    ClientSecret: secret,       // recipient team's client secret
    TransferSub:  transferSub,  // provided by the original team
}, &resp)

fmt.Println(resp.Sub)   // new stable user ID under your team
fmt.Println(resp.Email)
```

Apple allows a 60-day window during which both teams' credentials are valid. See [TN3159](https://developer.apple.com/documentation/technotes/tn3159-migrating-sign-in-with-apple-users-for-an-app-transfer) for the full migration flow.

---

### Server-to-Server Notifications

Apple sends a signed JWT to a webhook URL you register in the Developer portal when a user revokes access or deletes their Apple ID. Parse the incoming payload and respond to the event:

```go
client := apple.New()

http.HandleFunc("/apple/notifications", func(w http.ResponseWriter, r *http.Request) {
    notification, err := client.ParseServerNotification(r.Context(), r.FormValue("payload"))
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    switch notification.Events.Type {
    case "consent-revoked":
        // User revoked Sign in with Apple for your app
    case "account-delete":
        // User deleted their Apple ID — you must delete all their data within 30 days
    }
})
```

Register your webhook URL under **Certificates, Identifiers & Profiles → your App ID → Sign in with Apple** in the Apple Developer portal. See [TN3194](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple) for full details.

`ParseServerNotification` verifies the RS256 signature using the same JWKS cache as `VerifyIDToken`.

---

### Custom HTTP Client / Endpoints

`NewWithOptions` lets you override the HTTP client, timeouts, or endpoint URLs (useful for testing):

```go
client := apple.NewWithOptions(apple.ClientOptions{
    Client: &http.Client{Timeout: 10 * time.Second},
})
```

---

## Contributing

Make sure tests pass, then open a PR. Run tests with:

```
go test ./...
```

## License

go-signin-with-apple is licensed under the MIT License.
