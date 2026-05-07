package example

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Timothylock/go-signin-with-apple/apple"
)

/*
This example shows you how to handle Apple's server-to-server notifications.
Apple sends a signed JWT to your registered webhook URL when a user deletes
their account or revokes Sign in with Apple access for your app. You must
delete all of that user's data within 30 days of receiving the notification.
See https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
*/

func TestHandleServerNotification(t *testing.T) {
	client := apple.New()

	// In production this would be your HTTP handler registered at the webhook URL
	// you configured in the Apple Developer portal under Sign in with Apple.
	http.HandleFunc("/apple/notifications", func(w http.ResponseWriter, r *http.Request) {
		// Apple sends the signed JWT in the "payload" form field
		jwtPayload := r.FormValue("payload")

		notification, err := client.ParseServerNotification(r.Context(), jwtPayload)
		if err != nil {
			fmt.Println("failed to parse notification: " + err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		switch notification.Events.Type {
		case "consent-revoked":
			// The user has revoked Sign in with Apple for your app.
			// Revoke their session and stop sending them communications.
			fmt.Printf("user %s revoked consent\n", notification.Events.Sub)

		case "account-delete":
			// The user has deleted their Apple ID or asked Apple to delete your app's data.
			// You must delete all data associated with this user within 30 days.
			fmt.Printf("user %s deleted their account — delete all user data\n", notification.Events.Sub)

		default:
			fmt.Printf("received unknown event type: %s\n", notification.Events.Type)
		}

		w.WriteHeader(http.StatusOK)
	})
}
