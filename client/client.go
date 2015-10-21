package client

import (
	"net/http"

	"github.com/G5/oauth2"
	"golang.org/x/net/context"
)

// PasswordAuthenticatedClientFromConfig handles some boilerplate for
// service-to-service username/password authenticated client creation for you.
// Config should likely be created by one of the convenience functions in
// gog5auth/client, username and password should for the service account, and
// ctx is optional.
func PasswordAuthenticatedClientFromConfig(conf *oauth2.Config, username, password string, ctx context.Context) (*http.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	token, err := conf.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, err
	}

	return conf.Client(ctx, token), nil
}
