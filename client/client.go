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

	token, err := TokenForConfigAndCredentials(conf, username, password, ctx)
	if err != nil {
		return nil, err
	}

	return conf.Client(ctx, token), nil
}

// TokenForConfigAndCredentials will return a token using the passed-in config
// and credentials, and an optional context. This is likely to be used if you
// need to obtain a token, but will be arranging your own transport. Otherwise,
// you probably want the http.Client that PasswordAuthenticatedClientFromConfig
// can give you.
func TokenForConfigAndCredentials(conf *oauth2.Config, username, password string, ctx context.Context) (*oauth2.Token, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	token, err := conf.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, err
	}

	return token, nil
}
