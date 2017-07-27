package client

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func init() {
	// Apparently Doorkeeper doesn't follow the RFC exactly on how secrets are
	// passed. Don't worry, it's far from alone in this behavior, and joins a
	// bunch of well-known services in being "broken". A lot of libraries will
	// detect this behavior, but not this one, it's being passive-aggressive and
	// forcing you to register auth providers you want to use that don't follow
	// the convention. At least they're letting you register, I had to fork this
	// library to get G5 Auth in there before. Anywho, this will break if you try
	// and use a custom auth server, but I'll cross that bridge when I get to it.
	oauth2.RegisterBrokenAuthHeaderProvider("https://auth.g5search.com/")
	oauth2.RegisterBrokenAuthHeaderProvider("https://dev-auth.g5search.com/")
}

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
