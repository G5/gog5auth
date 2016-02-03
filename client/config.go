package client

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
)

// Variables to communicate with the auth server and request credentials. Not
// all are required. Use InitializeFromEnvironment to automatically set these
// from G5-standard environment variable names.
var (
	Endpoint               = "auth.g5search.com"
	ClientID               string
	ClientSecret           string
	ServiceAccountUsername string
	ServiceAccountPassword string
)

// InitializeFromEnvironment sets package-level configuration via G5-standard
// environment variable names.
func InitializeFromEnvironment() error {
	ClientID = os.Getenv("G5_AUTH_CLIENT_ID")
	ClientSecret = os.Getenv("G5_AUTH_CLIENT_SECRET")

	if e := os.Getenv("G5_AUTH_ENDPOINT"); e != "" {
		Endpoint = e
	}

	if ClientID == "" {
		return errors.New("missing G5Auth ClientID")
	}

	if ClientSecret == "" {
		return errors.New("missing G5Auth ClientSecret")
	}

	if Endpoint == "" {
		return errors.New("missing G5Auth Endpoint")
	}

	return nil
}

// NewStandaloneConfig creates a config using the weird redirect string that is
// peculiar to oauth2, which G5 Auth respects. Useful when you are making
// server-to-server requests using a service account.
func NewStandaloneConfig() *oauth2.Config {
	return NewConfigForRedirectURL("urn:ietf:wg:oauth:2.0:oob")
}

// NewConfigForRedirectURL builds a config for the passed-in redirect URL.
func NewConfigForRedirectURL(url string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		RedirectURL:  url,
		Endpoint:     NewDefaultEndpoint(),
	}
}

// NewDefaultEndpoint creates an endpoint using the package-level endpoint with
// URLs configured for G5Auth.
func NewDefaultEndpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("https://%s/oauth/authorize", Endpoint),
		TokenURL: fmt.Sprintf("https://%s/oauth/token", Endpoint),
	}
}

// ServiceToServiceClient instantiates a http.Client which will pass a token
// with all of its requests. If a token cannot be aquired, the Client will be
// nil and the error will show the issue. There will also be an error if the
// ServiceAccountUsername and ServiceAccountPassword are not set.
//
// This will make a network request to the auth server immediately, and will
// fail if there is a problem with any portion of the auth configuration.
//
// I am currently unsure of how the expiration of this token will affect the
// client. There is information in the oauth2 documentation that suggests it
// might refresh itself, but I have no tested it.
func ServiceToServiceClient() (*oauth2.Config, *http.Client, error) {
	if ServiceAccountUsername == "" || ServiceAccountPassword == "" {
		return nil, nil, errors.New("missing ServiceAccountUsername/ServiceAccountPassword values")
	}

	conf := NewStandaloneConfig()
	cl, err := PasswordAuthenticatedClientFromConfig(
		conf,
		ServiceAccountUsername, ServiceAccountPassword,
		nil,
	)

	return conf, cl, err
}
