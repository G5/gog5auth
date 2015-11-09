// Package cliconfig provides integration with the codegangsta/cli library, so
// that CLI applications that require auth can easily get their command-line
// flags documented but integrated with what gog5auth requires.
//
// It is a separate package so that non-CLI packages won't end up pulling in
// the CLI code when they are importing the rest of gog5auth.
package cliconfig

import (
	"fmt"

	"github.com/G5/gog5auth/client"
	"github.com/codegangsta/cli"
)

// CLI flags that may be registered and validated against by this package. You
// can use them in your own packages when you need to pull their values from
// the cli.Context.
const (
	ClientIDFlag     = "g5-auth-client-id"
	ClientSecretFlag = "g5-auth-client-secret"
	EndpointFlag     = "g5-auth-endpoint"
	UsernameFlag     = "g5-auth-username"
	PasswordFlag     = "g5-auth-password"
)

var serviceToServiceIsRegistered bool

// RegisterStandardFlags accepts an App to register flags that gog5auth
// accepts. This registers the typical flags for application and auth server.
// Should be paired with InitializeFromContext.
func RegisterStandardFlags(app *cli.App) {
	fs := []cli.Flag{
		cli.StringFlag{
			Name:   ClientIDFlag,
			Usage:  "G5 Auth application ID",
			EnvVar: "G5_AUTH_CLIENT_ID",
		},
		cli.StringFlag{
			Name:   ClientSecretFlag,
			Usage:  "G5 Auth application secret",
			EnvVar: "G5_AUTH_CLIENT_SECRET",
		},
		cli.StringFlag{
			Name:   EndpointFlag,
			Value:  client.Endpoint,
			Usage:  "G5 Auth endpoint",
			EnvVar: "G5_AUTH_ENDPOINT",
		},
	}
	app.Flags = append(app.Flags, fs...)
}

// InitializeFromContext sets all package-level variables based on the values
// of cli flags, whether they come from environment variables or from
// command-line flags. It will return an error if any required flag is not
// present. Any by required, I mean any, because they're all required.
//
// It will check for the presence of more flags if
// RegisterServiceToServiceFlags has been called.
func InitializeFromContext(c *cli.Context) error {
	reqd := map[*string]string{
		&client.ClientID:     ClientIDFlag,
		&client.ClientSecret: ClientSecretFlag,
		&client.Endpoint:     EndpointFlag,
	}
	if serviceToServiceIsRegistered {
		reqd[&client.ServiceAccountUsername] = UsernameFlag
		reqd[&client.ServiceAccountPassword] = PasswordFlag
	}
	for toSet, flagName := range reqd {
		s := c.String(flagName)
		if s == "" {
			return fmt.Errorf("missing required flag %s", flagName)
		}
		*toSet = s
	}

	return nil
}

// RegisterServiceToServiceFlags accepts an App to register flags that gog5auth
// accepts. This registers the flags needed for service-to-service auth. Should
// be paired with InitializeFromContext.
func RegisterServiceToServiceFlags(app *cli.App) {
	serviceToServiceIsRegistered = true
	fs := []cli.Flag{
		cli.StringFlag{
			Name:   UsernameFlag,
			Usage:  "G5 Auth Service Account Username",
			EnvVar: "G5_AUTH_USERNAME",
		},
		cli.StringFlag{
			Name:   PasswordFlag,
			Usage:  "G5 Auth Service Account Password",
			EnvVar: "G5_AUTH_PASSWORD",
		},
	}
	app.Flags = append(app.Flags, fs...)
}
