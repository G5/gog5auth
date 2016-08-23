package grpcg5auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"

	"golang.org/x/net/context"
)

const serviceToServiceIdentity = "service-to-service"

var (
	authTimeout     = 5 * time.Second
	employeeDomains = []string{
		"getg5.com",
		"g5platform.com",
		"g5searchmarketing.com",
	}
	// exists entirely for tests, which run over http
	authProtocol = "https"
)

// G5AuthenticatorConfig holds (mostly) optional configuration for how your app
// will communicate with G5 Auth, or how it will authenticate clients.
type G5AuthenticatorConfig struct {
	// How long to wait for auth's response
	TimeoutDuration time.Duration
	// A token you will accept in lieu of a real bearer token when
	// service-to-service calls really have to be quick. This is probably a bad
	// idea. Roll your own crypto? SURE!
	MagicalTokenOfSupremePower string
	// The hostname of the auth server, sans protocol.
	AuthHostname string
}

// An Authenticator can accepts a context which should contain credentials in
// its metadata, and will return of a copy of that context with identity
// metadata for the authorized person.
type Authenticator interface {
	IdentifyContext(context.Context) (context.Context, error)
}

// G5Authenticator is an implementation of Authenticator that finds email
// addresses from oauth tokens via G5 Auth.
type G5Authenticator struct {
	config G5AuthenticatorConfig
	client *http.Client
}

// NewG5Authenticator creates a G5Authenticator configured with an http.Client.
func NewG5Authenticator(c G5AuthenticatorConfig) *G5Authenticator {
	return &G5Authenticator{
		config: c,
		client: &http.Client{
			Timeout: c.TimeoutDuration,
		},
	}
}

type identityResponse struct {
	Email string
}

// IdentifyContext takes a context and will verify the token in its metadata
// with G5 Auth, populating the person's email address in the returned
// context's metadata. It will throw an error if there are any failures
// authenticating, problems with the metadata, or errors connecting to G5 Auth.
func (a *G5Authenticator) IdentifyContext(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return nil, errors.New("no metadata in request")
	}

	authorizations := md["authorization"]
	if i := len(authorizations); i != 1 {
		return nil, fmt.Errorf("unexpected number of authorization metadatum: %d", i)
	}

	parts := strings.Split(authorizations[0], " ")
	if len(parts) != 2 {
		return nil, errors.New("bad authorization format")
	}

	switch parts[0] {
	case "magic":
		if a.config.MagicalTokenOfSupremePower == "" {
			return nil, errors.New("magic auth is not configured")
		}
		if parts[1] == a.config.MagicalTokenOfSupremePower {
			return context.WithValue(ctx, "identity", serviceToServiceIdentity), nil
		}
		return nil, errors.New("bad magic token of supreme power")
	case "bearer":
		return a.authenticateBearerToken(parts[1], ctx)
	default:
		return nil, errors.New("unknown token type")
	}
}

func (a *G5Authenticator) authenticateBearerToken(token string, ctx context.Context) (context.Context, error) {
	meURL := fmt.Sprintf("%s://%s/v1/me", authProtocol, a.config.AuthHostname)
	req, err := http.NewRequest("GET", meURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building identity request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	me := &identityResponse{}
	if err := json.NewDecoder(resp.Body).Decode(me); err != nil {
		return nil, fmt.Errorf("decoding identity response: %v", err)
	}
	defer resp.Body.Close()

	if me.Email == "" {
		return nil, errors.New("no email found in identity")
	}

	if err := validateDomain(me.Email); err != nil {
		return nil, err
	}

	return context.WithValue(ctx, "identity", me.Email), nil
}

func validateDomain(s string) error {
	parts := strings.Split(s, "@")
	if len(parts) != 2 {
		return fmt.Errorf("unparseable identity email: %s", s)
	}
	domain := parts[1]

	for _, s := range employeeDomains {
		if s == domain {
			return nil
		}
	}

	return fmt.Errorf("non-employee identity found: %s", s)
}
