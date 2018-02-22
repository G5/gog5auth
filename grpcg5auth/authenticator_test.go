package grpcg5auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/stretchr/testify/assert"

	"golang.org/x/net/context"
)

func init() {
	authProtocol = "http"
}

type G5AuthenticatorContext struct {
	Context       context.Context
	Authenticator *G5Authenticator
	Server        *httptest.Server
	MeStatus      int
	MeJSON        string
	AuthCalled    bool
	PassedHeader  string
}

func NewG5AuthenticatorContext() *G5AuthenticatorContext {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	authCtx := metadata.NewOutgoingContext(
		context.Background(),
		map[string][]string{"authorization": []string{"bearer 12345"}},
	)

	config := G5AuthenticatorConfig{
		TimeoutDuration:            100 * time.Millisecond,
		MagicalTokenOfSupremePower: "bacon",
		AuthHostname:               strings.TrimLeft(srv.URL, "http://"),
	}
	ctx := &G5AuthenticatorContext{
		Context:       authCtx,
		Authenticator: NewG5Authenticator(config),
		Server:        srv,
		MeStatus:      http.StatusOK,
		MeJSON:        `{"email":"test@getg5.com"}`,
	}

	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		ctx.AuthCalled = true
		ctx.PassedHeader = r.Header.Get("Authorization")
		if ctx.MeStatus != http.StatusOK {
			w.WriteHeader(ctx.MeStatus)
			return
		}
		fmt.Fprintf(w, ctx.MeJSON)
	})

	return ctx
}

func TestG5Authenticator_IdentifyContext(t *testing.T) {
	ctx := NewG5AuthenticatorContext()
	defer ctx.Server.Close()

	idCtx, err := ctx.Authenticator.IdentifyContext(ctx.Context)
	assert.NoError(t, err)
	assert.Equal(t, "test@getg5.com", idCtx.Value("identity"))
	assert.Equal(t, "Bearer 12345", ctx.PassedHeader)
}

func TestG5Authenticator_IdentifyContext_RespectsMagicalToken(t *testing.T) {
	ctx := NewG5AuthenticatorContext()
	defer ctx.Server.Close()
	ctx.Context = metadata.NewOutgoingContext(
		context.Background(),
		map[string][]string{"authorization": []string{"magic bacon"}},
	)

	idCtx, err := ctx.Authenticator.IdentifyContext(ctx.Context)
	assert.NoError(t, err)
	assert.Equal(t, serviceToServiceIdentity, idCtx.Value("identity"))
	assert.False(t, ctx.AuthCalled)
}

func TestG5Authenticator_IdentifyContext_Error(t *testing.T) {
	suite := []struct {
		Setup       func(*G5AuthenticatorContext)
		Msg, Regexp string
	}{
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.Context = context.Background()
			},
			Msg: "no metadata in request",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.Context = metadata.NewOutgoingContext(
					context.Background(),
					map[string][]string{"authorization": []string{}},
				)
			},
			Msg: "unexpected number of authorization metadatum: 0",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.Context = metadata.NewOutgoingContext(
					context.Background(),
					map[string][]string{"authorization": []string{"unknown whatever"}},
				)
			},
			Msg: "unknown token type",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.Context = metadata.NewOutgoingContext(
					context.Background(),
					map[string][]string{"authorization": []string{"whatevenaretokens"}},
				)
			},
			Msg: "bad authorization format",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.Context = metadata.NewOutgoingContext(
					context.Background(),
					map[string][]string{"authorization": []string{"magic bad"}},
				)
			},
			Msg: "bad magic token of supreme power",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.Context = metadata.NewOutgoingContext(
					context.Background(),
					map[string][]string{"authorization": []string{"magic "}},
				)
				ctx.Authenticator.config.MagicalTokenOfSupremePower = ""
			},
			Msg: "magic auth is not configured",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.Server.Close()
			},
			Regexp: `making request:.+connection refused`,
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.MeStatus = http.StatusUnauthorized
			},
			Msg: "unexpected status: 401 Unauthorized",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.MeJSON = "bad"
			},
			Msg: "decoding identity response: invalid character 'b' looking for beginning of value",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.MeJSON = `{}`
			},
			Msg: "no email found in identity",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.MeJSON = `{"email":"whatever"}`
			},
			Msg: "unparseable identity email: whatever",
		},
		{
			Setup: func(ctx *G5AuthenticatorContext) {
				ctx.MeJSON = `{"email":"test@somecustomer.com"}`
			},
			Msg: "non-employee identity found: test@somecustomer.com",
		},
	}

	for _, test := range suite {
		t.Run(test.Msg, func(t *testing.T) {
			ctx := NewG5AuthenticatorContext()
			test.Setup(ctx)

			idCtx, err := ctx.Authenticator.IdentifyContext(ctx.Context)
			assert.Nil(t, idCtx)
			if test.Msg != "" {
				assert.EqualError(t, err, test.Msg)
			} else {
				assert.Regexp(t, test.Regexp, err.Error())
			}

			ctx.Server.Close()
		})
	}
}
