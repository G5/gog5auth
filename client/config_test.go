package client

import "testing"

func TestNewDefaultEndpoint_WithoutProtocol(t *testing.T) {
	Endpoint = "example.com"
	e := NewDefaultEndpoint()
	if e.AuthURL != "https://example.com/oauth/authorize" {
		t.Fatal("incorrect AuthURL")
	}
	if e.TokenURL != "https://example.com/oauth/token" {
		t.Fatal("incorrect TokenURL")
	}
}

func TestNewDefaultEndpoint_WithProtocol(t *testing.T) {
	Endpoint = "https://example.com"
	e := NewDefaultEndpoint()
	if e.AuthURL != "https://example.com/oauth/authorize" {
		t.Fatal("incorrect AuthURL")
	}
	if e.TokenURL != "https://example.com/oauth/token" {
		t.Fatal("incorrect TokenURL")
	}
}
