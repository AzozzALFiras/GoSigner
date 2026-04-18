package client

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"

	"github.com/AzozzALFiras/GoSigner/appstore/auth"
)

const baseURL = "https://api.appstoreconnect.apple.com/v1"

// Client is an App Store Connect API client.
type Client struct {
	httpClient *http.Client
	issuerID   string
	keyID      string
	privateKey *ecdsa.PrivateKey
}

// New creates a new App Store Connect API client.
func New(issuerID string, keyID string, privateKey *ecdsa.PrivateKey) *Client {
	return &Client{
		httpClient: &http.Client{},
		issuerID:   issuerID,
		keyID:      keyID,
		privateKey: privateKey,
	}
}

// GetToken generates a fresh JWT token for API authentication.
func (c *Client) GetToken() (string, error) {
	return auth.GenerateJWT(c.issuerID, c.keyID, c.privateKey)
}

// NewRequest creates an authenticated HTTP request.
func (c *Client) NewRequest(method string, path string) (*http.Request, error) {
	token, err := c.GetToken()
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	url := baseURL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}
