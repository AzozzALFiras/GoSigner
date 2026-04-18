package appstore

// JWTConfig holds the configuration for App Store Connect API authentication.
type JWTConfig struct {
	IssuerID string // Issuer ID from App Store Connect
	KeyID    string // Key ID for the .p8 key
	// PrivateKey is loaded separately via certificate/loader/p8.go
}
