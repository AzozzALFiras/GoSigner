package errors

import "fmt"

// ErrInvalidMachO indicates a malformed or unsupported Mach-O binary.
type ErrInvalidMachO struct {
	Detail string
}

func (e *ErrInvalidMachO) Error() string {
	return fmt.Sprintf("invalid mach-o: %s", e.Detail)
}

// ErrInvalidCertificate indicates a problem loading or parsing a certificate.
type ErrInvalidCertificate struct {
	Detail string
}

func (e *ErrInvalidCertificate) Error() string {
	return fmt.Sprintf("invalid certificate: %s", e.Detail)
}

// ErrInvalidProfile indicates a problem with a provisioning profile.
type ErrInvalidProfile struct {
	Detail string
}

func (e *ErrInvalidProfile) Error() string {
	return fmt.Sprintf("invalid provisioning profile: %s", e.Detail)
}

// ErrInvalidIPA indicates a problem with the IPA archive.
type ErrInvalidIPA struct {
	Detail string
}

func (e *ErrInvalidIPA) Error() string {
	return fmt.Sprintf("invalid ipa: %s", e.Detail)
}

// ErrSigningFailed indicates a failure during the code signing process.
type ErrSigningFailed struct {
	Detail string
}

func (e *ErrSigningFailed) Error() string {
	return fmt.Sprintf("signing failed: %s", e.Detail)
}

// ErrUnsupportedFormat indicates an unrecognized file format.
type ErrUnsupportedFormat struct {
	Format string
}

func (e *ErrUnsupportedFormat) Error() string {
	return fmt.Sprintf("unsupported format: %s", e.Format)
}
