package otp

type SourceType string

const (
	TOTP SourceType = "totp"
	HOTP SourceType = "hotp"
)
