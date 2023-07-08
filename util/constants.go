package util

import (
	"encoding/base32"
)

var B32NoPadding *base32.Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	DIGIT_SIZE  int32 = 6
	SECRET_SIZE int32 = 10
)

type SourceType string

const (
	TOTP SourceType = "totp"
	HOTP SourceType = "hotp"
)

const (
	TOTP_PERIOD int64 = 30
)
