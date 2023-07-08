package adapters

import "github.com/batuhanay97/otp/util"

type Adapter interface {
	SourceTyp() util.SourceType

	Generate(issuer, username string, counter ...uint64) (string, string, string, error)
	Validate(code, secret string, counter ...uint64) (bool, error)
}
