package otp

import (
	"errors"

	"github.com/batuhanay97/otp/adapters"
	hotpAdapter "github.com/batuhanay97/otp/adapters/hotp"
	totpAdapter "github.com/batuhanay97/otp/adapters/totp"
	otpService "github.com/batuhanay97/otp/service/otp"
	"github.com/batuhanay97/otp/util"
)

var (
	otpAdapters = make(map[util.SourceType]adapters.Adapter, 0)
)

func setOrGetAdapter(typ util.SourceType) (adapters.Adapter, error) {
	if _, ok := otpAdapters[typ]; !ok {
		otpSrv := otpService.NewService()
		switch typ {
		case util.HOTP:
			hotp := hotpAdapter.NewAdapter(otpSrv)
			otpAdapters[typ] = hotp
			return otpAdapters[typ], nil
		case util.TOTP:
			totp := totpAdapter.NewAdapter(otpSrv)
			otpAdapters[typ] = totp
			return otpAdapters[typ], nil
		}

		return nil, errors.New("component not implemented")
	}

	return otpAdapters[typ], nil
}

func Generate(provider SourceType, issuer, username string, counter ...uint64) (string, string, string, error) {
	a, err := setOrGetAdapter(util.SourceType(provider))
	if err != nil {
		return "", "", "", err
	}
	return a.Generate(issuer, username, counter...)
}

func Validate(provider SourceType, code, secret string, counter ...uint64) (bool, error) {
	a, err := setOrGetAdapter(util.SourceType(provider))
	if err != nil {
		return false, err
	}
	return a.Validate(code, secret, counter...)
}
