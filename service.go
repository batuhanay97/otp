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
	otpSrv      = otpService.NewService()
)

func implemention(typ SourceType) {
	switch typ {
	case HOTP:
		hotp := hotpAdapter.NewAdapter(otpSrv)
		addAdapter(hotp)
	case TOTP:
		totp := totpAdapter.NewAdapter(otpSrv)
		addAdapter(totp)
	}
}

func addAdapter(otpAdapter adapters.Adapter) {
	if _, ok := otpAdapters[otpAdapter.SourceTyp()]; !ok {
		otpAdapters[otpAdapter.SourceTyp()] = otpAdapter
	}
}

func getAdapter(typ util.SourceType) (adapters.Adapter, error) {
	if data, ok := otpAdapters[typ]; ok {
		return data, nil
	}
	return nil, errors.New("component not implemented")
}

func Generate(provider SourceType, issuer, username string, counter ...uint64) (string, string, string, error) {
	implemention(provider)
	a, err := getAdapter(util.SourceType(provider))
	if err != nil {
		return "", "", "", err
	}
	return a.Generate(issuer, username, counter...)
}

func Validate(provider SourceType, code, secret string, counter ...uint64) (bool, error) {
	implemention(provider)
	a, err := getAdapter(util.SourceType(provider))
	if err != nil {
		return false, err
	}
	return a.Validate(code, secret, counter...)
}
