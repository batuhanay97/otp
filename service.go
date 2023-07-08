package otp

import (
	"errors"

	"github.com/batuhanay97/otp/adapters"
	hotpAdapter "github.com/batuhanay97/otp/adapters/hotp"
	totpAdapter "github.com/batuhanay97/otp/adapters/totp"
	otpService "github.com/batuhanay97/otp/service/otp"
	"github.com/batuhanay97/otp/util"
)

type Service interface {
	addAdapter(otpAdapter adapters.Adapter)
	getAdapter(typ util.SourceType) (adapters.Adapter, error)

	Generate(provider SourceType, issuer, username string, counter ...uint64) (string, string, string, error)
	Validate(provider SourceType, code, secret string, counter ...uint64) (bool, error)
}

type service struct {
	adapters map[util.SourceType]adapters.Adapter
	otpSrv   otpService.Service
}

func NewService() Service {
	s := new(service)

	s.adapters = make(map[util.SourceType]adapters.Adapter)
	s.otpSrv = otpService.NewService()
	s.Init()
	return s
}

func (s *service) Init() {
	hotp := hotpAdapter.NewAdapter(s.otpSrv)
	s.addAdapter(hotp)
	totp := totpAdapter.NewAdapter(s.otpSrv)
	s.addAdapter(totp)
}

func (s *service) addAdapter(otpAdapter adapters.Adapter) {
	if _, ok := s.adapters[otpAdapter.SourceTyp()]; !ok {
		s.adapters[otpAdapter.SourceTyp()] = otpAdapter
	}
}

func (s *service) getAdapter(typ util.SourceType) (adapters.Adapter, error) {
	if data, ok := s.adapters[typ]; ok {
		return data, nil
	}
	return nil, errors.New("component not implemented")
}

func (s *service) Generate(provider SourceType, issuer, username string, counter ...uint64) (string, string, string, error) {
	a, err := s.getAdapter(util.SourceType(provider))
	if err != nil {
		return "", "", "", err
	}
	return a.Generate(issuer, username, counter...)
}

func (s *service) Validate(provider SourceType, code, secret string, counter ...uint64) (bool, error) {
	a, err := s.getAdapter(util.SourceType(provider))
	if err != nil {
		return false, err
	}
	return a.Validate(code, secret, counter...)
}
