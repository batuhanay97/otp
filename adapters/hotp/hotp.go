package hotp

import (
	"errors"
	"net/url"
	"strconv"

	"github.com/batuhanay97/otp/adapters"
	otpService "github.com/batuhanay97/otp/service/otp"
	"github.com/batuhanay97/otp/util"
)

type HotpAdapter struct {
	typ    util.SourceType
	otpSrv otpService.Service
}

func NewAdapter(otpSrv otpService.Service) adapters.Adapter {
	s := new(HotpAdapter)

	s.typ = util.HOTP
	s.otpSrv = otpSrv
	return s
}

func (a *HotpAdapter) Generate(issuer, username string, counter ...uint64) (string, string, string, error) {
	if len(counter) <= 0 {
		return "", "", "", errors.New("counter is needed")
	}

	counterInt := counter[0]

	sec, err := a.otpSrv.Secret()
	if err != nil {
		return "", "", "", err
	}
	hmacSum, err := a.otpSrv.HMACSum(sec, counterInt)
	if err != nil {
		return "", "", "", err
	}

	urlVal := url.Values{}
	urlVal.Set("secret", sec)
	urlVal.Set("issuer", issuer)
	urlVal.Set("algorithm", "SHA1")
	urlVal.Set("digits", strconv.Itoa(int(util.DIGIT_SIZE)))
	u := url.URL{
		Scheme:   "otpauth",
		Host:     string(util.HOTP),
		Path:     "/" + issuer + ":" + username,
		RawQuery: util.EncodeQuery(urlVal),
	}

	return a.otpSrv.Code(hmacSum, a.otpSrv.Offset(hmacSum)), sec, u.String(), nil
}

func (a *HotpAdapter) Validate(code, secret string, counter ...uint64) (bool, error) {
	if len(counter) <= 0 {
		return false, errors.New("counter is needed")
	}

	counterInt := counter[0]
	count := 0
	for count < 4 {
		hmacCounter := counterInt + uint64(count)

		hmacSum, err := a.otpSrv.HMACSum(secret, hmacCounter)
		if err != nil {
			return false, err
		}

		if code == a.otpSrv.Code(hmacSum, a.otpSrv.Offset(hmacSum)) {
			return true, nil
		}

		count++
	}
	return false, nil
}

func (a *HotpAdapter) SourceTyp() util.SourceType {
	return a.typ
}
