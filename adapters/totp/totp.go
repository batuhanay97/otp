package totp

import (
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/batuhanay97/otp/adapters"
	otpService "github.com/batuhanay97/otp/service/otp"
	"github.com/batuhanay97/otp/util"
)

type TotpAdapter struct {
	typ    util.SourceType
	otpSrv otpService.Service
}

func NewAdapter(otpSrv otpService.Service) adapters.Adapter {
	s := new(TotpAdapter)

	s.typ = util.TOTP
	s.otpSrv = otpSrv
	return s
}

func (a *TotpAdapter) Generate(issuer, username string, _ ...uint64) (string, string, string, error) {
	sec, err := a.otpSrv.Secret()
	if err != nil {
		return "", "", "", err
	}

	counterInt := uint64(math.Floor(float64(time.Now().Unix()) / float64(util.TOTP_PERIOD)))

	hmacSum, err := a.otpSrv.HMACSum(sec, counterInt)
	if err != nil {
		return "", "", "", err
	}

	urlVal := url.Values{}
	urlVal.Set("secret", sec)
	urlVal.Set("issuer", issuer)
	urlVal.Set("period", strconv.FormatUint(uint64(util.TOTP_PERIOD), 10))
	urlVal.Set("algorithm", "SHA1")
	urlVal.Set("digits", strconv.Itoa(int(util.DIGIT_SIZE)))
	u := url.URL{
		Scheme:   "otpauth",
		Host:     string(util.TOTP),
		Path:     "/" + issuer + ":" + username,
		RawQuery: util.EncodeQuery(urlVal),
	}

	return a.otpSrv.Code(hmacSum, a.otpSrv.Offset(hmacSum)), sec, u.String(), nil
}

func (a *TotpAdapter) Validate(code, secret string, counter ...uint64) (bool, error) {
	count := 0
	for count < 3 {
		var hmacCounter uint64

		switch count {
		case 0:
			hmacCounter = uint64(math.Floor(float64(time.Now().Unix()) / float64(util.TOTP_PERIOD)))
		case 1:
			hmacCounter = uint64(math.Floor(float64(time.Now().Add(30*time.Second).Unix()) / float64(util.TOTP_PERIOD)))
		case 2:
			hmacCounter = uint64(math.Floor(float64(time.Now().Add(1*time.Minute).Unix()) / float64(util.TOTP_PERIOD)))
		}

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

func (a *TotpAdapter) SourceTyp() util.SourceType {
	return a.typ
}
