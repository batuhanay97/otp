package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"math"

	"github.com/batuhanay97/otp/util"
)

type Service interface {
	Secret() (string, error)
	HMACSum(secret string, counter uint64) ([]byte, error)
	Offset(hsum []byte) byte
	Code(hsum []byte, offset byte) string
}

type service struct{}

func NewService() Service {
	s := new(service)
	return s
}

func (o *service) Secret() (string, error) {
	secret := make([]byte, util.SECRET_SIZE)
	_, err := rand.Reader.Read(secret)
	if err != nil {
		return "", err
	}

	return util.B32NoPadding.EncodeToString(secret), nil
}

func (o *service) HMACSum(secret string, counter uint64) ([]byte, error) {
	secBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 8)
	mac := hmac.New(sha1.New, secBytes)
	binary.BigEndian.PutUint64(buf, counter)

	mac.Write(buf)
	return mac.Sum(nil), nil
}

func (o *service) Offset(hmacSum []byte) byte {
	return hmacSum[len(hmacSum)-1] & 0xf
}

func (o *service) Code(hmacSum []byte, offset byte) string {
	value := int64(((int(hmacSum[offset]) & 0x7f) << 24) |
		((int(hmacSum[offset+1] & 0xff)) << 16) |
		((int(hmacSum[offset+2] & 0xff)) << 8) |
		(int(hmacSum[offset+3]) & 0xff))

	return util.ParseCode((value % int64(math.Pow10(int(util.DIGIT_SIZE)))))
}
