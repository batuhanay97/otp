package otp

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/batuhanay97/otp/util"
)

func TestGenerateTOTPSuccess(t *testing.T) {
	issuer := "test_issuer"
	username := "test_username"

	code, secret, u, err := Generate(TOTP, issuer, username)
	if err != nil {
		t.Error("Generate func has an error: ", err)
	}

	if len(code) != int(util.DIGIT_SIZE) {
		t.Error("Code has not "+strconv.Itoa(int(util.DIGIT_SIZE))+" digit, got :", len(code))
	}

	if len(secret) != 16 {
		t.Error("Secret has not 16 digit, got :", len(secret))
	}

	parsedURL, err := url.Parse(u)
	if err != nil {
		t.Error("Can not parse url : ", err)
	}

	if secret != parsedURL.Query().Get("secret") {
		t.Error("Secret is not equal with the one that in url")
	}

	if strconv.Itoa(int(util.DIGIT_SIZE)) != parsedURL.Query().Get("digits") {
		t.Error("Digit size is not equal with the one that in url")
	}

	if issuer != parsedURL.Query().Get("issuer") {
		t.Error("Issuer is not equal with the one that in url")
	}

	if strconv.FormatUint(uint64(util.TOTP_PERIOD), 10) != parsedURL.Query().Get("period") {
		t.Error("Period is not equal with the one that in url")
	}
}

func TestValidateTOTPSuccess(t *testing.T) {
	issuer := "test_issuer"
	username := "test_username"

	code, secret, _, err := Generate(TOTP, issuer, username)
	if err != nil {
		t.Error("Generate func has an error: ", err)
	}

	valid, err := Validate(TOTP, code, secret)
	if err != nil {
		t.Error("Validate func has an error: ", err)
	}
	if !valid {
		t.Error("Code and secret is invalid")
	}
}

func TestGenerateHOTPSuccess(t *testing.T) {
	issuer := "test_issuer"
	username := "test_username"

	code, secret, u, err := Generate(HOTP, issuer, username, 1)
	if err != nil {
		t.Error("Generate func has an error: ", err)
	}

	if len(code) != int(util.DIGIT_SIZE) {
		t.Error("Code has not "+strconv.Itoa(int(util.DIGIT_SIZE))+" digit, got :", len(code))
	}

	if len(secret) != 16 {
		t.Error("Secret has not 16 digit, got :", len(secret))
	}

	parsedURL, err := url.Parse(u)
	if err != nil {
		t.Error("Can not parse url : ", err)
	}

	if secret != parsedURL.Query().Get("secret") {
		t.Error("Secret is not equal with the one that in url")
	}

	if strconv.Itoa(int(util.DIGIT_SIZE)) != parsedURL.Query().Get("digits") {
		t.Error("Digit size is not equal with the one that in url")
	}

	if issuer != parsedURL.Query().Get("issuer") {
		t.Error("Issuer is not equal with the one that in url")
	}
}

func TestGenerateHOTPFailCounter(t *testing.T) {
	issuer := "test_issuer"
	username := "test_username"

	_, _, _, err := Generate(HOTP, issuer, username)
	if err.Error() != "counter is needed" {
		t.Error("Generate func has an error: ", err)
	}
}

func TestValidateHOTPSuccess(t *testing.T) {
	issuer := "test_issuer"
	username := "test_username"

	code, secret, _, err := Generate(HOTP, issuer, username, 1)
	if err != nil {
		t.Error("Generate func has an error: ", err)
	}

	valid, err := Validate(HOTP, code, secret, 1)
	if err != nil {
		t.Error("Validate func has an error: ", err)
	}
	if !valid {
		t.Error("Code and secret is invalid")
	}
}

func TestGenerateFailSourceTyp(t *testing.T) {
	issuer := "test_issuer"
	username := "test_username"

	_, _, _, err := Generate("test_typ", issuer, username)
	if err.Error() != "component not implemented" {
		t.Error("Generate func has an error: ", err)
	}
}

func TestValidateFailSourceTyp(t *testing.T) {
	_, err := Validate("test_typ", "", "")
	if err.Error() != "component not implemented" {
		t.Error("Generate func has an error: ", err)
	}
}
