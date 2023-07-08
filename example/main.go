package main

import (
	"fmt"

	"github.com/batuhanay97/otp"
)

func main() {
	otpSrv := otp.NewService()

	code, secret, url, err := otpSrv.Generate(otp.TOTP, "Dummy-TOTP-ISSUER", "Dummy-TOTP-USERNAME")
	fmt.Println("TOTP: ", code, secret, url, err)

	valid, err := otpSrv.Validate(otp.TOTP, code, secret)
	fmt.Println("TOTP: ", valid, err)

	code, secret, url, err = otpSrv.Generate(otp.HOTP, "Dummy-HOTP-ISSUER", "Dummy-HOTP-USERNAME", 1)
	fmt.Println("HOTP: ", code, secret, url, err)

	valid, err = otpSrv.Validate(otp.HOTP, code, secret, 1)
	fmt.Println("HOTP: ", valid, err)
}
