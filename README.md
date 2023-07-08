# Go (Golang) One Time Password (OTP) Library

This library helps to implementing Time-Based One Time Password (TOTP) and HMAC-Based One Time Password (HOTP) algorithms with SHA-1. It produces 6 digits code and 16 digits secret and validates it . Also give you an URL to use it in any authenticator applications like Google Authenticator. The Library supports synchronization (TOTP = 1 min, HOTP = 3 turn)

## Example

**Generate Code**

```go
package main

import (
	"fmt"
	"github.com/batuhanay97/otp"
)

func main() {
	code, secret, url, err := otp.Generate(otp.TOTP, <issuer>, <username>)
	fmt.Println("TOTP: ", code, secret, url, err)
    	// TOTP:  <code> <secret> otpauth://totp/<issuer>:<username>?algorithm=SHA1&digits=6&issuer=<issuer>&period=30&secret=<secret> <err>

	code, secret, url, err = otp.Generate(otp.HOTP, <issuer>, <username>, <counter>)
	fmt.Println("HOTP: ", code, secret, url, err)
    	// HOTP:  <code> <secret> otpauth://hotp/<issuer>:<username>?algorithm=SHA1&digits=6&issuer=<issuer>&secret=<secret> <err>
}
```

**Validate Code**

```go
package main

import (
	"fmt"
	"github.com/batuhanay97/otp"
)

func main() {
	valid, err := otp.Validate(otp.TOTP, <code>, <secret>)
	fmt.Println("TOTP: ", valid, err)
    	// TOTP:  true <nil>

	valid, err = otp.Validate(otp.HOTP, <code>, <secret>, <counter>)
	fmt.Println("HOTP: ", valid, err)
    	// HOTP:  true <nil>
}
```

## License

otp is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license
text.
