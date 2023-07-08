package util

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func EncodeQuery(v url.Values) string {
	if v == nil {
		return ""
	}
	var buf strings.Builder
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := v[k]
		keyEscaped := url.PathEscape(k)
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(url.PathEscape(v))
		}
	}
	return buf.String()
}

func ParseCode(code int64) string {
	digitTestCode := code
	digit := 0

	for digitTestCode > 0 {
		digitTestCode = digitTestCode / 10
		digit++
	}

	if DIGIT_SIZE-int32(digit) != 0 {
		return strings.Repeat("0", int(DIGIT_SIZE)-digit) + strconv.Itoa(int(code))
	}

	return strconv.Itoa(int(code))
}
