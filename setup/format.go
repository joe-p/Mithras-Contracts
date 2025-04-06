package setup

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// formatWithUnderscores formats a number with underscores every 3 digits
func formatWithUnderscores(num int) string {
	numStr := strconv.Itoa(num)
	n := len(numStr)
	var result strings.Builder
	for i, digit := range numStr {
		result.WriteByte(byte(digit))
		if (n-i-1)%3 == 0 && i != n-1 {
			result.WriteByte('_')
		}
	}
	return result.String()
}

// formatAsStringConcatenation converts a [][]byte to a string that looks like:
// "hex1"
// + "hex2"
// ...
// idented with `ident` spaces
func formatAsStringConcatenation(slices [][]byte, ident int) string {
	if len(slices) == 0 {
		return ""
	}
	spaces := strings.Repeat(" ", ident)
	var builder strings.Builder
	for i, bs := range slices {
		hexStr := hex.EncodeToString(bs)
		if i == 0 {
			builder.WriteString(spaces)
		} else {
			builder.WriteString("\n" + spaces + "+ ")
		}
		builder.WriteString("\"" + hexStr + "\"")
	}
	return builder.String()
}
