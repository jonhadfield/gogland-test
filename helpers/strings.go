package helpers

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

func ptrToStr(s string) *string {
	return &s
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func PadToWidth(input string, char string) (output string) {
	width, _, _ := terminal.GetSize(0)
	// Split string into lines
	var lines []string
	var newLines []string
	if strings.Contains(input, "\n") {
		lines = strings.Split(input, "\n")
	} else {
		lines = []string{input}
	}
	var paddingSize int
	for i, line := range lines {
		// If the number of the line is == num lines, then it's the last one
		if i == len(lines)-1 {
			paddingSize = width - len(line) - 1
			newLines = append(newLines, fmt.Sprintf("%s%s\r", line, strings.Repeat(char, paddingSize)))
		} else {
			//Not last line
			//fmt.Println("NOT LAST LINE")
			var suffix string
			//if linefeed {
			//	suffix = "\r"
			//}
			//if newline {
			//	suffix = "\n"
			//}
			newLines = append(newLines, fmt.Sprintf("%s%s%s\n", line, strings.Repeat(char, paddingSize), suffix))
		}
	}
	output = strings.Join(newLines, "")
	return
}

func GetStringInBetween(str string, start string, end string) (result string) {
	s := strings.Index(str, start)
	if s == -1 {
		return
	}
	s += len(start)
	e := strings.Index(str, end)
	return str[s:e]
}
