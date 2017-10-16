package helpers

import (
	"fmt"
	"os"
)

func OutputInfo(message string) {
	output := PadToWidth(fmt.Sprintf("\ninfo: %v\n", message), " ")
	fmt.Fprintf(os.Stderr, output)
}

func OutputError(err error) {
	output := PadToWidth(fmt.Sprintf("\nerror: %v\n", err), " ")
	fmt.Fprintf(os.Stderr, output)
}

func OutputWarning(err error) {
	output := PadToWidth(fmt.Sprintf("\nwarning: %v\n", err), " ")
	fmt.Fprintf(os.Stderr, output)
}
