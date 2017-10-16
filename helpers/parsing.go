package helpers

import (
	"strings"

	"github.com/pkg/errors"
)

func GetResourceParts(input string) (service string, resource string, err error) {
	colonPos := strings.Index(input, ":")
	if colonPos < 3 {
		err = errors.New("missing colon or invalid resource")
	} else {
		service = input[0:colonPos]
		resource = input[colonPos+1:]
	}
	return
}

func MapKey(m map[string]int64, value int64) (key string, ok bool) {
	for k, v := range m {
		if v == value {
			key = k
			ok = true
			return
		}
	}
	return
}
