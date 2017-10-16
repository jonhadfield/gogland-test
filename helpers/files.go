package helpers

import "os"

func DeleteFile(path string) (err error) {
	err = os.Remove(path)
	return
}
