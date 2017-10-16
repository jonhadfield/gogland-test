package helpers

import (
	"strconv"
	"time"

	r "github.com/jonhadfield/ape/root"
)

func ProcessTimeFilterValue(filter *r.Filter) (filterValue time.Time) {
	// Time based criterion prep
	loc, _ := time.LoadLocation("UTC")
	now := time.Now().In(loc)
	switch filter.Unit {
	case "days":
		int64val, _ := strconv.ParseInt(filter.Value, 10, 64)
		difference := time.Duration(int64val) * (time.Hour * 24)
		filterValue = now.Add(-difference)
	case "hours":
		int64val, _ := strconv.ParseInt(filter.Value, 10, 64)
		difference := time.Duration(int64val) * time.Hour
		filterValue = now.Add(-difference)
	case "minutes":
		int64val, _ := strconv.ParseInt(filter.Value, 10, 64)
		difference := time.Duration(int64val) * time.Minute
		filterValue = now.Add(-difference)
	case "seconds":
		int64val, _ := strconv.ParseInt(filter.Value, 10, 64)
		difference := time.Duration(int64val) * time.Second
		filterValue = now.Add(-difference)
	}
	return
}
