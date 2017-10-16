package root

type Policies struct {
	Policies []Policy
}
type Policy struct {
	Name     string
	Desc     string
	Resource string
	Severity string // critical, high, medium, low
	Filters  []Filter
	Actions  []string
}
