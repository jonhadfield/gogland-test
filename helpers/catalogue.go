package helpers

type Criterion struct {
	Name        string
	Comparisons []string
	Units       []string
}

type Criteria []Criterion

type Resource struct {
	Name     string
	Criteria Criteria
}

type Resources []Resource

type Service struct {
	Name      string
	Resources []Resource
}

type Services []Service
