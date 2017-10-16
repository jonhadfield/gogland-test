package root

type Role struct {
	Name       string
	RoleType   string `yaml:"roleType"`
	ExternalID string `yaml:"externalId"`
}

type Account struct {
	ID    string
	Alias string
	Roles []Role
}

type Accounts struct {
	Accounts []Account
}
