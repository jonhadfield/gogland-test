package root

type PlaybookTarget struct {
	RoleType string `yaml:"roleType"`
	Include  []string
	Exclude  []string
}
type Filter struct {
	Criterion  string
	Comparison string
	Unit       string
	Value      string
	Values     []string
}

type Play struct {
	Name     string
	Regions  []string
	Policies []string
	Targets  []PlaybookTarget
}

type Email struct {
	Provider   string
	Host       string
	Port       string
	Username   string
	Password   string
	Region     string
	Source     string
	Subject    string
	Recipients []string
	Threshold  string
}

type Slack struct {
	Channel   string
	Token     string
	Username  string
	Threshold string
}

type Playbook struct {
	Accounts string
	Policies string
	Plays    []Play
	Email    Email
	Slack    Slack
}

type Configs struct {
	Playbook Playbook
	Policies Policies
	Accounts []Account
}
