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

var IAMUserCriteria Criteria = Criteria{
	{
		Name:        "UserName",
		Comparisons: []string{"in", "not in"},
	},
	{
		Name:        "HasMFADevice",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasPassword",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "PasswordLastUsed",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	},
	{
		Name:        "AccessKeysLastUsed",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	},
	{
		Name:        "ActiveAccessKeysAge",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	},
}

var EC2InstanceCriteria Criteria = Criteria{
	{
		Name:        "InstanceType",
		Comparisons: []string{"in", "not in"},
	},
}

var EC2VolumeCriteria Criteria = Criteria{
	{
		Name:        "Attached",
		Comparisons: []string{"bool"},
	},
}

var CloudTrailTrailCriteria Criteria = Criteria{
	{
		Name:        "IsMultiRegionTrail",
		Comparisons: []string{"bool"},
	},
}

var IAMResources Resources = []Resource{
	{
		Name:     "User",
		Criteria: IAMUserCriteria,
	},
	{
		Name: "PasswordPolicy",
	},
}

var EC2Resources Resources = []Resource{
	{
		Name:     "Instance",
		Criteria: EC2InstanceCriteria,
	},
	{
		Name:     "Volume",
		Criteria: EC2VolumeCriteria,
	},
}

var CloudTrailResources Resources = []Resource{
	{
		Name:     "Trail",
		Criteria: CloudTrailTrailCriteria,
	},
}
