package ape

import (
	"fmt"

	"encoding/csv"
	"io"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	h "github.com/jonhadfield/gogland-test/helpers"
	r "github.com/jonhadfield/gogland-test/root"
)

var severities = map[string]int64{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}
type EnforcePlanInput struct {
	DryRun          bool
	RoleArn         string
	ExternalId      string
	RoleSessionName string
	IgnoreFailures  bool
	Interactive     bool
	LogLevel        string
	Email           r.Email
	Slack           r.Slack
}

type CreatePolicyOutputInput struct {
	PlanItem     PlanItem
	Details      []EnforcePolicyOutputItemDetail
	Action       string
	ActionResult string
	Success      bool
	ResourceName string
	ResourceArn  string
}

func AppendPolicyOutput(existing EnforcePolicyOutput, input CreatePolicyOutputInput) (output EnforcePolicyOutput) {
	output = append(existing, EnforcePolicyOutputItem{
		AccountId:    input.PlanItem.Target.AccountID,
		AccountAlias: input.PlanItem.Target.AccountAlias,
		PolicyName:   input.PlanItem.Policy.Name,
		ResourceName: input.PlanItem.Target.AccountID,
		ResourceArn:  input.ResourceArn,
		Severity:     input.PlanItem.Policy.Severity,
		Details:      input.Details,
		Action:       input.Action,
		ActionResult: input.ActionResult,
		Success:      input.Success,
		Time:         time.Now(),
	})
	return
}

type EnforcePlanOutput []EnforcePlanItemOutput

type enforcePlanItemInput struct {
	session *session.Session
	dryRun  bool
}

type EnforcePlanItemOutput []EnforcePolicyOutput

type LoadPlanInput struct {
	PlanPath     string
	PlaybookFile string
	PolicyFile   string
}

type EnforcePolicyOutputItemDetail struct {
	ResourceId     string
	ResourceName   string
	ResourceType   string
	ResourceArn    string
	MatchingPolicy *r.Policy
}

type EnforcePolicyOutputItem struct {
	AccountId    string
	AccountAlias string
	PolicyName   string
	ResourceName string
	ResourceType string
	ResourceArn  string
	Action       string
	ActionResult string
	Severity     string // critical, high, medium, low
	Details      []EnforcePolicyOutputItemDetail
	Success      bool
	Time         time.Time
}

type EnforcePolicyOutput []EnforcePolicyOutputItem

type Plan []PlanItem

type PlanItemTarget struct {
	AccountID    string
	AccountAlias string
	Regions      []string
	Role         string
	ExternalID   string `yaml:"ExternalId"`
}

type PlanItem struct {
	ID      string
	Target  PlanItemTarget
	Policy  r.Policy
	PlayRef string
}

type CreatePlanInput struct {
	PlaybookFilePath string
	AccountsFilePath string
	PoliciesFilePath string
	AssueRole        string
	OutputFile       string
}

type CreatePlanOutput struct {
	Plan  *Plan
	Email r.Email
	Slack r.Slack
}

const (
	CRUser                           = iota
	CRArn                            = iota
	CRUser_creation_time             = iota
	CRPassword_enabled               = iota
	CRPassword_last_used             = iota
	CRPassword_last_changed          = iota
	CRPassword_next_rotation         = iota
	CRMfa_active                     = iota
	CRAccess_key_1_active            = iota
	CRAccess_key_1_last_rotated      = iota
	CRAccess_key_1_last_used_date    = iota
	CRAccess_key_1_last_used_region  = iota
	CRAccess_key_1_last_used_service = iota
	CRAccess_key_2_active            = iota
	CRAccess_key_2_last_rotated      = iota
	CRAccess_key_2_last_used_date    = iota
	CRAccess_key_2_last_used_region  = iota
	CRAccess_key_2_last_used_service = iota
	CRCert_1_active                  = iota
	CRCert_1_last_rotated            = iota
	CRCert_2_active                  = iota
	CRCert_2_last_rotated            = iota
)

func ptrToStr(s string) *string {
	return &s
}

func ListUsers(svc iamiface.IAMAPI) (users *iam.ListUsersOutput, err error) {
	users, err = svc.ListUsers(&iam.ListUsersInput{})
	return
}

func getMFADevices(svc iamiface.IAMAPI, username string) (devices []*iam.MFADevice) {
	input := iam.ListMFADevicesInput{}
	if username != "" {
		input.UserName = &username
	}
	output, _ := svc.ListMFADevices(&input)
	devices = output.MFADevices
	return
}

func getAccessKeys(svc iamiface.IAMAPI, username string) (accessKeys []*iam.AccessKeyMetadata) {
	input := iam.ListAccessKeysInput{}
	if username != "" {
		input.UserName = &username
	}
	list, _ := svc.ListAccessKeys(&input)
	accessKeys = list.AccessKeyMetadata
	return
}

func enforceIAMPolicy(session *session.Session, planItem PlanItem) (result EnforcePolicyOutput, err error) {
	_, resource, err := h.GetResourceParts(planItem.Policy.Resource)
	switch resource {
	case "User":
		result, _ = EnforceUserPolicy(session, planItem)
	case "PasswordPolicy":
		result, _ = EnforcePasswordPolicy(session, planItem)
	default:
		err = fmt.Errorf("unhandled resource: iam:%s", resource)
	}
	return
}

type CredentialReportItem struct {
	User                      string
	Arn                       string
	UserCreationTime          time.Time
	PasswordEnabled           bool
	PasswordLastUsed          time.Time
	PasswordLastChanged       time.Time
	PasswordNextRotation      time.Time
	MfaActive                 bool
	AccessKey1Active          bool
	AccessKey1LastRotated     time.Time
	AccessKey1LastUsedDate    time.Time
	AccessKey1LastUsedRegion  string
	AccessKey1LastUsedService string
	AccessKey2Active          bool
	AccessKey2LastRotated     time.Time
	AccessKey2LastUsedDate    time.Time
	AccessKey2LastUsedRegion  string
	AccessKey2LastUsedService string
	Cert1Active               bool
	Cert1LastRotated          time.Time
	Cert2Active               bool
	Cert2LastRotated          time.Time
}

type CredentialReport []CredentialReportItem

func stringToBool(input string) (output bool, err error) {
	switch strings.ToLower(input) {
	case "true":
		output = true
	case "false":
		output = false
	default:
		err = fmt.Errorf("input: \"%s\" cannot be converted to bool", input)
	}
	return
}

func getCredentialReport(svc iamiface.IAMAPI) (output CredentialReport, err error) {
	getInput := &iam.GetCredentialReportInput{}
	var report *iam.GetCredentialReportOutput
	genInput := &iam.GenerateCredentialReportInput{}
	var generateCredentialReportOutput *iam.GenerateCredentialReportOutput
	for {
		generateCredentialReportOutput, err = svc.GenerateCredentialReport(genInput)
		if err != nil {
			return
		}
		if *generateCredentialReportOutput.State != "COMPLETE" {
			time.Sleep(500 * time.Millisecond)
			continue
		} else {
			break
		}
	}

	report, err = svc.GetCredentialReport(getInput)
	if err != nil {
		return
	}
	reportContent := string(report.Content)

	r := csv.NewReader(strings.NewReader(reportContent))
	var readErr error
	var record []string
	var reportItem CredentialReportItem
	for {
		record, readErr = r.Read()
		if len(record) > 0 && record[0] == "user" && record[1] == "arn" {
			continue
		}
		if readErr == io.EOF {
			break
		}
		var userName string
		if record[CRUser] == "<root_account>" {
			userName = "root"
		} else {
			userName = record[CRUser]
		}

		userCreationTime, _ := time.Parse(time.RFC3339, record[CRUser_creation_time])
		passwordEnabled, _ := stringToBool(record[CRPassword_enabled])
		passwordLastUsed, _ := time.Parse(time.RFC3339, record[CRPassword_last_used])
		passwordLastChanged, _ := time.Parse(time.RFC3339, record[CRPassword_last_changed])
		passwordNextRotation, _ := time.Parse(time.RFC3339, record[CRPassword_next_rotation])
		mfaActive, _ := stringToBool(record[CRMfa_active])
		accessKey1Active, _ := stringToBool(record[CRAccess_key_1_active])
		accessKey1LastRotated, _ := time.Parse(time.RFC3339, record[CRAccess_key_1_last_rotated])
		accessKey1LastUsedDate, _ := time.Parse(time.RFC3339, record[CRAccess_key_1_last_used_date])
		accessKey2Active, _ := stringToBool(record[CRAccess_key_2_active])
		accessKey2LastRotated, _ := time.Parse(time.RFC3339, record[CRAccess_key_2_last_rotated])
		accessKey2LastUsedDate, _ := time.Parse(time.RFC3339, record[CRAccess_key_2_last_used_date])
		cert1Active, _ := stringToBool(record[CRCert_1_active])
		cert1LastRotated, _ := time.Parse(time.RFC3339, record[CRCert_1_last_rotated])
		cert2Active, _ := stringToBool(record[CRCert_2_active])
		cert2LastRotated, _ := time.Parse(time.RFC3339, record[CRCert_2_last_rotated])

		reportItem = CredentialReportItem{
			Arn:                       record[CRArn],
			User:                      userName,
			UserCreationTime:          userCreationTime,
			PasswordEnabled:           passwordEnabled,
			PasswordLastUsed:          passwordLastUsed,
			PasswordLastChanged:       passwordLastChanged,
			PasswordNextRotation:      passwordNextRotation,
			MfaActive:                 mfaActive,
			AccessKey1Active:          accessKey1Active,
			AccessKey1LastRotated:     accessKey1LastRotated,
			AccessKey1LastUsedDate:    accessKey1LastUsedDate,
			AccessKey1LastUsedRegion:  record[CRAccess_key_1_active],
			AccessKey1LastUsedService: record[CRAccess_key_1_active],
			AccessKey2Active:          accessKey2Active,
			AccessKey2LastRotated:     accessKey2LastRotated,
			AccessKey2LastUsedDate:    accessKey2LastUsedDate,
			AccessKey2LastUsedRegion:  record[CRAccess_key_2_active],
			AccessKey2LastUsedService: record[CRAccess_key_2_active],
			Cert1Active:               cert1Active,
			Cert1LastRotated:          cert1LastRotated,
			Cert2Active:               cert2Active,
			Cert2LastRotated:          cert2LastRotated,
		}
		output = append(output, reportItem)
	}
	return
}

func getAccessKeyLastUsed(svc iamiface.IAMAPI, accessKeyId string) (time *time.Time) {
	input := iam.GetAccessKeyLastUsedInput{
		AccessKeyId: &accessKeyId,
	}
	output, _ := svc.GetAccessKeyLastUsed(&input)
	time = output.AccessKeyLastUsed.LastUsedDate
	return
}

func filterUserName(user *iam.User, filter *r.Filter) (filterMatch bool) {
	if filter.Comparison == "in" {
		if h.StringInSlice(*user.UserName, filter.Values) {
			filterMatch = true
		}
	}
	if filter.Comparison == "not in" {
		if !h.StringInSlice(*user.UserName, filter.Values) {
			filterMatch = true
		}
	}
	return
}

func filterHasPassword(svc iamiface.IAMAPI, user *iam.User, filter *r.Filter) (filterMatch bool, err error) {
	var getLoginProfileOutput *iam.GetLoginProfileOutput
	getLoginProfileInput := &iam.GetLoginProfileInput{
		UserName: user.UserName,
	}
	var hasPassword bool
	getLoginProfileOutput, err = svc.GetLoginProfile(getLoginProfileInput)
	if err != nil {
		return
	}
	if getLoginProfileOutput.LoginProfile != nil {
		hasPassword = true
	}
	if filter.Value == "false" && !hasPassword {
		filterMatch = true
	}
	if filter.Value == "true" && hasPassword {
		filterMatch = true
	}
	return
}

func filterHasMFADevice(svc iamiface.IAMAPI, user *iam.User, filter *r.Filter) (filterMatch bool, err error) {
	devices := getMFADevices(svc, *user.UserName)
	hasMFADevice := "false"
	if len(devices) > 0 {
		hasMFADevice = "true"
	}
	if filter.Value == "false" && hasMFADevice == "false" {
		filterMatch = true
	}
	if filter.Value == "true" && hasMFADevice == "true" {
		filterMatch = true
	}
	return
}

func filterPasswordLastUsed(user *iam.User, filter *r.Filter) (filterMatch bool, err error) {
	loc, _ := time.LoadLocation("UTC")
	filterValue := h.ProcessTimeFilterValue(filter)
	if user.PasswordLastUsed != nil && !user.PasswordLastUsed.IsZero() {
		passwordLastUsed := user.PasswordLastUsed.In(loc)
		expressionTxt := fmt.Sprintf("(filterValue %s lastUsed)", filter.Comparison)
		expression, _ := govaluate.NewEvaluableExpression(expressionTxt)
		parameters := make(map[string]interface{}, 8)
		parameters["lastUsed"] = passwordLastUsed.Unix()
		parameters["filterValue"] = filterValue.Unix()
		result, _ := expression.Evaluate(parameters)
		if result == true {
			filterMatch = true
		}
	}
	return
}

type filterAccessKeysLastUsedInput struct {
	svc                        iamiface.IAMAPI
	user                       *iam.User
	filter                     *r.Filter
	rootAccessKey1Active       bool
	rootAccessKey1LastUsedDate time.Time
	rootAccessKey2Active       bool
	rootAccessKey2LastUsedDate time.Time
}

func filterAccessKeysLastUsed(input *filterAccessKeysLastUsedInput) (filterMatch bool, err error) {
	loc, _ := time.LoadLocation("UTC")
	filterValue := h.ProcessTimeFilterValue(input.filter)
	var keys []*iam.AccessKeyMetadata
	// have to process root access keys separately
	var key1Status, key2Status string
	// manually add the root keys obtained from the credential report
	if *input.user.UserName == "root" {

		if input.rootAccessKey1Active {
			key1Status = "Active"
		}
		key1 := &iam.AccessKeyMetadata{
			UserName:    input.user.UserName,
			AccessKeyId: ptrToStr("accessKey1"),
			Status:      &key1Status,
		}
		if input.rootAccessKey2Active {
			key2Status = "Active"
		}
		key2 := &iam.AccessKeyMetadata{
			UserName:    input.user.UserName,
			AccessKeyId: ptrToStr("accessKey2"),
			Status:      &key2Status,
		}
		keys = append(keys, key1, key2)
	} else {
		keys = getAccessKeys(input.svc, *input.user.UserName)

	}
	for _, key := range keys {
		if *key.Status == "Active" {
			// Check if key last used > or < date
			var keyLastUsed *time.Time
			// Have to process root access keys separately
			switch *key.AccessKeyId {
			case "accessKey1":
				keyLastUsed = &input.rootAccessKey1LastUsedDate
			case "accessKey2":
				keyLastUsed = &input.rootAccessKey2LastUsedDate
			default:
				keyLastUsed = getAccessKeyLastUsed(input.svc, *key.AccessKeyId)
			}

			if keyLastUsed != nil {
				keyLastUsedConverted := keyLastUsed.In(loc)
				expressionTxt := fmt.Sprintf("(filterValue %s lastUsed)", input.filter.Comparison)
				expression, _ := govaluate.NewEvaluableExpression(expressionTxt)
				parameters := make(map[string]interface{}, 8)
				parameters["lastUsed"] = keyLastUsedConverted.Unix()
				parameters["filterValue"] = filterValue.Unix()
				result, _ := expression.Evaluate(parameters)
				if result == true {
					filterMatch = true
					break
				}
			}

		}
	}
	return
}

func filterActiveAccessKeysAge(svc iamiface.IAMAPI, user *iam.User, filter *r.Filter) (filterMatch bool, err error) {
	loc, _ := time.LoadLocation("UTC")
	filterValue := h.ProcessTimeFilterValue(filter)
	keys := getAccessKeys(svc, *user.UserName)
	for _, key := range keys {
		if *key.Status == "Active" {
			// Check if key age > or < date
			keyCreated := key.CreateDate.In(loc)
			expressionTxt := fmt.Sprintf("(filterValue %s lastUsed)", filter.Comparison)
			expression, _ := govaluate.NewEvaluableExpression(expressionTxt)
			parameters := make(map[string]interface{}, 8)
			parameters["lastUsed"] = keyCreated.Unix()
			parameters["filterValue"] = filterValue.Unix()
			result, _ := expression.Evaluate(parameters)
			if result == true {
				filterMatch = true
				break
			}
		}
	}
	return
}

func EnforceUserPolicy(session *session.Session, planItem PlanItem) (output EnforcePolicyOutput, err error) {
	// Create IAM client
	svc := iam.New(session)
	var listUsersOutput *iam.ListUsersOutput
	listUsersOutput, err = ListUsers(svc)
	if err != nil {
		return
	}
	var credReport CredentialReport
	credReport, err = getCredentialReport(svc)
	if err != nil {
		return
	}
	users := listUsersOutput.Users
	var rootAccessKey1Active bool
	var rootAccessKey1LastUsedDate time.Time
	var rootAccessKey2Active bool
	var rootAccessKey2LastUsedDate time.Time

	// add root user details obtained from credential report
	for _, crUser := range credReport {
		if crUser.User == "root" {
			rootAccessKey1Active = crUser.AccessKey1Active
			rootAccessKey1LastUsedDate = crUser.AccessKey1LastUsedDate
			rootAccessKey2Active = crUser.AccessKey2Active
			rootAccessKey2LastUsedDate = crUser.AccessKey2LastUsedDate
			uct := crUser.UserCreationTime.UTC()
			plu := crUser.PasswordLastUsed.UTC()
			arn := &crUser.Arn
			rootUser := iam.User{
				CreateDate:       &uct,
				UserName:         ptrToStr("root"),
				Arn:              ptrToStr(*arn),
				PasswordLastUsed: &plu,
				Path:             ptrToStr(""),
				UserId:           ptrToStr(""),
			}
			users = append(users, &rootUser)
		}
	}
	for _, user := range users {
		filterMatch, filtersMatch := false, false
		for _, filter := range planItem.Policy.Filters {
			filterMatch = false
			switch filter.Criterion {
			case "UserName":
				// imp:iam:User:UserName
				filterMatch = filterUserName(user, &filter)

			case "HasPassword":
				// imp:iam:User:HasPassword
				filterMatch, err = filterHasPassword(svc, user, &filter)

			case "HasMFADevice":
				// imp:iam:User:HasMFADevice
				filterMatch, err = filterHasMFADevice(svc, user, &filter)

			case "PasswordLastUsed":
				// imp:iam:User:PasswordLastUsed
				filterMatch, err = filterPasswordLastUsed(user, &filter)

			case "AccessKeyLastUsed":
				// imp:iam:User:AccessKeyLastUsed
				filterInput := filterAccessKeysLastUsedInput{
					svc:                        svc,
					user:                       user,
					filter:                     &filter,
					rootAccessKey1Active:       rootAccessKey1Active,
					rootAccessKey1LastUsedDate: rootAccessKey1LastUsedDate,
					rootAccessKey2Active:       rootAccessKey2Active,
					rootAccessKey2LastUsedDate: rootAccessKey2LastUsedDate,
				}
				filterMatch, err = filterAccessKeysLastUsed(&filterInput)

			case "ActiveAccessKeysAge":
				// imp:iam:User:ActiveAccessKeysAge
				filterMatch, err = filterActiveAccessKeysAge(svc, user, &filter)
			}
			// If not found, then no point running more filters
			if !filterMatch {
				filtersMatch = false
				break
			} else {
				filtersMatch = true
			}
		}
		if filtersMatch {
			// All filters match for this user, so perform all actions
			for _, action := range planItem.Policy.Actions {
				switch strings.ToLower(action) {
				case "report":
					// TODO: Output the affected items, e.g. access key ids
					output = AppendPolicyOutput(output, CreatePolicyOutputInput{
						PlanItem:     planItem,
						ResourceName: *user.UserName,
						ResourceArn:  *user.Arn,
						Action:       "report",
						ActionResult: "",
						Success:      true,
					})
				case "delete":
					fmt.Printf("Deleting user: %s matches all filters.\n", *user.UserName)
					output = AppendPolicyOutput(output, CreatePolicyOutputInput{
						PlanItem:     planItem,
						ResourceName: *user.UserName,
						ResourceArn:  *user.Arn,
						Action:       "<delete response goes here>",
						ActionResult: "<action result goes here>",
						Success:      true,
					})
				}
			}
		}
	}
	return
}

func EnforcePasswordPolicy(session *session.Session, planItem PlanItem) (output EnforcePolicyOutput, err error) {
	svc := iam.New(session)
	var getPolicyOutput *iam.GetAccountPasswordPolicyOutput
	getPolicyOutput, _ = svc.GetAccountPasswordPolicy(&iam.GetAccountPasswordPolicyInput{})
	filtersMatch := false

	//  AllowUsersToChangePassword should be: true
	if !*getPolicyOutput.PasswordPolicy.AllowUsersToChangePassword {
		filtersMatch = true
	}
	//  ExpirePasswords should be: true
	if !*getPolicyOutput.PasswordPolicy.ExpirePasswords {
		filtersMatch = true
	}
	//	HardExpiry should be: false
	if *getPolicyOutput.PasswordPolicy.HardExpiry {
		filtersMatch = true
	}
	//	MaxPasswordAge should be: <= 90
	if *getPolicyOutput.PasswordPolicy.MaxPasswordAge > 90 {
		filtersMatch = true
	}
	//	MinimumPasswordLength should be: >= 20
	if *getPolicyOutput.PasswordPolicy.MinimumPasswordLength < 20 {
		filtersMatch = true
	}
	//	PasswordReusePrevention should be: >= 24
	if *getPolicyOutput.PasswordPolicy.PasswordReusePrevention < 24 {
		filtersMatch = true
	}
	//	RequireLowercaseCharacters should be: true
	if !*getPolicyOutput.PasswordPolicy.RequireLowercaseCharacters {
		filtersMatch = true
	}
	//	RequireNumbers should be: true
	if !*getPolicyOutput.PasswordPolicy.RequireNumbers {
		filtersMatch = true
	}
	//	RequireSymbols should be: true
	if !*getPolicyOutput.PasswordPolicy.RequireSymbols {
		filtersMatch = true
	}
	//	RequireUppercaseCharacters should be: true
	if !*getPolicyOutput.PasswordPolicy.RequireUppercaseCharacters {
		filtersMatch = true
	}

	if filtersMatch {
		output = AppendPolicyOutput(EnforcePolicyOutput{}, CreatePolicyOutputInput{
			PlanItem:     planItem,
			ResourceArn:  "Password Policy",
			Action:       "report",
			ActionResult: "",
			Success:      true,
		})
	}

	return
}
