package helpers

import (
	"github.com/aws/aws-sdk-go/aws/session"
)

type GetAssumeRoleCredsInput struct {
	Sess       *session.Session
	AccountId  string
	RoleArn    string
	RoleName   string
	ExternalId string
}
