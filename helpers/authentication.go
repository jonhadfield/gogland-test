package helpers

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"

	"os"
)

func GetSession() (sess *session.Session) {
	sess, err := session.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	return sess
}

type GetAssumeRoleCredsInput struct {
	Sess       *session.Session
	AccountId  string
	RoleArn    string
	RoleName   string
	ExternalId string
}

//func GetAssumeRoleCreds(sess *session.Session, accountId string, role string, externalId string) (creds *credentials.Credentials, err error) {
func GetAssumeRoleCreds(input GetAssumeRoleCredsInput) (creds *credentials.Credentials, err error) {
	var roleArn string
	if input.RoleArn != "" {
		roleArn = input.RoleArn
	} else {
		roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", input.AccountId, input.RoleName)
	}
	// TODO: Test without external id specified
	creds = stscreds.NewCredentials(input.Sess, roleArn, func(p *stscreds.AssumeRoleProvider) {
		p.ExternalID = &input.ExternalId
	})
	_, err = creds.Get()
	if err != nil {
		err = fmt.Errorf("Unable to assume role: %s\nMessage: %s", roleArn, err)
	}
	return
}
