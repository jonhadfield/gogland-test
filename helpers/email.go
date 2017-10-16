package helpers

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
)

type CreateEmailInput struct {
	Region     string
	CharSet    string
	Source     string
	Recipients []string
	Subject    string
	Html       string
}


func Send(input ses.SendEmailInput, region string) (err error) {
	sess, err := session.NewSession()
	if err != nil {
		return
	}
	svc := ses.New(sess, &aws.Config{Region: &region})
	_, err = svc.SendEmail(&input)
	if err != nil {
		return
	}
	return
}
