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

func CreateEmail(input CreateEmailInput) (emailInput ses.SendEmailInput, err error) {
	var recipients []*string
	for _, recipient := range input.Recipients {
		recipients = append(recipients, &recipient)
	}
	dest := ses.Destination{
		ToAddresses: recipients,
	}
	subject := ses.Content{
		Charset: &input.CharSet,
		Data:    &input.Subject,
	}
	htmlBody := ses.Content{
		Charset: &input.CharSet,
		Data:    &input.Html,
	}
	var body ses.Body
	body.SetHtml(&htmlBody)
	message := ses.Message{
		Subject: &subject,
		Body:    &body,
	}

	emailInput = ses.SendEmailInput{
		Destination: &dest,
		Message:     &message,
		Source:      &input.Source,
	}
	return
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
