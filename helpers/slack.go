package helpers

import (
	"github.com/jonhadfield/ape/root"
	"github.com/nlopes/slack"
)

type PostSlackMessageInput struct {
	User    string
	Color   string
	PreText string
	Title   string
	Text    string
}

func PostSlackMessage(config root.Slack, input PostSlackMessageInput) (err error) {
	client := slack.New(config.Token)

	attachment := slack.Attachment{
		Color:   input.Color,
		Pretext: input.PreText,
		Title:   input.Title,
		Text:    input.Text,
	}
	attachments := []slack.Attachment{attachment}
	pmParams := slack.PostMessageParameters{
		Username:    config.Username,
		AsUser:      true,
		Attachments: attachments,
	}
	_, _, err = client.PostMessage(config.Channel, "", pmParams)
	return
}
