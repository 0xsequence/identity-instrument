package email

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/proto/builder"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Sender struct {
	builder builder.Builder
	awsCfg  aws.Config
	cfg     config.SESConfig
}

func NewSender(builder builder.Builder, awsCfg aws.Config, cfg config.SESConfig) *Sender {
	return &Sender{
		builder: builder,
		awsCfg:  awsCfg,
		cfg:     cfg,
	}
}

func (s *Sender) NormalizeRecipient(recipient string) (string, error) {
	// TODO: Validate email address
	return Normalize(recipient), nil
}

func (s *Sender) SendOTP(ctx context.Context, scope proto.Scope, recipient string, code string) (err error) {
	ctx, span := o11y.Trace(ctx, "email.Sender.SendOTP")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	ecosystem, err := scope.Ecosystem()
	if err != nil {
		return fmt.Errorf("failed to get ecosystem: %w", err)
	}

	// Retrieve the email template from the Builder.
	ecoID, err := strconv.ParseUint(ecosystem, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse ecosystem ID: %w", err)
	}
	tplType := builder.EmailTemplateType_LOGIN
	tpl, err := s.builder.GetEmailTemplate(ctx, ecoID, &tplType)
	if err != nil {
		return fmt.Errorf("failed to build email template: %w", err)
	}

	// Build the email message from templates.
	subject := strings.Replace(tpl.Subject, "{auth_code}", code, 1)
	html := strings.Replace(*tpl.Template, "{auth_code}", code, 1)
	text := tpl.IntroText + "\n\n" + code

	awsCfg := s.awsCfg // make a copy
	accessRoleARN := s.cfg.AccessRoleARN
	if tpl.SesConfig != nil && tpl.SesConfig.AccessRoleARN != "" {
		accessRoleARN = tpl.SesConfig.AccessRoleARN
	}
	if accessRoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, accessRoleARN)
		awsCfg.Credentials = aws.NewCredentialsCache(creds)
	}
	if tpl.SesConfig != nil && tpl.SesConfig.Region != "" {
		awsCfg.Region = tpl.SesConfig.Region
	} else if s.cfg.Region != "" {
		awsCfg.Region = s.cfg.Region
	}

	source := &s.cfg.Source
	if tpl.FromEmail != nil && *tpl.FromEmail != "" {
		source = tpl.FromEmail
	}

	sourceARN := &s.cfg.SourceARN
	if tpl.SesConfig != nil && tpl.SesConfig.SourceARN != "" {
		sourceARN = &tpl.SesConfig.SourceARN
	}

	client := ses.NewFromConfig(awsCfg)
	_, err = client.SendEmail(ctx, &ses.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses: []string{recipient},
		},
		Message: &types.Message{
			Body: &types.Body{
				Html: &types.Content{
					Data:    &html,
					Charset: aws.String("UTF-8"),
				},
				Text: &types.Content{
					Data:    &text,
					Charset: aws.String("UTF-8"),
				},
			},
			Subject: &types.Content{
				Data:    &subject,
				Charset: aws.String("UTF-8"),
			},
		},
		Source:    source,
		SourceArn: sourceARN,
	})
	return err
}
