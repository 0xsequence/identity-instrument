package builder

import (
	"context"
	"fmt"
)

type Mock struct{}

func NewMock() EcosystemManager {
	return Mock{}
}

func (m Mock) GetTemplate(ctx context.Context, projectID uint64, templateType TemplateType) (*EcosystemTemplate, error) {
	return &EcosystemTemplate{
		Subject:   fmt.Sprintf("Login code for %d", projectID),
		IntroText: "Your login code",
		Content:   "Your login code: {auth_code}",
	}, nil
}

var _ EcosystemManager = (*Mock)(nil)
