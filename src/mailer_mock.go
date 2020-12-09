package main

import (
	"github.com/stretchr/testify/mock"
)

// MailerMock mocks Mailer
type MailerMock struct {
	mock.Mock
}

// SendRecoveryCode mock sending recovery mock
func (m *MailerMock) SendRecoveryCode(to string, code string) error {
	return m.Called(to, code).Error(0)
}
