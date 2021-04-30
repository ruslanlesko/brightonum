package main

import (
	"github.com/stretchr/testify/mock"
)

// MailerMock mocks Mailer
type MailerMock struct {
	mock.Mock
}

// SendRecoveryCode mock sending recovery code
func (m *MailerMock) SendRecoveryCode(to string, code string) error {
	return m.Called(to, code).Error(0)
}

// SendInviteCode mock sending invite code
func (m *MailerMock) SendInviteCode(to string, code string) error {
	return m.Called(to, code).Error(0)
}
