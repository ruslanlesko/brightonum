package email

import (
	"fmt"
	"net/smtp"
)

// Mailer sends emails
type Mailer interface {
	SendRecoveryCode(string, string) error
	SendInviteCode(string, string) error
	SendVerificationCode(string, string) error
}

// EmailMailer sends emails
type EmailMailer struct {
	Email    string
	Password string
	Server   string
	Port     int
	SiteName string
}

// SendRecoveryCode sends password recovery code
func (m *EmailMailer) SendRecoveryCode(to string, code string) error {
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + m.SiteName + " recovery code\r\n" +
		"\r\n" +
		"Your password recovery code: " +
		code +
		"\r\n")
	return m.send(to, msg)
}

// SendInviteCode sends invite code
func (m *EmailMailer) SendInviteCode(to string, code string) error {
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + m.SiteName + " invite code\r\n" +
		"\r\n" +
		"Your invite code: " +
		code +
		"\r\n")
	return m.send(to, msg)
}

// SendVerificationCode sends verification code
func (m *EmailMailer) SendVerificationCode(to string, code string) error {
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + m.SiteName + " Verification Code\r\n" +
		"\r\n" +
		"Your verification code: " +
		code +
		"\r\n")
	return m.send(to, msg)
}

func (m *EmailMailer) send(to string, msg []byte) error {
	auth := LoginAuth(m.Email, m.Password)
	server := fmt.Sprintf("%s:%d", m.Server, m.Port)
	return smtp.SendMail(server, auth, m.Email, []string{to}, msg)
}
