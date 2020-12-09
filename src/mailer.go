package main

import (
	"net/smtp"
)

// Mailer sends emails
type Mailer interface {
	SendRecoveryCode(string, string) error
}

// EmailMailer sends emails
type EmailMailer struct {
	Email    string
	Password string
}

// SendRecoveryCode sends password recovery code
func (m *EmailMailer) SendRecoveryCode(to string, code string) error {
	auth := smtp.PlainAuth("", m.Email, m.Password, "smtp.gmail.com")

	// Here we do it all: connect to our server, set up a message and send it
	msg := []byte("To: " + to + "\r\n" +
		"Subject: AirPicHub password recovery code\r\n" +
		"\r\n" +
		"Your password recovery code: " +
		code +
		"\r\n")
	return smtp.SendMail("smtp.gmail.com:587", auth, m.Email, []string{to}, msg)
}
