package email

import (
	"crypto/tls"
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
	msg := "To: " + to + "\r\n" +
		"From: " + m.SiteName + "<" + m.Email + ">\r\n" +
		"Subject: " + m.SiteName + " recovery code\r\n" +
		"\r\n" +
		"Your password recovery code: " +
		code +
		"\r\n"
	return m.send(to, msg)
}

// SendInviteCode sends invite code
func (m *EmailMailer) SendInviteCode(to string, code string) error {
	msg := "To: " + to + "\r\n" +
		"From: " + m.SiteName + "<" + m.Email + ">\r\n" +
		"Subject: " + m.SiteName + " invite code\r\n" +
		"\r\n" +
		"Your invite code: " +
		code +
		"\r\n"
	return m.send(to, msg)
}

// SendVerificationCode sends verification code
func (m *EmailMailer) SendVerificationCode(to string, code string) error {
	msg := "To: " + to + "\r\n" +
		"From: " + m.SiteName + "<" + m.Email + ">\r\n" +
		"Subject: " + m.SiteName + " Verification Code\r\n" +
		"\r\n" +
		"Your verification code: " +
		code +
		"\r\n"
	return m.send(to, msg)
}

func (m *EmailMailer) send(to string, msg string) error {
	// Connect to the SMTP server with TLS support.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         m.Server,
	}

	conn, err := smtp.Dial(fmt.Sprintf("%s:%d", m.Server, m.Port))
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = conn.StartTLS(tlsConfig)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	auth := smtp.PlainAuth("", m.Email, m.Password, m.Server)

	// Authenticate to the SMTP server.
	err = conn.Auth(auth)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Set the sender and recipient.
	err = conn.Mail(m.Email)
	if err != nil {
		return err
	}

	err = conn.Rcpt(to)
	if err != nil {
		return err
	}

	// Send the email body.
	wc, err := conn.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	_, err = fmt.Fprintf(wc, msg)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Quit the connection.
	conn.Quit()
	return nil
}
