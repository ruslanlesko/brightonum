package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"testing"

	"ruslanlesko/brightonum/src/dao"
	s "ruslanlesko/brightonum/src/structs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const baseURL string = "http://localhost:2525/"

var user = s.User{
	ID:        42,
	Username:  "alle",
	FirstName: "test",
	LastName:  "user",
	Email:     "test@email.com",
	Password:  "$2a$04$Mhlu1.a4QchlVgGQFc/0N.qAw9tsXqm1OMwjJRaPRCWn47bpsRa4S",
}
var updatedUser = s.User{ID: 42, Email: "updated@email.com"}
var user2 = s.User{ID: -1, Username: "sarah", FirstName: "Sarah", LastName: "Lynn", Email: "sarah@email.com", Password: "oakheart"}
var userInfo = s.UserInfo{ID: 42, Username: "alle", FirstName: "test", LastName: "user", Email: "test@email.com"}
var code = "267483"
var hashedCode = "$2a$04$c12NAkAi9nOxkYM5vO7eUur2fd9M23M4roKPbroOvNhsBVF0mOmS."

func TestMain(m *testing.M) {
	setup()
	retCode := m.Run()
	os.Exit(retCode)
}

// TokenResponse encapsulates token response
type TokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func TestFunctional_InviteUser(t *testing.T) {
	var client = &http.Client{}
	var token = issueTestToken(user.ID, user.Username, "../test_data/private.pem")
	req, err := http.NewRequest(http.MethodPost, baseURL+"v1/invite", bytes.NewReader([]byte("{\"email\":\""+user.Email+"\"}")))
	assert.Nil(t, err)
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestFunctional_GetByUsername(t *testing.T) {
	resp, err := http.Get(baseURL + "v1/userinfo/byusername/" + user.Username)
	assert.Nil(t, err)

	defer resp.Body.Close()

	var resultUserInfo s.UserInfo
	json.NewDecoder(resp.Body).Decode(&resultUserInfo)
	assert.Equal(t, userInfo, resultUserInfo)
}

func TestFunctional_GetById(t *testing.T) {
	resp, err := http.Get(baseURL + "v1/userinfo/byid/" + strconv.Itoa(user.ID))
	assert.Nil(t, err)

	defer resp.Body.Close()

	var resultUserInfo s.UserInfo
	json.NewDecoder(resp.Body).Decode(&resultUserInfo)
	assert.Equal(t, userInfo, resultUserInfo)
}

func TestFunctional_CreateUser(t *testing.T) {
	resp, err := http.Post(baseURL+"v1/users", "application/json", bytes.NewReader(s.U2JSON(&user)))
	assert.Nil(t, err)

	assert.Equal(t, 400, resp.StatusCode)

	resp, err = http.Post(baseURL+"v1/users", "application/json", bytes.NewReader(s.U2JSON(&user2)))
	assert.Nil(t, err)

	assert.Equal(t, 201, resp.StatusCode)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.JSONEq(t, "{ \"id\" : 43}", string(body))
}

func TestFunctional_Token(t *testing.T) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, baseURL+"v1/token", nil)
	assert.Nil(t, err)
	req.Header.Add("Authorization", "Basic YWxsZTpvYWtoZWFydA==")
	resp, err := client.Do(req)
	assert.Nil(t, err)

	var tokenResp TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	assert.Nil(t, err)

	assert.True(t, len(tokenResp.AccessToken) > 1)
	assert.True(t, len(tokenResp.RefreshToken) > 1)

	req, err = http.NewRequest(http.MethodPost, baseURL+"v1/token?type=refresh_token", nil)
	assert.Nil(t, err)
	req.Header.Add("Authorization", "Bearer "+tokenResp.RefreshToken)
	resp, err = client.Do(req)
	assert.Nil(t, err)

	var tokenResp2 TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp2)
	assert.Nil(t, err)
	assert.True(t, len(tokenResp2.AccessToken) > 1)
	assert.Empty(t, tokenResp2.RefreshToken)
}

func TestFunctional_Update(t *testing.T) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, baseURL+"v1/token", nil)
	assert.Nil(t, err)
	req.Header.Add("Authorization", "Basic YWxsZTpvYWtoZWFydA==")
	resp, err := client.Do(req)
	assert.Nil(t, err)

	var tokenResp TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	assert.Nil(t, err)

	assert.True(t, len(tokenResp.AccessToken) > 1)
	assert.True(t, len(tokenResp.RefreshToken) > 1)

	req, err = http.NewRequest(http.MethodPatch, baseURL+"v1/users/42", bytes.NewReader(s.U2JSON(&updatedUser)))
	assert.Nil(t, err)
	req.Header.Add("Authorization", "Bearer "+tokenResp.AccessToken)
	resp, err = client.Do(req)
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestFunctional_EmailRecoveryCode(t *testing.T) {
	client := &http.Client{}

	req, err := http.NewRequest(
		http.MethodPost,
		baseURL+"v1/password-recovery/email",
		bytes.NewReader([]byte("{\"username\":\""+user.Username+"\"}")))
	assert.Nil(t, err)

	resp, err := client.Do(req)
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestFunctional_ExchangeRecoveryCode(t *testing.T) {
	client := &http.Client{}

	req, err := http.NewRequest(
		http.MethodPost,
		baseURL+"v1/password-recovery/exchange",
		bytes.NewReader([]byte("{\"username\":\""+user.Username+"\",\"code\":\""+code+"\"}")))
	assert.Nil(t, err)

	resp, err := client.Do(req)
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestFunctional_ResetPassword(t *testing.T) {
	client := &http.Client{}

	req, err := http.NewRequest(
		http.MethodPost,
		baseURL+"v1/password-recovery/reset",
		bytes.NewReader([]byte("{\"username\":\""+user.Username+"\",\"code\":\""+code+"\",\"password\":\"kek\"}")))
	assert.Nil(t, err)

	resp, err := client.Do(req)
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func setup() {
	dao := dao.MockUserDao{}
	dao.On("GetByUsername", user.Username).Return(&user, nil)
	dao.On("GetByUsername", user2.Username).Return(nil, nil)
	dao.On("Get", user.ID).Return(&user, nil)
	dao.On("Save", mock.MatchedBy(
		func(u *s.User) bool {
			return u.Username == user2.Username && u.FirstName == user2.FirstName && u.LastName == user2.LastName
		})).Return(43)
	dao.On("Save", mock.MatchedBy(
		func(u *s.User) bool {
			return u.Email == user.Email && len(u.InviteCode) == 32
		})).Return(99)
	dao.On("Update", &updatedUser).Return(nil)
	dao.On("SetRecoveryCode", user.ID,
		mock.MatchedBy(func(hashedCode string) bool { return hashedCode != "" })).Return(nil)
	dao.On("GetRecoveryCode", user.ID).Return(hashedCode, nil)
	dao.On(
		"SetResettingCode",
		user.ID,
		mock.MatchedBy(func(hashedResettingCode string) bool { return hashedResettingCode != "" })).Return(nil)
	dao.On("GetResettingCode", user.ID).Return(hashedCode, nil)
	dao.On(
		"ResetPassword",
		user.ID,
		mock.MatchedBy(func(hashedPassword string) bool { return hashedPassword != "" })).Return(nil)

	mailer := MailerMock{}
	mailer.On("SendRecoveryCode", user.Email, mock.MatchedBy(
		func(code string) bool {
			return len(code) == 6
		})).Return(nil)
	mailer.On("SendInviteCode", user.Email, mock.MatchedBy(
		func(code string) bool {
			return len(code) == 32
		})).Return(nil)

	conf := Config{PrivKeyPath: "../test_data/private.pem", PubKeyPath: "../test_data/public.pem", AdminID: user.ID}
	service := AuthService{UserDao: &dao, Mailer: &mailer, Config: conf}

	auth := Auth{AuthService: &service}
	go auth.start()
}
