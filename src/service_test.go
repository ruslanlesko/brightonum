package main

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"ruslanlesko/brightonum/src/dao"
	"ruslanlesko/brightonum/src/email"
	st "ruslanlesko/brightonum/src/structs"
)

var mailer = email.MailerMock{}

func TestAuthService_InviteUser(t *testing.T) {
	var token = issueTestToken(user.ID, user.Username, createTestConfig().PrivKeyPath)
	var email = "bojack@horseman.com"
	var codeMatcher = func(code string) bool {
		return len(code) == 32
	}
	var userMatcher = func(u *st.User) bool {
		return u.Email == email && len(u.InviteCode) == 32
	}

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", user.Username).Return(&user, nil)
	dao.On("Save", mock.MatchedBy(userMatcher)).Return(42)
	mailer.On("SendInviteCode", email, mock.MatchedBy(codeMatcher)).Return(nil)
	s := AuthService{&mailer, &dao, createTestConfig()}

	err := s.InviteUser(email, token)
	assert.Nil(t, err)
	dao.AssertExpectations(t)
	mailer.AssertExpectations(t)
}

func TestAuthService_InviteUser_Forbidden(t *testing.T) {
	var token = issueTestToken(user.ID, user.Username, createTestConfig().PrivKeyPath)
	var email = "bojack@horseman.com"

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", user.Username).Return(&st.User{ID: user.ID + 1}, nil)
	s := AuthService{&mailer, &dao, createTestConfig()}

	err := s.InviteUser(email, token)
	assert.Equal(t, st.AuthError{Msg: "Available only for admin", Status: 403}, err)
	dao.AssertExpectations(t)
}

func TestAuthService_CreateUser(t *testing.T) {
	var u = st.User{ID: -1, Username: "uname", FirstName: "test", LastName: "user", Email: "test@email.com", Password: "pwd"}

	dao := dao.MockUserDao{}
	dao.On("Save", &u).Return(1)
	dao.On("GetByUsername", u.Username).Return(nil, nil)

	s := AuthService{&mailer, &dao, createTestConfig()}
	err := s.CreateUser(&u)

	assert.Nil(t, err)
	dao.AssertExpectations(t)
}

func TestAuthService_CreateUser_DuplicateHandling(t *testing.T) {
	u := st.User{ID: -1, Username: "alle", FirstName: "Alle", LastName: "Alle", Email: "alle@alle.com", Password: "pwd"}

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", u.Username).Return(&u, nil)

	s := AuthService{&mailer, &dao, createTestConfig()}
	err := s.CreateUser(&u)
	assert.Equal(t, st.AuthError{Msg: "Username already exists", Status: 400}, err)
}

func TestAuthService_BasicAuthToken(t *testing.T) {
	user := createTestUser()
	username := user.Username
	password := "oakheart"

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", username).Return(&user, nil)

	s := AuthService{&mailer, &dao, createTestConfig()}
	accessToken, refreshToken, err := s.BasicAuthToken(username, password)
	assert.Nil(t, err)
	assert.NotEmpty(t, accessToken)
	assert.True(t, testJWTIntField(accessToken, "userId", 42))
	assert.True(t, testJWTStringField(accessToken, "sub", "alle"))
	assert.NotEmpty(t, refreshToken)
	assert.True(t, testJWTStringField(refreshToken, "sub", "alle"))

	expRaw := exctractField(accessToken, "exp", -1)
	exp := int64(expRaw.(float64))
	estimatedEx := time.Now().Add(time.Hour).UTC().Unix()
	assert.True(t, exp >= estimatedEx-1 && exp <= estimatedEx+1)

	expRaw = exctractField(refreshToken, "exp", -1)
	exp = int64(expRaw.(float64))
	estimatedEx = time.Now().AddDate(1, 0, 0).UTC().Unix()
	assert.True(t, exp >= estimatedEx-1 && exp <= estimatedEx+1)

	accessToken, refreshToken, err = s.BasicAuthToken(username, password+"xyz")
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)
	assert.Equal(t, st.AuthError{Msg: "Username or password is wrong", Status: 403}, err)
}

func TestAuthService_RefreshToken(t *testing.T) {
	user := createTestUser()
	username := user.Username
	password := "oakheart"

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", username).Return(&user, nil)

	s := AuthService{&mailer, &dao, createTestConfig()}
	accessToken, refreshToken, err := s.BasicAuthToken(username, password)
	assert.Nil(t, err)
	assert.NotEmpty(t, accessToken)

	refreshedToken, err := s.RefreshToken(refreshToken)
	assert.Nil(t, err)
	assert.NotEmpty(t, refreshedToken)

	refreshedToken, err = s.RefreshToken(refreshedToken + "xyz")
	assert.Empty(t, refreshedToken)
	assert.Equal(t, st.AuthError{Msg: "Refresh token is not valid", Status: 403}, err)
}

func TestAuthService_GetUserByToken(t *testing.T) {
	user := createTestUser()
	username := user.Username
	password := "oakheart"

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", username).Return(&user, nil)

	s := AuthService{&mailer, &dao, createTestConfig()}
	token, _, err := s.BasicAuthToken(username, password)
	assert.Nil(t, err)

	u, err := s.GetUserByToken(token)
	assert.Nil(t, err)
	assert.Equal(t, user, *u)

	u, err = s.GetUserByToken(token + "xyz")
	assert.NotNil(t, err)
	assert.Nil(t, u)
}

func TestAuthService_GetUsers(t *testing.T) {
	user1 := createTestUser()
	user2 := createAnotherTestUser()
	token := issueTestToken(user1.ID, user1.Username, createTestConfig().PrivKeyPath)

	dao := dao.MockUserDao{}
	dao.On("GetAll").Return(&[]st.User{user1, user2}, nil)
	dao.On("GetByUsername", user1.Username).Return(&user1, nil)

	s := AuthService{&mailer, &dao, createTestConfig()}

	userInfo := createTestUserInfo()
	userInfo2 := createAdditionalTestUserInfo()
	expected := &[]st.UserInfo{userInfo, userInfo2}
	us, err := s.GetUsers(token)
	assert.Nil(t, err)
	assert.Equal(t, expected, us)
}

func TestAuthService_UpdateUser(t *testing.T) {
	user := createTestUserUpdatePayload()
	token := issueTestToken(user.ID, user.Username, createTestConfig().PrivKeyPath)

	dao := dao.MockUserDao{}
	dao.On("Get", user.ID).Return(&user, nil)
	dao.On("GetByUsername", user.Username).Return(&user, nil)
	dao.On("Update", &user).Return(nil)

	s := AuthService{&mailer, &dao, createTestConfig()}

	err := s.UpdateUser(&user, token)
	assert.Nil(t, err)
}

func TestAuthService_UpdateUserInvalidToken(t *testing.T) {
	user := createTestUserUpdatePayload()
	token := "invalid token"

	dao := dao.MockUserDao{}
	s := AuthService{&mailer, &dao, createTestConfig()}

	err := s.UpdateUser(&user, token)
	assert.Equal(t, st.AuthError{Msg: "Invalid token", Status: 401}, err)
}

func TestAuthService_DeleteUser(t *testing.T) {
	user := createTestUser()
	token := issueTestToken(user.ID, user.Username, createTestConfig().PrivKeyPath)

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", user.Username).Return(&user, nil)
	dao.On("DeleteById", user.ID).Return(nil)

	s := AuthService{&mailer, &dao, createTestConfig()}

	err := s.DeleteUser(user.ID, token)
	assert.Nil(t, err)
}

func TestAuthService_SendRecoveryEmail(t *testing.T) {
	user := createTestUser()

	codeMatcher := func(code string) bool {
		return len(code) == 6
	}

	dao := dao.MockUserDao{}

	mailer.On(
		"SendRecoveryCode",
		user.Email,
		mock.MatchedBy(codeMatcher)).Return(nil)

	dao.On(
		"SetRecoveryCode",
		user.ID,
		mock.MatchedBy(func(hashedCode string) bool { return hashedCode != "" })).Return(nil)

	dao.On("GetByUsername", user.Username).Return(&user, nil)

	s := AuthService{&mailer, &dao, createTestConfig()}

	err := s.SendRecoveryEmail(user.Username)
	assert.Nil(t, err)
}

func TestAuthService_ExchangeRecoveryCode(t *testing.T) {
	user := createTestUser()
	code := "267483"
	hashedCode := "$2a$04$c12NAkAi9nOxkYM5vO7eUur2fd9M23M4roKPbroOvNhsBVF0mOmS."

	dao := dao.MockUserDao{}

	dao.On("GetByUsername", user.Username).Return(&user, nil)
	dao.On("GetRecoveryCode", user.ID).Return(hashedCode, nil)
	dao.On(
		"SetResettingCode",
		user.ID,
		mock.MatchedBy(func(hashedResettingCode string) bool { return hashedResettingCode != "" })).Return(nil)

	s := AuthService{&mailer, &dao, createTestConfig()}

	resettingCode, err := s.ExchangeRecoveryCode(user.Username, code)
	assert.Nil(t, err)
	assert.True(t, len(resettingCode) == 10)
}

func TestAuthService_ResetPassword(t *testing.T) {
	user := createTestUser()
	code := "267483"
	hashedCode := "$2a$04$c12NAkAi9nOxkYM5vO7eUur2fd9M23M4roKPbroOvNhsBVF0mOmS."

	dao := dao.MockUserDao{}

	dao.On("GetByUsername", user.Username).Return(&user, nil)
	dao.On("GetResettingCode", user.ID).Return(hashedCode, nil)
	dao.On(
		"ResetPassword",
		user.ID,
		mock.MatchedBy(func(hashedPassword string) bool { return hashedPassword != "" })).Return(nil)

	s := AuthService{&mailer, &dao, createTestConfig()}

	err := s.ResetPassword(user.Username, code, "kek")
	assert.Nil(t, err)
}

func createTestUser() st.User {
	return st.User{ID: 42, Username: "alle", FirstName: "test", LastName: "user", Email: "test@email.com", Password: "$2a$04$Mhlu1.a4QchlVgGQFc/0N.qAw9tsXqm1OMwjJRaPRCWn47bpsRa4S"}
}

func createTestUserUpdatePayload() st.User {
	return st.User{ID: 42, Email: "changed@email.com"}
}

func createTestUserInfo() st.UserInfo {
	return st.UserInfo{ID: 42, Username: "alle", FirstName: "test", LastName: "user", Email: "test@email.com"}
}

func createAnotherTestUser() st.User {
	return st.User{ID: 43, Username: "alle2", FirstName: "test", LastName: "user", Email: "test@email.com", Password: "$2a$04$Mhlu1.a4QchlVgGQFc/0N.qAw9tsXqm1OMwjJRaPRCWn47bpsRa4S"}
}

func createAdditionalTestUserInfo() st.UserInfo {
	return st.UserInfo{ID: 43, Username: "alle2", FirstName: "test", LastName: "user", Email: "test@email.com"}
}

func createTestConfig() Config {
	return Config{PrivKeyPath: "../test_data/private.pem", PubKeyPath: "../test_data/public.pem", AdminID: user.ID}
}

func testJWTIntField(tokenStr string, fieldName string, fieldValue int) bool {
	value := exctractField(tokenStr, fieldName, -1)

	actualValue, ok := value.(float64)
	if ok {
		return int(actualValue) == fieldValue
	}

	return false
}

func testJWTStringField(tokenStr string, fieldName string, fieldValue string) bool {
	value := exctractField(tokenStr, fieldName, "")

	actualValue, ok := value.(string)
	if !ok {
		return false
	}

	return actualValue == fieldValue
}

func exctractField(tokenStr string, fieldName string, defaultValue interface{}) interface{} {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return defaultValue
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return defaultValue
	}

	actualValue, ok := claims[fieldName]
	if !ok {
		return defaultValue
	}

	return actualValue
}

func issueTestToken(userID int, username string, privKeyPath string) string {
	keyData, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return ""
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ""
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":    username,
		"userId": userID,
		"exp":    time.Now().Add(time.Hour).UTC().Unix(),
	})

	tokenString, err := token.SignedString(key)
	if err != nil {
		return ""
	}

	return tokenString
}
