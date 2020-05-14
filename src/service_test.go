package main

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"

	"ruslanlesko/brightonum/src/dao"
	st "ruslanlesko/brightonum/src/structs"
)

func TestAuthService_CreateUser(t *testing.T) {
	var u = st.User{-1, "uname", "test", "user", "test@email.com", "pwd"}

	dao := dao.MockUserDao{}
	dao.On("Save", &u).Return(1)
	dao.On("GetByUsername", u.Username).Return(nil, nil)

	s := AuthService{&dao, createTestConfig()}
	err := s.CreateUser(&u)

	assert.Nil(t, err)
	dao.AssertExpectations(t)
}

func TestAuthService_CreateUser_DuplicateHandling(t *testing.T) {
	u := st.User{-1, "alle", "Alle", "Alle", "alle@alle.com", "pwd"}

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", u.Username).Return(&u, nil)

	s := AuthService{&dao, createTestConfig()}
	err := s.CreateUser(&u)
	assert.Equal(t, st.AuthError{Msg: "Username already exists", Status: 400}, err)
}

func TestAuthService_BasicAuthToken(t *testing.T) {
	user := createTestUser()
	username := user.Username
	password := "oakheart"

	dao := dao.MockUserDao{}
	dao.On("GetByUsername", username).Return(&user, nil)

	s := AuthService{&dao, createTestConfig()}
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

	s := AuthService{&dao, createTestConfig()}
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

	s := AuthService{&dao, createTestConfig()}
	token, _, err := s.BasicAuthToken(username, password)
	assert.Nil(t, err)

	u := s.GetUserByToken(token)
	assert.Equal(t, user, *u)

	u = s.GetUserByToken(token + "xyz")
	assert.Nil(t, u)
}

func createTestUser() st.User {
	return st.User{42, "alle", "test", "user", "test@email.com", "$2a$04$Mhlu1.a4QchlVgGQFc/0N.qAw9tsXqm1OMwjJRaPRCWn47bpsRa4S"}
}

func createTestConfig() Config {
	return Config{PrivKeyPath: "../test_data/private.pem", PubKeyPath: "../test_data/public.pem"}
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
