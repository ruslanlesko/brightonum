package main

import (
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockUserDao struct {
	mock.Mock
}

func (m *MockUserDao) Save(u *User) int {
	return m.Called(u).Int(0)
}

func (m *MockUserDao) GetByUsername(uname string) *User {
	return m.Called(uname).Get(0).(*User)
}

func TestAuthService_CreateUser(t *testing.T) {
	var u = User{-1, "uname", "test", "user", "test@email.com", "pwd"}

	dao := MockUserDao{}
	dao.On("Save", &u).Return(1)

	s := AuthService{&dao, createTestConfig()}
	s.CreateUser(&u)

	dao.AssertExpectations(t)
}

func TestAuthService_BasicAuthToken(t *testing.T) {
	user := createTestUser()
	username := user.Username
	password := user.Password

	dao := MockUserDao{}
	dao.On("GetByUsername", username).Return(&user)

	s := AuthService{&dao, createTestConfig()}
	token, err := s.BasicAuthToken(username, password)
	assert.Nil(t, err)
	assert.NotEmpty(t, token)
	assert.True(t, testJWTIntField(token, "userId", 42))
	assert.True(t, testJWTStringField(token, "sub", "alle"))

	token, err = s.BasicAuthToken(username, password+"xyz")
	assert.Empty(t, token)
	assert.Equal(t, AuthError{"not matches"}, err)
}

func TestAuthService_RefreshToken(t *testing.T) {
	user := createTestUser()
	username := user.Username
	password := user.Password

	dao := MockUserDao{}
	dao.On("GetByUsername", username).Return(&user)

	s := AuthService{&dao, createTestConfig()}
	token, err := s.BasicAuthToken(username, password)
	assert.Nil(t, err)
	assert.NotEmpty(t, token)

	refreshedToken, err := s.RefreshToken(token)
	assert.Nil(t, err)
	assert.NotEmpty(t, refreshedToken)

	refreshedToken, err = s.RefreshToken(refreshedToken + "xyz")
	assert.Empty(t, refreshedToken)
	assert.Equal(t, AuthError{"not validated"}, err)
}

func TestAuthService_GetUserByToken(t *testing.T) {
	user := createTestUser()
	username := user.Username
	password := user.Password

	dao := MockUserDao{}
	dao.On("GetByUsername", username).Return(&user)

	s := AuthService{&dao, createTestConfig()}
	token, err := s.BasicAuthToken(username, password)
	assert.Nil(t, err)

	u := s.GetUserByToken(token)
	assert.Equal(t, user, *u)

	u = s.GetUserByToken(token + "xyz")
	assert.Nil(t, u)
}

func createTestUser() User {
	return User{42, "alle", "test", "user", "test@email.com", "oakheart"}
}

func createTestConfig() Config {
	return Config{PrivKeyPath: "../../test_data/private.pem", PubKeyPath: "../../test_data/public.pem"}
}

func testJWTIntField(tokenStr string, fieldName string, fieldValue int) bool {
	value := exctractField(tokenStr, fieldName)
	if value == nil {
		return false
	}

	actualValue, ok := value.(float64)
	if ok {
		return int(actualValue) == fieldValue
	}

	return false
}

func testJWTStringField(tokenStr string, fieldName string, fieldValue string) bool {
	value := exctractField(tokenStr, fieldName)
	if value == nil {
		return false
	}

	actualValue, ok := value.(string)
	if !ok {
		return false
	}

	return actualValue == fieldValue
}

func exctractField(tokenStr string, fieldName string) interface{} {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}

	actualValue, ok := claims[fieldName]
	if !ok {
		return nil
	}

	return actualValue
}