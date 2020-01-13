package main

import (
	"testing"

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
	return User{-1, "alle", "test", "user", "test@email.com", "oakheart"}
}

func createTestConfig() Config {
	return Config{PrivKeyPath: "../../test_data/private.pem", PubKeyPath: "../../test_data/public.pem"}
}
