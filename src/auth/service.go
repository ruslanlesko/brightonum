package main

import (
	"io/ioutil"
	"github.com/dgrijalva/jwt-go"
	"time"
	"fmt"
)

// AuthService provides all auth operations
type AuthService struct {
	UserDao UserDao
	Config Config
}

// CreateUser creates new User
func (s *AuthService) CreateUser(u *User) {
	logger.Logf("DEBUG creating user")
	ID := s.UserDao.Save(u)
	u.ID = ID
}

// BasicAuthToken issues new token by username and password
func (s *AuthService) BasicAuthToken(username, passoword string) (string, error) {
	user := s.UserDao.GetByUsername(username)

	if user == nil || user.Password != passoword {
		return "", AuthError{"not matches"}
	}

	keyData, _ := ioutil.ReadFile(s.Config.PrivKeyPath)
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": username,
		"exp": time.Now().AddDate(1, 0, 0).UTC().Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString(key)

	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": username,
		"userId": user.ID,
		"exp": time.Now().Add(time.Hour).UTC().Unix(),
		"refresh_token": refreshTokenString,
	})

	tokenString, err := token.SignedString(key)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// RefreshToken refreshes existing token
func (s *AuthService) RefreshToken(t string) (string, error) {
	u, ok := s.validateRefreshToken(t)
	if ok {
		return s.BasicAuthToken(u.Username, u.Password)
	}
	return "", AuthError{"not validated"}
}

func (s *AuthService) validateRefreshToken(t string) (*User, bool) {
	keyData, _ := ioutil.ReadFile(s.Config.PubKeyPath)
	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		u := s.UserDao.GetByUsername(fmt.Sprintf("%s", claims["sub"]))
		return u, true
	}
	return nil, false
}

// GetUserByToken returns user by token
func (s *AuthService) GetUserByToken(t string) *User {
	keyData, _ := ioutil.ReadFile(s.Config.PubKeyPath)
	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return s.UserDao.GetByUsername(fmt.Sprintf("%s", claims["sub"]))
	}
	return nil
}