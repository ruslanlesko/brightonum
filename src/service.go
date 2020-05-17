package main

import (
	"fmt"
	"io/ioutil"
	"ruslanlesko/brightonum/src/crypto"
	"ruslanlesko/brightonum/src/dao"
	st "ruslanlesko/brightonum/src/structs"

	"time"

	"github.com/dgrijalva/jwt-go"
)

// AuthService provides all auth operations
type AuthService struct {
	UserDao dao.UserDao
	Config  Config
}

// CreateUser creates new User
func (s *AuthService) CreateUser(u *st.User) error {
	logger.Logf("DEBUG creating user")

	uname := u.Username

	alreadyExists, err := s.usernameExists(uname)
	if err != nil {
		return st.AuthError{Msg: err.Error(), Status: 500}
	}
	if alreadyExists {
		logger.Logf("WARN Username %s already exists", uname)
		return st.AuthError{Msg: "Username already exists", Status: 400}
	}

	hashedPassword, err := crypto.Hash(u.Password)
	if err != nil {
		logger.Logf("ERROR Failed to hash password, %s", err.Error())
		return err
	}

	u.Password = hashedPassword
	ID := s.UserDao.Save(u)
	if ID < 0 {
		return st.AuthError{Msg: "Cannot save user", Status: 500}
	}
	u.ID = ID
	return nil
}

func (s *AuthService) usernameExists(username string) (bool, error) {
	u, err := s.UserDao.GetByUsername(username)
	return u != nil, err
}

// BasicAuthToken issues new token by username and password
func (s *AuthService) BasicAuthToken(username, password string) (string, string, error) {
	user, err := s.UserDao.GetByUsername(username)

	if err != nil {
		return "", "", st.AuthError{Msg: "Cannot extract user", Status: 500}
	}

	if user == nil || !crypto.Match(password, user.Password) {
		return "", "", st.AuthError{Msg: "Username or password is wrong", Status: 403}
	}

	tokenString, err := s.issueAccessToken(user)
	if err != nil {
		return "", "", err
	}

	refreshTokenString, err := s.issueRefreshToken(user)
	if err != nil {
		return "", "", err
	}

	return tokenString, refreshTokenString, nil
}

func (s *AuthService) issueAccessToken(user *st.User) (string, error) {
	if user == nil {
		return "", st.AuthError{Msg: "User is missing", Status: 403}
	}

	keyData, err := ioutil.ReadFile(s.Config.PrivKeyPath)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":    user.Username,
		"userId": user.ID,
		"exp":    time.Now().Add(time.Hour).UTC().Unix(),
	})

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}

	return tokenString, nil
}

func (s *AuthService) issueRefreshToken(user *st.User) (string, error) {
	keyData, err := ioutil.ReadFile(s.Config.PrivKeyPath)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": user.Username,
		"exp": time.Now().AddDate(1, 0, 0).UTC().Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString(key)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}

	return refreshTokenString, nil
}

// RefreshToken refreshes existing token
func (s *AuthService) RefreshToken(t string) (string, error) {
	u, ok := s.validateRefreshToken(t)
	if ok {
		accessToken, err := s.issueAccessToken(u)
		return accessToken, err
	}
	return "", st.AuthError{Msg: "Refresh token is not valid", Status: 403}
}

func (s *AuthService) validateRefreshToken(t string) (*st.User, bool) {
	keyData, err := ioutil.ReadFile(s.Config.PubKeyPath)
	if err != nil {
		return nil, false
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		logger.Logf("WARN %s", err.Error())
		return nil, false
	}

	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		logger.Logf("WARN %s", err.Error())
		return nil, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		u, err := s.UserDao.GetByUsername(fmt.Sprintf("%s", claims["sub"]))
		if err != nil {
			return nil, false
		}
		return u, true
	}
	return nil, false
}

// GetUserByToken returns user by token
func (s *AuthService) GetUserByToken(t string) (*st.User, error) {
	keyData, err := ioutil.ReadFile(s.Config.PubKeyPath)
	if err != nil {
		return nil, st.AuthError{Msg: err.Error(), Status: 500}
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, st.AuthError{Msg: err.Error(), Status: 500}
	}

	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, st.AuthError{Msg: err.Error(), Status: 400}
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		u, err := s.UserDao.GetByUsername(fmt.Sprintf("%s", claims["sub"]))
		if err != nil {
			return nil, st.AuthError{Msg: err.Error(), Status: 500}
		}
		return u, nil
	}
	return nil, nil
}

// GetUserById returns user info for specific id
func (s *AuthService) GetUserById(id int) (*st.UserInfo, error) {
	u, err := s.UserDao.Get(id)
	if err != nil {
		return nil, st.AuthError{Msg: err.Error(), Status: 500}
	}
	if u == nil {
		return nil, nil
	}
	return &st.UserInfo{ID: u.ID, Username: u.Username, FirstName: u.FirstName, LastName: u.LastName}, nil
}

// GetUserById returns user info for username
func (s *AuthService) GetUserByUsername(username string) (*st.UserInfo, error) {
	u, err := s.UserDao.GetByUsername(username)
	if err != nil {
		return nil, st.AuthError{Msg: err.Error(), Status: 500}
	}
	if u == nil {
		return nil, nil
	}
	return &st.UserInfo{ID: u.ID, Username: u.Username, FirstName: u.FirstName, LastName: u.LastName}, nil
}
