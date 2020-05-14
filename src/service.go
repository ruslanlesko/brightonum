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

	if s.usernameExists(uname) {
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
	u.ID = ID
	return nil
}

func (s *AuthService) usernameExists(username string) bool {
	u, _ := s.UserDao.GetByUsername(username)
	return u != nil
}

// BasicAuthToken issues new token by username and password
func (s *AuthService) BasicAuthToken(username, password string) (string, string, error) {
	user, _ := s.UserDao.GetByUsername(username)

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

	keyData, _ := ioutil.ReadFile(s.Config.PrivKeyPath)
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":    user.Username,
		"userId": user.ID,
		"exp":    time.Now().Add(time.Hour).UTC().Unix(),
	})

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *AuthService) issueRefreshToken(user *st.User) (string, error) {
	keyData, _ := ioutil.ReadFile(s.Config.PrivKeyPath)
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": user.Username,
		"exp": time.Now().AddDate(1, 0, 0).UTC().Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString(key)
	if err != nil {
		return "", err
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
	keyData, _ := ioutil.ReadFile(s.Config.PubKeyPath)
	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		u, _ := s.UserDao.GetByUsername(fmt.Sprintf("%s", claims["sub"]))
		return u, true
	}
	return nil, false
}

// GetUserByToken returns user by token
func (s *AuthService) GetUserByToken(t string) *st.User {
	keyData, _ := ioutil.ReadFile(s.Config.PubKeyPath)
	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		u, _ := s.UserDao.GetByUsername(fmt.Sprintf("%s", claims["sub"]))
		return u
	}
	return nil
}

// GetUserById returns user info for specific id
func (s *AuthService) GetUserById(id int) *st.UserInfo {
	u, _ := s.UserDao.Get(id)
	if u == nil {
		return nil
	}
	return &st.UserInfo{u.ID, u.Username, u.FirstName, u.LastName}
}

// GetUserById returns user info for username
func (s *AuthService) GetUserByUsername(username string) *st.UserInfo {
	u, _ := s.UserDao.GetByUsername(username)
	if u == nil {
		return nil
	}
	return &st.UserInfo{u.ID, u.Username, u.FirstName, u.LastName}
}
