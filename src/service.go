package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"ruslanlesko/brightonum/src/crypto"
	"ruslanlesko/brightonum/src/dao"
	st "ruslanlesko/brightonum/src/structs"
	"strconv"

	"time"

	"github.com/dgrijalva/jwt-go"
)

// AuthService provides all auth operations
type AuthService struct {
	Mailer  Mailer
	UserDao dao.UserDao
	Config  Config
}

// InviteUser sends invite code for given email
func (s *AuthService) InviteUser(email string, token string) error {
	if !s.validateAdminToken(token) {
		return st.AuthError{Msg: "Available only for admin", Status: 403}
	}

	var code = generateCode(32)
	var user = st.User{Email: email, InviteCode: code}

	id := s.UserDao.Save(&user)
	if id < 0 {
		return st.AuthError{Msg: "Cannot save user invite", Status: 500}
	}

	err := s.Mailer.SendInviteCode(email, code)
	if err != nil {
		logger.Logf("ERROR Email was not sent: " + err.Error())
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	return err
}

func (s *AuthService) validateAdminToken(token string) bool {
	u, valid := s.validateToken(token)
	return valid && u.ID == s.Config.AdminID
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

	if s.Config.Private {
		dbUser, err := s.UserDao.GetByEmail(u.Email)
		if err != nil {
			logger.Logf("ERROR Failed to fetch user, %s", err.Error())
			return st.AuthError{Msg: err.Error(), Status: 500}
		}
		if dbUser == nil || u.InviteCode == "" || dbUser.InviteCode != u.InviteCode {
			return st.AuthError{Msg: "Wrong email or invite code", Status: 401}
		}
	}

	hashedPassword, err := crypto.Hash(u.Password)
	if err != nil {
		logger.Logf("ERROR Failed to hash password, %s", err.Error())
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	u.Password = hashedPassword
	u.InviteCode = ""
	ID := s.UserDao.Save(u)
	if ID < 0 {
		return st.AuthError{Msg: "Cannot save user", Status: 500}
	}
	u.ID = ID
	return nil
}

// UpdateUser updates existing user
func (s *AuthService) UpdateUser(u *st.User, token string) error {
	logger.Logf("DEBUG Updating user with id %d", u.ID)

	tokenUser, valid := s.validateToken(token)
	if !valid || tokenUser.ID != u.ID {
		return st.AuthError{Msg: "Invalid token", Status: 401}
	}

	if !validateUpdatePayload(u) {
		return st.AuthError{Msg: "Invalid Update payload", Status: 400}
	}

	userExists, err := s.userExists(u.ID)
	if err != nil {
		return st.AuthError{Msg: err.Error(), Status: 500}
	}
	if !userExists {
		return st.AuthError{Msg: "User does not exist", Status: 404}
	}

	err = s.UserDao.Update(u)
	if err != nil {
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	return nil
}

// DeleteUser delets user
func (s *AuthService) DeleteUser(id int, token string) error {
	tokenUser, valid := s.validateToken(token)
	if !valid || tokenUser.ID != id && tokenUser.ID != s.Config.AdminID {
		return st.AuthError{Msg: "Invalid token", Status: 401}
	}

	err := s.UserDao.DeleteById(id)
	if err != nil {
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	return nil
}

func (s *AuthService) usernameExists(username string) (bool, error) {
	u, err := s.UserDao.GetByUsername(username)
	return u != nil, err
}

func validateUpdatePayload(u *st.User) bool {
	return u.ID > 0 && u.Username == "" && u.Password == ""
}

func (s *AuthService) userExists(id int) (bool, error) {
	u, err := s.UserDao.Get(id)
	if err != nil {
		return false, err
	}
	return u != nil, nil
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
	u, ok := s.validateToken(t)
	if ok {
		accessToken, err := s.issueAccessToken(u)
		return accessToken, err
	}
	return "", st.AuthError{Msg: "Refresh token is not valid", Status: 403}
}

func (s *AuthService) validateToken(t string) (*st.User, bool) {
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
	return &st.UserInfo{ID: u.ID, Username: u.Username, FirstName: u.FirstName, LastName: u.LastName, Email: u.Email}, nil
}

// GetUserByUsername returns user info for username
func (s *AuthService) GetUserByUsername(username string) (*st.UserInfo, error) {
	u, err := s.UserDao.GetByUsername(username)
	if err != nil {
		return nil, st.AuthError{Msg: err.Error(), Status: 500}
	}
	if u == nil {
		return nil, nil
	}
	return mapToUserInfo(u), nil
}

// GetUsers returns all users info
func (s *AuthService) GetUsers() (*[]st.UserInfo, error) {
	us, err := s.UserDao.GetAll()
	if err != nil {
		return nil, st.AuthError{Msg: err.Error(), Status: 500}
	}
	return mapToUserInfoList(us), nil
}

// SendRecoveryEmail sends password recovery email for user or error is user does not exist or email sending fails
func (s *AuthService) SendRecoveryEmail(username string) error {
	u, err := s.UserDao.GetByUsername(username)
	if err != nil {
		return st.AuthError{Msg: err.Error(), Status: 500}
	}
	if u == nil || u.Email == "" {
		return st.AuthError{Msg: "Username does not registered or email is absent", Status: 404}
	}

	code := generateCode(6)
	err = s.Mailer.SendRecoveryCode(u.Email, code)
	if err != nil {
		logger.Logf("ERROR Email was not sent: " + err.Error())
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	hashedCode, err := crypto.Hash(code)
	if err != nil {
		logger.Logf("ERROR Failed to hash code, %s", err.Error())
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	return s.UserDao.SetRecoveryCode(u.ID, hashedCode)
}

// ExchangeRecoveryCode exchanges recovery code for a password resetting one
func (s *AuthService) ExchangeRecoveryCode(username string, code string) (string, error) {
	generalErrorMsg := "Username does not registered or recovery process has not been initiated"

	u, err := s.UserDao.GetByUsername(username)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}
	if u == nil {
		return "", st.AuthError{Msg: generalErrorMsg, Status: 404}
	}

	existingCodeHash, err := s.UserDao.GetRecoveryCode(u.ID)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}

	if existingCodeHash == "" {
		return "", st.AuthError{Msg: generalErrorMsg, Status: 404}
	}

	if !crypto.Match(code, existingCodeHash) {
		return "", st.AuthError{Msg: "Provided recovery code does not match", Status: 403}
	}

	resetingCode := generateCode(10)
	resetingCodeHash, err := crypto.Hash(resetingCode)
	if err != nil {
		logger.Logf("ERROR Failed to hash code, %s", err.Error())
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}

	err = s.UserDao.SetResettingCode(u.ID, resetingCodeHash)
	if err != nil {
		return "", st.AuthError{Msg: err.Error(), Status: 500}
	}

	return resetingCode, nil
}

// ResetPassword resets password given username and code
func (s *AuthService) ResetPassword(username string, code string, newPassword string) error {
	generalErrorMsg := "Username does not registered or recovery process has not been initiated"

	u, err := s.UserDao.GetByUsername(username)
	if err != nil {
		return st.AuthError{Msg: err.Error(), Status: 500}
	}
	if u == nil {
		return st.AuthError{Msg: generalErrorMsg, Status: 404}
	}

	existingCodeHash, err := s.UserDao.GetResettingCode(u.ID)
	if err != nil {
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	if !crypto.Match(code, existingCodeHash) {
		return st.AuthError{Msg: "Provided recovery code does not match", Status: 403}
	}

	hashedPassword, err := crypto.Hash(newPassword)
	if err != nil {
		logger.Logf("ERROR Failed to hash password, %s", err.Error())
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	err = s.UserDao.ResetPassword(u.ID, hashedPassword)
	if err != nil {
		return st.AuthError{Msg: err.Error(), Status: 500}
	}

	return nil
}

func generateCode(size int) string {
	rand.Seed(time.Now().UnixNano())
	result := ""

	for i := 0; i < size; i++ {
		d := rand.Intn(10)
		result += strconv.Itoa(d)
	}

	return result
}

func mapToUserInfoList(us *[]st.User) *[]st.UserInfo {
	result := []st.UserInfo{}
	for _, u := range *us {
		result = append(result, *mapToUserInfo(&u))
	}
	return &result
}

func mapToUserInfo(u *st.User) *st.UserInfo {
	return &st.UserInfo{ID: u.ID, Username: u.Username, FirstName: u.FirstName, LastName: u.LastName, Email: u.Email}
}
