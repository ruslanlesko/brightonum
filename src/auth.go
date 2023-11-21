package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ruslanlesko/brightonum/src/dao"
	"ruslanlesko/brightonum/src/email"
	s "ruslanlesko/brightonum/src/structs"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-pkgz/lgr"
	"github.com/jessevdk/go-flags"
)

var loggerFormat = lgr.Format(`{{.Level}} {{.DT.Format "2006-01-02 15:04:05.000"}} {{.Message}}`)
var logger = lgr.New(loggerFormat)

// Auth provides main function and routing
type Auth struct {
	AuthService *AuthService
}

// Config provides configuration variables
type Config struct {
	// Path to a private key
	PrivKeyPath string `long:"privkey" required:"true" description:"Path to a private key"`

	// Path to a public key
	PubKeyPath string `long:"pubkey" required:"true" description:"Path to a public key"`

	// MongoDB URL
	MongoDBURL string `long:"mongoURL" required:"true" description:"URL for MongoDB"`

	// Database name
	DatabaseName string `long:"databaseName" required:"true" description:"Database name"`

	// Email for password recovery (Gmail)
	Email string `long:"email" required:"true" description:"Email for password recovery (Gmail)"`

	// Password from email for password recovery
	EmailPassword string `long:"emailPassword" required:"true" description:"Password from email for password recovery"`

	// Enable debug logging
	Debug bool `long:"debug" required:"false" description:"Enable debug logging"`

	// Admin ID
	AdminIDs []int `long:"adminID" required:"true" description:"Admin ID"`

	// Enable private mode
	Private bool `long:"private" required:"false" description:"Private Mode"`

	// Enable email verification
	EmailVerification bool `long:"emailVerification" required:"false" description:"Enable email verification"`

	// Email Server
	EmailServer string `long:"emailServer" required:"true" description:"Email Server (such as smtp.office365.com)"`

	// Email Port
	EmailPort int `long:"emailPort" required:"true" description:"Email Port (such as 587)"`

	// Site Name
	SiteName string `long:"siteName" required:"false" description:"Site Name used in email subjects"`
}

// RecoveryEmailPayload represents payload of password recovery email request
type RecoveryEmailPayload struct {
	Username string `json:"username"`
}

// ExchangeCodeRequestPayload represents request payload for password recovery exchange code request
type ExchangeCodeRequestPayload struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

// PasswordResetPayload represents request payload for password reset request
type PasswordResetPayload struct {
	Username string `json:"username"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

// VerificationCodePayload represents payload for user email verification
type VerificationCodePayload struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

func (a *Auth) inviteUser(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)

	authHeader := r.Header.Get("Authorization")
	headerItems := strings.Split(authHeader, " ")

	if len(headerItems) < 2 {
		writeError(w, s.AuthError{Msg: "Authorization header is missing or invalid", Status: 401})
		return
	}

	token := headerItems[1]

	var payload struct {
		Email string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		logger.Logf("ERROR Cannot decode JSON payload")
		writeError(w, s.AuthError{Msg: err.Error(), Status: 400})
		return
	}

	err = a.AuthService.InviteUser(payload.Email, token)
	if err != nil {
		authErr, isAuthErr := err.(s.AuthError)
		if isAuthErr {
			writeError(w, authErr)
		} else {
			writeError(w, s.AuthError{Msg: err.Error(), Status: 500})
		}
		return
	}

	w.WriteHeader(200)
}

func (a *Auth) createUser(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	if r.Body == nil {
		logger.Logf("ERROR Data is missing")
		writeError(w, s.AuthError{Msg: "Request body is missing", Status: 400})
		return
	}

	var newUser s.User

	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		logger.Logf("ERROR Cannot decode JSON payload")
		writeError(w, s.AuthError{Msg: err.Error(), Status: 400})
		return
	}
	err = a.AuthService.CreateUser(&newUser)
	if err != nil {
		authErr, isAuthErr := err.(s.AuthError)
		if isAuthErr {
			writeError(w, authErr)
		} else {
			writeError(w, s.AuthError{Msg: err.Error(), Status: 500})
		}
		return
	}

	w.WriteHeader(201)
	w.Write(s.ID2JSON(&s.IDResp{ID: newUser.ID}))
}

func (a *Auth) updateUser(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	authHeader := r.Header.Get("Authorization")
	headerItems := strings.Split(authHeader, " ")

	if len(headerItems) < 2 {
		writeError(w, s.AuthError{Msg: "Authorization header is missing or invalid", Status: 401})
		return
	}

	token := headerItems[1]

	if r.Body == nil {
		logger.Logf("ERROR Data is missing")
		writeError(w, s.AuthError{Msg: "Request body is missing", Status: 400})
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		logger.Logf("ERROR Cannot parse user ID: %d", userID)
		writeError(w, s.AuthError{Msg: "Cannot parse user ID", Status: 400})
		return
	}

	var updatedUser s.User

	err = json.NewDecoder(r.Body).Decode(&updatedUser)
	if err != nil {
		logger.Logf("ERROR Cannot decode JSON payload")
		writeError(w, s.AuthError{Msg: err.Error(), Status: 400})
		return
	}

	if userID != updatedUser.ID {
		writeError(w, s.AuthError{Msg: "User IDs are not matching", Status: 400})
		return
	}

	err = a.AuthService.UpdateUser(&updatedUser, token)
	if err != nil {
		authErr, isAuthErr := err.(s.AuthError)
		if isAuthErr {
			writeError(w, authErr)
		} else {
			writeError(w, s.AuthError{Msg: err.Error(), Status: 500})
		}
	}
}

func (a *Auth) verifyUser(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	if r.Body == nil {
		logger.Logf("ERROR Data is missing")
		writeError(w, s.AuthError{Msg: "Request body is missing", Status: 400})
		return
	}

	var payload VerificationCodePayload
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil || payload.Code == "" || payload.Username == "" {
		logger.Logf("ERROR Invalid payload")
		writeError(w, s.AuthError{Msg: err.Error(), Status: 400})
		return
	}
	err = a.AuthService.VerifyUser(payload.Username, payload.Code)
	if err != nil {
		writeError(w, err.(s.AuthError))
		return
	}
}

func (a *Auth) deleteUser(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)

	authHeader := r.Header.Get("Authorization")
	headerItems := strings.Split(authHeader, " ")

	if len(headerItems) < 2 {
		writeError(w, s.AuthError{Msg: "Authorization header is missing or invalid", Status: 401})
		return
	}

	token := headerItems[1]

	if r.Body == nil {
		logger.Logf("ERROR Data is missing")
		writeError(w, s.AuthError{Msg: "Request body is missing", Status: 400})
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		logger.Logf("ERROR Cannot parse user ID: %d", userID)
		writeError(w, s.AuthError{Msg: "Cannot parse user ID", Status: 400})
		return
	}

	err = a.AuthService.DeleteUser(userID, token)
	if err != nil {
		authErr, isAuthErr := err.(s.AuthError)
		if isAuthErr {
			writeError(w, authErr)
		} else {
			writeError(w, s.AuthError{Msg: err.Error(), Status: 500})
		}
	}
}

func (a *Auth) getToken(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	t := r.URL.Query().Get("type")
	if t == "refresh_token" {
		logger.Logf("INFO Refreshing token")
		refToken := strings.Split(r.Header.Get("Authorization"), " ")[1]
		token, err := a.AuthService.RefreshToken(refToken)
		if err != nil {
			logger.Logf("WARN Cannot refresh token: %s", err.Error())
			authErr, isAuthErr := err.(s.AuthError)
			if isAuthErr {
				writeError(w, authErr)
			} else {
				writeError(w, s.AuthError{Msg: err.Error(), Status: 500})
			}
		} else {
			w.Write(s.AR2JSON(&s.AccessTokenResp{AccessToken: token}))
		}
		return
	}
	u, p, ok := r.BasicAuth()
	if ok {
		accessToken, refreshToken, err := a.AuthService.BasicAuthToken(u, p)
		if err != nil {
			logger.Logf("WARN Cannot issue token: %s", err.Error())
			writeError(w, err.(s.AuthError))
		} else {
			w.Write(s.ARR2JSON(&s.AccessAndRefreshTokenResp{AccessToken: accessToken, RefreshToken: refreshToken}))
		}
		return
	}
	logger.Logf("ERROR Basic Auth is missing")
	writeError(w, s.AuthError{Msg: "Basic Auth token is missing", Status: 400})
}

func (a *Auth) getUsers(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	authHeader := r.Header.Get("Authorization")
	headerItems := strings.Split(authHeader, " ")

	if len(headerItems) < 2 {
		writeError(w, s.AuthError{Msg: "Authorization header is missing or invalid", Status: 401})
		return
	}

	token := headerItems[1]

	users, err := a.AuthService.GetUsers(token)
	if err != nil {
		writeError(w, err.(s.AuthError))
		return
	}
	w.Write(s.UL2JSON(users))
}

func (a *Auth) getUserByUsername(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	authHeader := r.Header.Get("Authorization")
	headerItems := strings.Split(authHeader, " ")

	if len(headerItems) < 2 {
		writeError(w, s.AuthError{Msg: "Authorization header is missing or invalid", Status: 401})
		return
	}

	token := headerItems[1]

	username := chi.URLParam(r, "username")
	user, err := a.AuthService.GetUserByUsername(username, token)
	if err != nil {
		writeError(w, err.(s.AuthError))
		return
	}
	if user == nil {
		writeError(w, s.AuthError{Msg: "User is missing", Status: 404})
		return
	}
	w.Write(s.UI2JSON(user))
}

func (a *Auth) getUserById(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	authHeader := r.Header.Get("Authorization")
	headerItems := strings.Split(authHeader, " ")

	if len(headerItems) < 2 {
		writeError(w, s.AuthError{Msg: "Authorization header is missing or invalid", Status: 401})
		return
	}

	token := headerItems[1]

	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		logger.Logf("ERROR Cannot parse user ID: %d", userID)
		writeError(w, s.AuthError{Msg: "Cannot parse user ID", Status: 400})
		return
	}
	user, err := a.AuthService.GetUserById(userID, token)
	if err != nil {
		writeError(w, err.(s.AuthError))
		return
	}
	if user == nil {
		writeError(w, s.AuthError{Msg: "User is missing", Status: 404})
		return
	}
	w.Write(s.UI2JSON(user))
}

func (a *Auth) emailRecoveryCode(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	if r.Body == nil {
		logger.Logf("ERROR Data is missing")
		writeError(w, s.AuthError{Msg: "Request body is missing", Status: 400})
		return
	}

	var payload RecoveryEmailPayload
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil || payload.Username == "" {
		logger.Logf("ERROR Invalid payload")
		writeError(w, s.AuthError{Msg: err.Error(), Status: 400})
		return
	}

	err = a.AuthService.SendRecoveryEmail(payload.Username)
	if err != nil {
		writeError(w, err.(s.AuthError))
		return
	}
}

func (a *Auth) exchangeRecoveryCode(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	if r.Body == nil {
		logger.Logf("ERROR Data is missing")
		writeError(w, s.AuthError{Msg: "Request body is missing", Status: 400})
		return
	}

	var payload ExchangeCodeRequestPayload
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil || payload.Username == "" || payload.Code == "" {
		logger.Logf("ERROR Invalid payload")
		writeError(w, s.AuthError{Msg: err.Error(), Status: 400})
		return
	}

	code, err := a.AuthService.ExchangeRecoveryCode(payload.Username, payload.Code)
	if err != nil {
		writeError(w, err.(s.AuthError))
		return
	}

	w.Write(s.EC2JSON(&s.ExchangeCodeResponse{Code: code}))
}

func (a *Auth) resetPassword(w http.ResponseWriter, r *http.Request) {
	a.options(w, r)

	if r.Body == nil {
		logger.Logf("ERROR Data is missing")
		writeError(w, s.AuthError{Msg: "Request body is missing", Status: 400})
		return
	}

	var payload PasswordResetPayload
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil || payload.Password == "" || payload.Code == "" || payload.Username == "" {
		logger.Logf("ERROR Invalid payload")
		writeError(w, s.AuthError{Msg: err.Error(), Status: 400})
		return
	}

	err = a.AuthService.ResetPassword(payload.Username, payload.Code, payload.Password)
	if err != nil {
		writeError(w, err.(s.AuthError))
		return
	}
}

func (a *Auth) options(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PATCH, DELETE, OPTIONS")
}

func writeError(w http.ResponseWriter, err s.AuthError) {
	w.WriteHeader(err.Status)
	w.Write(s.ER2JSON(&s.ErrorResp{Error: err.Error()}))
}

func (a *Auth) start() {
	r := chi.NewRouter()

	r.Use(func(h http.Handler) http.Handler {
		return loggerHandler(h)
	})

	r.Route("/v1", func(r chi.Router) {
		r.Options("/*", a.options)
		r.Post("/invite", a.inviteUser)
		r.Post("/users", a.createUser)
		r.Patch("/users/{userID}", a.updateUser)
		r.Delete("/users/{userID}", a.deleteUser)
		r.Post("/users/verify", a.verifyUser)
		r.Post("/token", a.getToken)
		r.Get("/userinfo/byid/{userID}", a.getUserById)
		r.Get("/userinfo/byusername/{username}", a.getUserByUsername)
		r.Get("/userinfo", a.getUsers)
		r.Post("/password-recovery/email", a.emailRecoveryCode)
		r.Post("/password-recovery/exchange", a.exchangeRecoveryCode)
		r.Post("/password-recovery/reset", a.resetPassword)
	})
	http.ListenAndServe(":2525", r)
}

func loggerHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		ww := middleware.NewWrapResponseWriter(rw, r.ProtoMajor)
		logfmt := "INFO %s %s %d %d - %d ms"
		defer func() {
			if r.Method != "OPTIONS" {
				logger.Logf(logfmt, r.Method, r.URL, ww.Status(), ww.BytesWritten(), time.Since(t1).Milliseconds())
			}
		}()
		h.ServeHTTP(ww, r)
	})
}

func main() {
	conf := Config{}

	_, err := flags.Parse(&conf)

	if err != nil {
		logger.Logf("FATAL Cannot parse arguments: %s", err.Error())
	}

	if conf.Debug {
		logger = lgr.New(lgr.Debug, loggerFormat)
	}

	dao := dao.NewMongoUserDao(conf.MongoDBURL, conf.DatabaseName)
	mailer := email.EmailMailer{Email: conf.Email, Password: conf.EmailPassword, Server: conf.EmailServer, Port: conf.EmailPort, SiteName: conf.SiteName}
	service := AuthService{UserDao: dao, Mailer: &mailer, Config: conf}
	auth := Auth{AuthService: &service}
	logger.Logf("INFO BrightonUM 1.9.1 is starting")
	auth.start()
}
