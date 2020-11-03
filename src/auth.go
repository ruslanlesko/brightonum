package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"ruslanlesko/brightonum/src/dao"
	s "ruslanlesko/brightonum/src/structs"

	"github.com/go-chi/chi"
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

	// Enable debug logging
	Debug bool `long:"debug" required:"false" description:"Enable debug logging"`
}

func (a *Auth) createUser(w http.ResponseWriter, r *http.Request) {
	logger.Logf("INFO POST /v1/users request accepted")
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

func (a *Auth) getToken(w http.ResponseWriter, r *http.Request) {
	logger.Logf("INFO POST /v1/token request accepted")
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
	logger.Logf("INFO GET /v1/userinfo request accepted")
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	users, err := a.AuthService.GetUsers()
	if err != nil {
		writeError(w, err.(s.AuthError))
		return
	}
	w.Write(s.UL2JSON(users))
}

func (a *Auth) getUserByUsername(w http.ResponseWriter, r *http.Request) {
	logger.Logf("INFO GET /v1/userinfo/byusername request accepted")
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	username := chi.URLParam(r, "username")
	user, err := a.AuthService.GetUserByUsername(username)
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
	logger.Logf("INFO GET /v1/userinfo/byid request accepted")
	a.options(w, r)
	w.Header().Add("Content-type", "application/json; charset=utf-8")

	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		logger.Logf("ERROR Cannot parse user ID: %d", userID)
		writeError(w, s.AuthError{Msg: "Cannot parse user ID", Status: 400})
		return
	}
	user, err := a.AuthService.GetUserById(userID)
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

func (a *Auth) options(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization")
}

func writeError(w http.ResponseWriter, err s.AuthError) {
	w.WriteHeader(err.Status)
	w.Write(s.ER2JSON(&s.ErrorResp{Error: err.Error()}))
}

func (a *Auth) start() {
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Options("/*", a.options)
		r.Post("/users", a.createUser)
		r.Post("/token", a.getToken)
		r.Get("/userinfo/byid/{userID}", a.getUserById)
		r.Get("/userinfo/byusername/{username}", a.getUserByUsername)
		r.Get("/userinfo", a.getUsers)
	})
	http.ListenAndServe(":2525", r)
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
	service := AuthService{UserDao: dao, Config: conf}
	auth := Auth{AuthService: &service}
	logger.Logf("INFO BrightonUM 1.4.0 is starting")
	auth.start()
}
