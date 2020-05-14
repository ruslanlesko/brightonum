package main

import (
	"encoding/json"
	"fmt"
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

func (a *Auth) getUser(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization")
	if header == "" {
		logger.Logf("ERROR Token is missing")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	currentUser := a.AuthService.GetUserByToken(strings.Split(header, " ")[1])
	if currentUser == nil {
		logger.Logf("ERROR Token is invalid")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		logger.Logf("ERROR Cannot parse user ID: %d", userID)
		w.Write([]byte(fmtErrorResponse(err.Error())))
		return
	}
	if currentUser.ID != userID {
		w.WriteHeader(http.StatusUnauthorized)
		logger.Logf("WARN Unauthorized access attempt")
		return
	}
	w.Write(s.U2JSON(currentUser))
}

func (a *Auth) createUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	var newUser s.User
	if r.Body == nil {
		logger.Logf("ERROR Data is missing")
		w.Write([]byte(fmtErrorResponse("No data")))
		return
	}
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		logger.Logf("ERROR Cannot decode JSON payload")
		w.Write([]byte(fmtErrorResponse(err.Error())))
		return
	}
	err = a.AuthService.CreateUser(&newUser)
	if err != nil {
		authErr, isAuthErr := err.(s.AuthError)
		if isAuthErr {
			w.WriteHeader(authErr.Status)
		} else {
			w.WriteHeader(500)
		}
		w.Write([]byte(fmtErrorResponse(err.Error())))
		return
	}

	newID := newUser.ID
	response := fmt.Sprintf("{\"id\": %d}", newID)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte(response))
}

func (a *Auth) getToken(w http.ResponseWriter, r *http.Request) {
	logger.Logf("DEBUG Request for issuing a token was accepted")
	t := r.URL.Query().Get("type")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization")
	if t == "refresh_token" {
		logger.Logf("INFO Refreshing token")
		refToken := strings.Split(r.Header.Get("Authorization"), " ")[1]
		token, err := a.AuthService.RefreshToken(refToken)
		if err != nil {
			logger.Logf("WARN Cannot refresh token: %s", err.Error())
			authErr, isAuthErr := err.(s.AuthError)
			if isAuthErr {
				w.WriteHeader(authErr.Status)
			} else {
				w.WriteHeader(500)
			}
			w.Write([]byte(fmtErrorResponse(err.Error())))
		} else {
			w.Write([]byte(fmtAccTokenResponse(token)))
		}
		return
	}
	u, p, ok := r.BasicAuth()
	if ok {
		accessToken, refreshToken, err := a.AuthService.BasicAuthToken(u, p)
		if err != nil {
			logger.Logf("WARN Cannot issue token: %s", err.Error())
			w.WriteHeader(400)
			w.Write([]byte(fmtErrorResponse(err.Error())))
		} else {
			w.Write([]byte(fmtAccRefTokenResponse(accessToken, refreshToken)))
		}
		return
	}
	logger.Logf("ERROR Basic Auth is missing")
	w.Write([]byte(fmtErrorResponse("Basic Auth is missing from request")))
}

func (a *Auth) getUserByUsername(w http.ResponseWriter, r *http.Request) {
	logger.Logf("DEBUG Request for getting user by username was accepted")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	username := chi.URLParam(r, "username")
	user := a.AuthService.GetUserByUsername(username)
	if user == nil {
		w.Write([]byte(fmtErrorResponse("User is missing")))
		return
	}
	w.Write(s.UI2JSON(user))
}

func (a *Auth) getUserById(w http.ResponseWriter, r *http.Request) {
	logger.Logf("DEBUG Request for getting user by id was accepted")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		logger.Logf("ERROR Cannot parse user ID: %d", userID)
		w.Write([]byte(fmtErrorResponse(err.Error())))
		return
	}
	user := a.AuthService.GetUserById(userID)
	if user == nil {
		w.Write([]byte(fmtErrorResponse("User is missing")))
		return
	}
	w.Write(s.UI2JSON(user))
}

func (a *Auth) options(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization")
}

func (a *Auth) start() {
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Options("/*", a.options)
		r.Get("/users/{userID}", a.getUser)
		r.Post("/users", a.createUser)
		r.Post("/token", a.getToken)
		r.Get("/userinfo/byid/{userID}", a.getUserById)
		r.Get("/userinfo/byusername/{username}", a.getUserByUsername)
	})
	http.ListenAndServe(":2525", r)
}

// Formats access and refresh token to JSON response
func fmtAccRefTokenResponse(accessToken, refreshToken string) string {
	return fmt.Sprintf("{\"accessToken\":\"%s\",\"refreshToken\":\"%s\"}", accessToken, refreshToken)
}

// Formats access token to JSON response
func fmtAccTokenResponse(accessToken string) string {
	return fmt.Sprintf("{\"accessToken\":\"%s\"}", accessToken)
}

// Formats error response to JSON
func fmtErrorResponse(err string) string {
	return fmt.Sprintf("{\"error\":\"%s\"}", err)
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
	logger.Logf("INFO BrightonUM 1.3.0 is starting")
	auth.start()
}
