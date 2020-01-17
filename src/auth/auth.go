package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi"
	"github.com/jessevdk/go-flags"
)

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
}

func (a *Auth) getUser(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization")
	if header == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	currentUser := a.AuthService.GetUserByToken(strings.Split(header, " ")[1])
	if currentUser == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	if currentUser.ID != userID {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Write(currentUser.toJSON())
}

func (a *Auth) createUser(w http.ResponseWriter, r *http.Request) {
	var newUser User
	if r.Body == nil {
		w.Write([]byte("No data"))
		return
	}
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	a.AuthService.CreateUser(&newUser)
	newID := newUser.ID
	response := fmt.Sprintf("{\"id\": %d}", newID)
	fmt.Println(response)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte(response))
}

func (a *Auth) getToken(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("type")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization")
	if t == "refresh_token" {
		refToken := strings.Split(r.Header.Get("Authorization"), " ")[1]
		token, err := a.AuthService.RefreshToken(refToken)
		if err != nil {
			w.Write([]byte(err.Error()))
		} else {
			w.Write([]byte(token))
		}
		return
	}
	u, p, ok := r.BasicAuth()
	if ok {
		token, err := a.AuthService.BasicAuthToken(u, p)
		if err != nil {
			w.Write([]byte(err.Error()))
		} else {
			w.Write([]byte(token))
		}
		return
	}
	w.Write([]byte("error"))
}

func (a *Auth) options(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization")
}

func (a *Auth) start() {
	fmt.Printf("Starting the server...\n")
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Options("/*", a.options)
		r.Get("/users/{userID}", a.getUser)
		r.Post("/users", a.createUser)
		r.Post("/token", a.getToken)
	})
	http.ListenAndServe(":2525", r)
}

func main() {
	conf := Config{}

	_, err := flags.Parse(&conf)

	if err != nil {
		fmt.Printf("Cannot parse arguments: %s", err.Error())
	}

	dao := MongoUserDao{URL: conf.MongoDBURL, databaseName: conf.DatabaseName}
	service := AuthService{UserDao: &dao, Config: conf}
	auth := Auth{AuthService: &service}
	auth.start()
}
