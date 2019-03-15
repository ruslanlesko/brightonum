package main

import (
	"fmt"
	"net/http"
	"github.com/go-chi/chi"
	"strconv"
	"encoding/json"
	"strings"
	"github.com/dgrijalva/jwt-go"
	"time"
	"io/ioutil"
)

// Auth provide root routing
type Auth struct {
	Users map[int]*User
	LatestID int
}

func (a *Auth) checkAuth(r *http.Request) *User {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil
	}
	t := strings.Split(header, " ")[1]
	keyData, _ := ioutil.ReadFile("key.pub")
	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return a.getUserByUsername(fmt.Sprintf("%s", claims["sub"]))
	}
	return nil
}

func (a * Auth) getUser(w http.ResponseWriter, r *http.Request) {
	currentUser := a.checkAuth(r)
	if currentUser == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "authorization")
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
	newID := a.LatestID + 1
	a.LatestID = newID
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
	newUser.ID = newID
	a.Users[newID] = &newUser
	response := fmt.Sprintf("{\"id\": %d}", newID)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte(response))
}

func (a *Auth) getUserByUsername(username string) *User {
	for _, u := range a.Users {
		if u.Username == username {
			return u
		}
	}
	return nil
}

func (a *Auth) basicAuthToken(username, password string) string {
	user := a.getUserByUsername(username)

	if user == nil || user.Password != password {
		return "not matches"
	}

	keyData, _ := ioutil.ReadFile("key")
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": username,
		"exp": time.Now().AddDate(1, 0, 0).UTC().Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString(key)

	if err != nil {
		return err.Error()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": username,
		"userId": user.ID,
		"exp": time.Now().Add(time.Hour).UTC().Unix(),
		"refresh_token": refreshTokenString,
	})

	tokenString, err := token.SignedString(key)

	if err != nil {
		return err.Error()
	}

	return tokenString
}

func (a *Auth) validateRefreshToken(t string) (*User, bool) {
	keyData, _ := ioutil.ReadFile("key.pub")
	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		u := a.getUserByUsername(fmt.Sprintf("%s", claims["sub"]))
		return u, true
	}
	return nil, false
}

func (a *Auth) refreshToken(t string) string {
	u, ok := a.validateRefreshToken(t)
	if ok {
		return a.basicAuthToken(u.Username, u.Password)
	}
	return "not validated"
}

func (a *Auth) getToken(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("type")
	if t == "refresh_token" {
		refToken := strings.Split(r.Header.Get("Authorization"), " ")[1]
		token := a.refreshToken(refToken)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte(token))
		return
	}
	u, p, ok := r.BasicAuth()
	if ok {
		token := a.basicAuthToken(u, p)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte(token))
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
	auth := Auth{Users: make(map[int]*User), LatestID: 0}
	auth.start()
}