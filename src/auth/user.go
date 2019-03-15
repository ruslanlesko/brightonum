package main

import (
	"encoding/json"
)

// User structure
type User struct {
	ID        int
	Username  string
	FirstName string
	LastName  string
	Email     string
	Password  string
}

func (u *User) toJSON() []byte {
	data, _ := json.Marshal(u)
	return data
}