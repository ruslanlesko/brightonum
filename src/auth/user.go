package main

import (
	"encoding/json"
)

// User structure
type User struct {
	ID        int		`bson:"id"`
	Username  string	`bson:"username`
	FirstName string	`bson:"firstName"`
	LastName  string	`bson:"lastName"`
	Email     string	`bson:"email"`
	Password  string	`bson:"password"`
}

func (u *User) toJSON() []byte {
	data, _ := json.Marshal(u)
	return data
}