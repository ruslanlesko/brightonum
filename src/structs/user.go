package structs

import (
	"encoding/json"
)

// User structure
type User struct {
	ID        int    `bson:"_id"`
	Username  string `bson:"username"`
	FirstName string `bson:"firstName"`
	LastName  string `bson:"lastName"`
	Email     string `bson:"email"`
	Password  string `bson:"password"`
}

// UserInfo structure
type UserInfo struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

func U2JSON(u *User) []byte {
	data, _ := json.Marshal(u)
	return data
}

func UI2JSON(u *UserInfo) []byte {
	data, _ := json.Marshal(u)
	return data
}

func UL2JSON(us *[]UserInfo) []byte {
	data, _ := json.Marshal(us)
	return data
}
