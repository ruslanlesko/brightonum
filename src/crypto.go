package main

import (
	"golang.org/x/crypto/bcrypt"
)

// Hash salts password and hashes it, returning salted hash
func Hash(password string) (string, error) {
	hash, er := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if er != nil {
		return "", er
	}
	return string(hash), nil
}

// Match compares password with salted hashed value
func Match(password, hash string) bool {
	byteHash := []byte(hash)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(password))
	if err != nil {
		return false
	}
	return true
}