package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCrypto(t *testing.T) {
	password := "p@ssw0rd"
	wrongPassword := "password"
	hash, err := Hash(password)

	assert.Nil(t, err)

	matchSuccess := Match(password, hash)
	assert.True(t, matchSuccess)

	matchFail := Match(wrongPassword, hash)
	assert.False(t, matchFail)
}