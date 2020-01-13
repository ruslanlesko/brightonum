package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryUserDao_Save(t *testing.T) {
	var ud UserDao = &MemoryUserDao{make(map[int]*User), 0}

	firstID := ud.Save(&User{-1, "", "", "", "", ""})
	assert.Equal(t, 1, firstID)

	secondID := ud.Save(&User{-1, "", "", "", "", ""})
	assert.Equal(t, 2, secondID)
}

func TestMemoryUserDao_GetByUsername(t *testing.T) {
	var ud UserDao = &MemoryUserDao{make(map[int]*User), 0}
	var u = User{-1, "uname", "test", "user", "test@email.com", "pwd"}

	id := ud.Save(&u)
	u.ID = id

	var extractedUser = *ud.GetByUsername("uname")
	assert.Equal(t, u, extractedUser)
}
