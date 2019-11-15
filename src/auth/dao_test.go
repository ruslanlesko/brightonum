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

func TestMongoUserDao_Save(t *testing.T) {
	var ud UserDao = &MongoUserDao{"mongodb://pcusr:pcpwd@localhost/pichubdb"}
	var u1 = User{-1, "uname", "test", "user", "test@email.com", "pwd"}
	var u2 = User{-1, "uname2", "test2", "user2", "test2@email.com", "pwd2"}

	id1 := ud.Save(&u1)
	id2 := ud.Save(&u2)

	assert.Equal(t, id2, id1 + 1)
}

func TestMongoUserDao_GetByUsername(t *testing.T) {
	var ud UserDao = &MongoUserDao{"mongodb://pcusr:pcpwd@localhost/pichubdb"}
	var u1 = User{-1, "uname3", "test", "user", "test@email.com", "pwd"}

	u1.ID = ud.Save(&u1)

	var extractedUser = *ud.GetByUsername("uname3")
	assert.Equal(t, u1, extractedUser)
}