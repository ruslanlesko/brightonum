package main

// UserDao provides interface to persisting operations
type UserDao interface {
	Save(*User) int
	GetByUsername(string) *User
}

// MemoryUserDao implementation for UserDao
type MemoryUserDao struct {
	Users map[int]*User
	LatestID int
}

// Save saves user
func (d *MemoryUserDao) Save(u *User) int {
	newID := d.LatestID + 1
	d.LatestID = newID
	d.Users[newID] = u
	return newID
}

// GetByUsername returns user by username
func (d *MemoryUserDao) GetByUsername(username string) *User {
	for _, u := range d.Users {
		if u.Username == username {
			return u
		}
	}
	return nil
}