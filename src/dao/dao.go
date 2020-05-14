package dao

import "ruslanlesko/brightonum/src/structs"

// UserDao provides interface to persisting operations
type UserDao interface {

	// Save Returns generated id (> 0) on success.
	// Returns -1 on internal failure.
	Save(*structs.User) int

	// GetByUsername returns nil when user is not found
	// Returns error is data access error occured
	GetByUsername(string) (*structs.User, error)

	// Get returns nil when user is not found
	// Returns error is data access error occured
	Get(int) (*structs.User, error)
}
