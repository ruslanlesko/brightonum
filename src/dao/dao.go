package dao

import "ruslanlesko/brightonum/src/structs"

// UserDao provides interface to persisting operations
type UserDao interface {

	// Save Returns generated id (> 0) on success.
	// Returns -1 on internal failure.
	Save(*structs.User) int

	// GetByUsername returns nil when user is not found
	// Returns error if data access error occured
	GetByUsername(string) (*structs.User, error)

	// GetByEmail returns nil when user is not found
	// Returns error if data access error occured
	GetByEmail(string) (*structs.User, error)

	// Get returns nil when user is not found
	// Returns error if data access error occured
	Get(int) (*structs.User, error)

	// GetAll returns all users or empty list
	GetAll() (*[]structs.User, error)

	// Update updates user if exists
	Update(*structs.User) error

	// SetRecoveryCode sets password recovery code for user id
	SetRecoveryCode(int, string) error

	// GetRecoveryCode extracts recovery code for user id
	GetRecoveryCode(int) (string, error)

	// SetResettingCode sets resetting code and removes recovery one
	SetResettingCode(int, string) error

	// GetResettingCode extracts resetting code for user id
	GetResettingCode(int) (string, error)

	// ResetPassword updates password and removes resetting code
	ResetPassword(int, string) error
}
