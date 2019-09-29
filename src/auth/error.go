package main

// AuthError simple error
type AuthError struct {
	Msg string
}

func (e AuthError) Error() string {
	return e.Msg
}