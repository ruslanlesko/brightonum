package structs

// AuthError simple error
type AuthError struct {
	Msg    string
	Status int
}

func (e AuthError) Error() string {
	return e.Msg
}
