package structs

import "encoding/json"

type ErrorResp struct {
	Error string `json:"error"`
}

type IDResp struct {
	ID int `json:"id"`
}

type AccessAndRefreshTokenResp struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type AccessTokenResp struct {
	AccessToken string `json:"accessToken"`
}

func ER2JSON(r *ErrorResp) []byte {
	data, _ := json.Marshal(r)
	return data
}

func ID2JSON(id *IDResp) []byte {
	data, _ := json.Marshal(id)
	return data
}

func ARR2JSON(r *AccessAndRefreshTokenResp) []byte {
	data, _ := json.Marshal(r)
	return data
}

func AR2JSON(r *AccessTokenResp) []byte {
	data, _ := json.Marshal(r)
	return data
}
