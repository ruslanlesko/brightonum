![BrightonUM logo](https://github.com/ruslanlesko/brightonum/raw/master/logo/main.png)
# BrightonUM - simple authentication and user management system
Created by [Ruslan Lesko](https://leskor.com)

BrightonUM is a perfect choice if you are looking for self-hosted JWT-based simple authentication and user management solution. This system exposes REST API and user authentication can be verified by checking signature of the issued JWT tokens (resource services need public keys for it). Data is stored using MongoDB, which is the only dependency for BrightonUM.

## API
Port number: 2525

* GET `/v1/userinfo/byid/{userId}` Returns user info by id
* GET `/v1/userinfo/byusername/{username}` Returns user info by username
* GET `/v1/userinfo` Returns list of all users info
* POST `/v1/users` Creates user from JSON payload. Required string fields: username, firstName, lastName, email, password
* PATCH `/v1/users/{id}` Updates user data
* POST `/v1/token` Issues a token using basic auth. Returns JSON with 2 fields: accessToken and refreshToken
* POST `/v1/token?type=refresh_token` Issues an access token using refresh token (bearer)
* POST `/v1/password-recovery/email` Sends email with a password recovery code

Any errors would result in corresponding 4xx or 5xx status code and a JSON body with single `error` string attribute containing error message.

### Payload of user info:
```
{
  "id": 42,
  "username": "sarah69",
  "firstName": "Sarah",
  "lastName": "Lynn",
  "email": "srah69@gmail.com"
}
```

### Payload of the access token:
```
{
  "exp": 1579794679,
  "refresh_token": "eyJhbGc...7hBV3FGQ",
  "sub": "sarah69",
  "userId": 42
}
```
Token will expire in an hour. `exp` field is Unix time.
### Payload of the refresh token:
```
{
  "exp": 1579794679,
  "sub": "sarah69"
}
```
Token will expire in a year. `exp` field is Unix time.

### Payload of password recovery:
```
{
  "username": "sarah69"
}
```

## Build and run

Make sure that you have Go 1.13 or later, MongoDB and RSA Keys (described below) on your machine.

From the project root run
`go build -o main ./src`

### Required Parameters

* `--privkey` - path to RSA private key in PEM format
* `--pubkey` - path to RSA public key in PEM format
* `--mongoURL` - URL to mongo DB (mongodb://username:password@localhost/db)
* `--databaseName` - Name of the database to use

### Optional Parameters
* `--debug true` - enable debug logging

## RSA Key Generation On Linux

1. Generate a private key `openssl genrsa -out private.pem 2048`
2. Export public key `openssl rsa -in private.pem -outform PEM -pubout -out public.pem`