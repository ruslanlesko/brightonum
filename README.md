![BrightonUM logo](https://github.com/ruslanlesko/brightonum/raw/master/logo/main.png)
# BrightonUM - simple authentication and user management system
Created by [Ruslan Lesko](https://leskor.com)

![badge](https://action-badges.now.sh/ruslanlesko/brightonum)

BrightonUM is a perfect choice if you are looking for self-hosted JWT-based simple authentication and user management solution. This system exposes REST API and user authentication can be verified by checking signature of the issued JWT tokens (resource services need public keys for it). Data is stored using MongoDB, which is the only dependency for BrightonUM.

## API
Port number: 2525

* POST `/v1/invite` Sends invite to email and persists invite code
* GET `/v1/userinfo/byid/{userId}` Returns user info by id
* GET `/v1/userinfo/byusername/{username}` Returns user info by username
* GET `/v1/userinfo` Returns list of all users info
* POST `/v1/users` Creates user from JSON payload. Required string fields: inviteCode (only for private mode), username, firstName, lastName, email, password
* PATCH `/v1/users/{id}` Updates user data
* DELETE `/v1/users/{id}` Deletes user
* POST `/v1/token` Issues a token using basic auth. Returns JSON with 2 fields: accessToken and refreshToken
* POST `/v1/token?type=refresh_token` Issues an access token using refresh token (bearer)
* POST `/v1/password-recovery/email` Sends email with a password recovery code
* POST `/v1/password-recovery/exchange` Exchande recovery code for password reset code
* POST `/v1/password-recovery/reset` Reset password using code from the exchange step

Any errors would result in corresponding 4xx or 5xx status code and a JSON body with single `error` string attribute containing error message.

### Payload of user invite:
```
{
  "email": "srah69@gmail.com"
}
```

### Payload of user creation:
```
{
  "inviteCode": "19284261",
  "username": "sarah69",
  "firstName": "Sarah",
  "lastName": "Lynn",
  "email": "srah69@gmail.com",
  "password": "or@angeJu1ce"
}
```

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

### Payload of password recovery exchange code request
```
{
  "username": "sarah69"
  "code": "123987"
}
```

### Payload of password recovery exchange code response
```
{
  "code": "1239874560"
}
```

### Payload of password reset request
```
{
  "username": "sarah69"
  "code": "1239874560"
  "password": "o@kh3art"
}
```

## Build and run

Make sure that you have Go 1.15 or later, MongoDB and RSA Keys (described below) on your machine.

From the project root run
`go build -o main ./src`

### Required Parameters

* `--privkey` - path to RSA private key in PEM format
* `--pubkey` - path to RSA public key in PEM format
* `--mongoURL` - URL to mongo DB (mongodb://username:password@localhost/db)
* `--databaseName` - Name of the database to use
* `--adminID` - Admin User ID

### Optional Parameters
* `--debug true` - enable debug logging
* `--private true` - require invite code during registration

## RSA Key Generation On Linux

1. Generate a private key `openssl genrsa -out private.pem 2048`
2. Export public key `openssl rsa -in private.pem -outform PEM -pubout -out public.pem`