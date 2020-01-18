# Authenthication Service

## API

GET `/v1/users/{userId}` Returns user in JSON payload.
POST `/v1/users` Creates user from JSON payload. Required string fields: Username, FirstName, LastName, Email, Password
POST `/v1/token` Issues a token using basic auth.

## Required Parameters

* `--privkey` - path to RSA private key in PEM format
* `--pubkey` - path to RSA public key in PEM format
* `--mongoURL` - URL to mongo DB (mongodb://username:password@localhost/db)
* `--databaseName` - Name of the database to use

## RSA Key Generation On Linux

1. Generate a private key `openssl genrsa -out private.pem 2048`
2. Export public key `openssl rsa -in private.pem -outform PEM -pubout -out public.pem`