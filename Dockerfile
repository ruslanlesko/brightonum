FROM golang:1.15.5 as build

COPY . /app

WORKDIR /app

RUN go test -run '^(TestAuthService_CreateUser|TestAuthService_RefreshToken|TestAuthService_ResetPassword|TestCrypto)$' ruslanlesko/brightonum/src

RUN go build -o main ./src

FROM debian:10.7-slim

COPY --from=build /app/main ./main

EXPOSE 2525

ENTRYPOINT ["./main"]