FROM golang:latest

WORKDIR /app

COPY src/auth .

RUN go get github.com/dgrijalva/jwt-go
RUN go get github.com/go-chi/chi
RUN go get github.com/jessevdk/go-flags
RUN go get gopkg.in/mgo.v2
RUN go get gopkg.in/mgo.v2/bson
RUN go get github.com/go-pkgz/lgr
RUN go get golang.org/x/crypto/bcrypt

RUN go build -o main .

EXPOSE 2525

ENTRYPOINT ["./main"]
