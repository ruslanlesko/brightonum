FROM golang:latest

WORKDIR /app

COPY src/auth .

RUN go build -o main .

EXPOSE 2525

ENTRYPOINT ["./main"]
