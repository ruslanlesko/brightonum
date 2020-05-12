FROM golang:latest

COPY . /app

WORKDIR /app

RUN go build -o main ./src

EXPOSE 2525

ENTRYPOINT ["./main"]
