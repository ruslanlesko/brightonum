FROM golang:latest as build

COPY . /app

WORKDIR /app

RUN go test ./...

RUN go build -o main ./src

FROM debian:10.7-slim

COPY --from=build /app/main ./main

EXPOSE 2525

ENTRYPOINT ["./main"]