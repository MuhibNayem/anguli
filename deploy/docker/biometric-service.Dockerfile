# Multi-stage production build using golang:1.25.3-alpine
FROM golang:1.25.3-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o /bin/biometric-service ./services/biometric-service/cmd/server/main.go

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/biometric-service /usr/local/bin/biometric-service

USER nobody:nobody

EXPOSE 50051

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD nc -z 127.0.0.1 50051 || exit 1

ENTRYPOINT ["/usr/local/bin/biometric-service"]
