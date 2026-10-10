# Multi-stage production build using golang:1.26-alpine
FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o /bin/access-policy-service ./services/access-policy-service/cmd/server/main.go

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/access-policy-service /usr/local/bin/access-policy-service

USER nobody:nobody

EXPOSE 50052

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD nc -z 127.0.0.1 50052 || exit 1

ENTRYPOINT ["/usr/local/bin/access-policy-service"]
