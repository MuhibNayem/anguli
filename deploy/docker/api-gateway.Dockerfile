# Multi-stage production build using golang:1.25.3-alpine
FROM golang:1.25.3-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o /bin/api-gateway ./services/api-gateway/cmd/server/main.go

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata curl

WORKDIR /app

COPY --from=builder /bin/api-gateway /usr/local/bin/api-gateway
COPY web/ /app/web/

USER nobody:nobody

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/api-gateway"]
