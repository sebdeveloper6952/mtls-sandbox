# Stage 1: Build
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /mtls-sandbox ./cmd/mtls-sandbox

# Stage 2: Runtime (distroless includes CA certs for outbound TLS)
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /mtls-sandbox /mtls-sandbox
EXPOSE 8443 8080
ENTRYPOINT ["/mtls-sandbox"]
CMD ["serve"]
