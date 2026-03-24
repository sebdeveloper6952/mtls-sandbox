# Stage 1: Build SvelteKit UI
FROM node:22-alpine AS ui-builder
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ .
RUN pnpm build

# Stage 2: Build Go binary
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Replace embedded static dir with SvelteKit build output
COPY --from=ui-builder /src/web/build /src/internal/ui/static
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /mtls-sandbox ./cmd/mtls-sandbox

# Stage 3: Runtime (distroless includes CA certs for outbound TLS)
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /mtls-sandbox /mtls-sandbox
EXPOSE 8443 8080
ENTRYPOINT ["/mtls-sandbox"]
CMD ["serve"]
