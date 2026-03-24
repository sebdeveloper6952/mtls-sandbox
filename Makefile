.PHONY: build-web build clean

# Build SvelteKit UI and copy output into Go embed directory
build-web:
	cd web && pnpm install && pnpm build
	rm -rf internal/ui/static
	cp -r web/build internal/ui/static

# Build Go binary (runs build-web first)
build: build-web
	go build -o mtls-sandbox ./cmd/mtls-sandbox

clean:
	rm -rf web/build internal/ui/static mtls-sandbox
