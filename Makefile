PLUGIN := silo-plugin-auth-ldap
VERSION ?= dev

.PHONY: test vet build clean

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/$(PLUGIN) .

clean:
	rm -rf dist
