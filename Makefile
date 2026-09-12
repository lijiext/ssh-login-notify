APP := ssh-login-notify
VERSION ?= dev
MODULE := github.com/lijiext/ssh-login-notify
LDFLAGS := -s -w -X $(MODULE)/internal/app.version=$(VERSION)

.PHONY: build fmt lint test release image

fmt:
	gofmt -w cmd internal

lint:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	./scripts/lint-docs.sh

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/$(APP) ./cmd/$(APP)

test:
	go test -race ./...

release: lint test
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/$(APP)-linux-amd64 ./cmd/$(APP)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/$(APP)-linux-arm64 ./cmd/$(APP)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/$(APP)-linux-armv7 ./cmd/$(APP)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/$(APP)-linux-386 ./cmd/$(APP)
	cd dist && sha256sum $(APP)-linux-* > SHA256SUMS

image:
	mkdir -p dist
	docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 --tag $(APP):$(VERSION) --output type=oci,dest=dist/$(APP)-$(VERSION).oci.tar .
	cd dist && sha256sum $(APP)-$(VERSION).oci.tar > $(APP)-$(VERSION).oci.tar.sha256
