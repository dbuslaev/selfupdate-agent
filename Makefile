# Build, sign and exercise the self-updating agent.
#
# The important target is `release`: it cross-compiles every supported platform
# from one machine, stamps each binary with its version and the trusted release
# key, and signs a manifest over the result. Cross-compiling without a
# per-platform C toolchain is most of why this is written in Go.

VERSION ?= 0.0.0-dev
DIST    ?= dist
KEY     ?= release.key
PUB     ?= release.pub
ROLLOUT ?= 100

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

MODULE  := github.com/dbuslaev/selfupdate-agent
LDFLAGS  = -s -w -X $(MODULE)/internal/version.Version=$(VERSION)
APP_LD   = $(LDFLAGS) -X main.releaseKeys=$(RELEASE_KEYS)

# A static binary with no dynamic loader dependencies matters more here than
# usual: an updater that installs a binary the host cannot load has replaced a
# working install with a broken one.
export CGO_ENABLED = 0

.PHONY: all tools keys release build-app build-host test vet fmt clean demo

all: test release

tools:
	@mkdir -p bin
	go build -o bin/releasectl ./cmd/releasectl
	go build -o bin/updateserver ./cmd/updateserver

# keys mints the release signing keypair. Refuses to overwrite: losing the
# private key means the fleet can never be updated again.
keys: tools
	@test ! -f $(KEY) || (echo "$(KEY) exists; refusing to overwrite the signing key" && false)
	./bin/releasectl keygen -out $(basename $(KEY))

# release cross-compiles the program for every platform and signs the manifest.
# Only the program is published; the shim is placed by the installer and is
# updated out of band.
release: tools
	@test -f $(PUB) || (echo "no $(PUB); run 'make keys' first" && false)
	@mkdir -p $(DIST)
	@$(MAKE) --no-print-directory build-app RELEASE_KEYS="$$(cat $(PUB))"
	./bin/releasectl sign -key $(KEY) -version $(VERSION) -dir $(DIST) -rollout $(ROLLOUT)
	./bin/releasectl verify -pub $(PUB) -manifest $(DIST)/manifest.json

build-app:
	@for platform in $(PLATFORMS); do \
		goos=$${platform%/*}; goarch=$${platform#*/}; ext=""; \
		[ "$$goos" = "windows" ] && ext=".exe"; \
		out="$(DIST)/agent-app_$${goos}_$${goarch}$${ext}"; \
		GOOS=$$goos GOARCH=$$goarch go build -trimpath -ldflags '$(APP_LD)' -o "$$out" ./cmd/app || exit 1; \
		echo "  built $$out"; \
	done

# build-host builds all three binaries for the current platform, for installing
# locally or assembling an installer bundle.
build-host: tools
	@test -f $(PUB) || (echo "no $(PUB); run 'make keys' first" && false)
	@mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/agent ./cmd/shim
	go build -trimpath -ldflags '$(LDFLAGS) -X main.releaseKeys=$(shell cat $(PUB))' -o bin/agent-app ./cmd/app
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/installer ./cmd/installer

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

demo:
	./scripts/demo.sh

clean:
	rm -rf bin $(DIST) .demo
