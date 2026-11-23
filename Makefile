BUILD_DIR = builds
BINARY_NAME = vault-unsealer
MODULE = github.com/soerenschneider/$(BINARY_NAME)/v2
CHECKSUM_FILE = checksum.sha256
SIGNATURE_KEYFILE = ~/.signify/github.sec
DOCKER_PREFIX = ghcr.io/soerenschneider

# Reproducible builds: pin the compiler to the toolchain declared in go.mod, strip
# local paths and VCS metadata, and clear the build ID so identical sources yield
# identical binaries regardless of where they're built.
export GOTOOLCHAIN = $(shell awk '/^toolchain/ {print $$2}' go.mod)
export CGO_ENABLED = 0
BUILD_FLAGS = -trimpath -buildvcs=false
LDFLAGS = -w -buildid= -X '$(MODULE)/internal.BuildVersion=$(VERSION)' -X '$(MODULE)/internal.CommitHash=$(COMMIT_HASH)'

tests:
	go test ./... -race -covermode=atomic -coverprofile=coverage.out
	go tool cover -html=coverage.out -o=coverage.html
	go tool cover -func=coverage.out -o=coverage.out

clean:
	git diff --quiet || { echo 'Dirty work tree' ; false; }
	rm -rf ./$(BUILD_DIR)

build: version-info
	go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd

release: clean version-info cross-build
	cd $(BUILD_DIR) && LC_ALL=C sha256sum * > $(CHECKSUM_FILE) && cd -

signed-release: release
	pass keys/signify/github | signify -S -s $(SIGNATURE_KEYFILE) -m $(BUILD_DIR)/$(CHECKSUM_FILE)
	gh-upload-assets -o soerenschneider -r $(BINARY_NAME) -f ~/.gh-token builds

cross-build:
	GOOS=linux GOARCH=amd64       go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64   ./cmd
	GOOS=linux GOARCH=arm GOARM=6 go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-armv6   ./cmd
	GOOS=linux GOARCH=arm64       go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-aarch64 ./cmd

docker-build:
	docker build -t "$(DOCKER_PREFIX)/$(BINARY_NAME)" .

version-info:
	$(eval VERSION := $(shell git describe --tags --abbrev=0 || echo "dev"))
	$(eval COMMIT_HASH := $(shell git rev-parse HEAD))

fmt:
	find . -iname "*.go" -exec go fmt {} \; 

lint:
	golangci-lint run

pre-commit-init:
	pre-commit install
	pre-commit install --hook-type commit-msg

pre-commit-update:
	pre-commit autoupdate
