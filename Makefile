.PHONY: all setup test cover

all: setup cover

setup:
		go mod download

test:
		go test -v ./...

cover:
		go test -coverprofile=coverage.txt ./...
