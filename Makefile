.PHONY: all setup test cover

all: setup test cover

setup:
		go mod download

test:
		go test -v ./...

cover:
		go test -coverprofile=coverage.txt ./...
