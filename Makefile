.PHONY: all setup test cover

all: setup cover

setup:
		go get

test:
		go test -v ./...

cover:
		go test -coverprofile=coverage.txt ./...
