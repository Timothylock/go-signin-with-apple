.PHONEY: all setup test cover

all: setup cover

setup:
		go get golang.org/x/tools/cmd/cover
		go get github.com/stretchr/testify/assert
		go get github.com/tideland/gorest/jwt
		go get github.com/dgrijalva/jwt-go
		go get ./...

test:
		go test -v ./...

cover:
		go test -coverprofile=coverage.txt ./...