NAME 	:= ssc
SRCS	:= $(shell find . -type d -name archive -prune -o -type f -name '*.go')
TAG_NAME := $(shell git tag -l --contains HEAD)
SHA := $(shell git rev-parse HEAD)
VERSION := $(if $(TAG_NAME),$(TAG_NAME),$(SHA))
LDFLAGS	:= -ldflags="-s -w -X \"github.com/n-creativesystem/self-signed-certificate/version.Version=$(VERSION)\" -extldflags \"-static\""

build/static: $(SRCS)
	CGO_ENABLED=0 go build -a -tags netgo -installsuffix netgo $(LDFLAGS) -o bin/$(NAME)

build/mac:
	@echo Version: $(VERSION)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -a -tags netgo -installsuffix netgo $(LDFLAGS) -o bin/drawin-amd64-$(NAME)