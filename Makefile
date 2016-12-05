.PHONY: all templates test test-deps vendor

all: templates

builder:
	docker build -t convox/build:$(USER) -f api/cmd/build/Dockerfile .
	docker push convox/build:$(USER)

fixtures:
	make -C api/models/fixtures

manpages: ## Generate man pages from go source and markdown
	docker build -t convox-manpage-dev -f "man/Dockerfile" ./man
	docker run --rm \
		-v $(PWD):/go/src/github.com/convox/rack/ \
		convox-manpage-dev

release:
	make -C provider release VERSION=$(VERSION)
	docker build -t convox/api:$(VERSION) .
	docker push convox/api:$(VERSION)

templates:
	go get -u github.com/jteeuwen/go-bindata/...
	make -C api templates
	make -C cmd templates
	make -C provider templates
	make -C sync templates

test:
	env PROVIDER=test bin/test

vendor:
	godep save ./...
