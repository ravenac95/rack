.PHONY: all templates test test-deps vendor

CONVOX_BUILDER_TAG ?= convox/build
CONVOX_BUILDER_TAG_VERSION ?= $(USER)
CONVOX_API_TAG ?= convox/api
CONVOX_API_TAG_VERSION ?= $(VERSION)
CONVOX_CUSTOM_RELEASE ?= convox

all: templates

clean:
	make -C provider clean

builder:
	docker build -t $(CONVOX_BUILDER_TAG):$(CONVOX_BUILDER_TAG_VERSION) -f api/cmd/build/Dockerfile .
	docker push $(CONVOX_BUILDER_TAG):$(CONVOX_BUILDER_TAG_VERSION)	

fixtures:
	make -C api/models/fixtures

release:
	make -C provider release VERSION=$(CONVOX_API_TAG_VERSION)
	docker build -t $(CONVOX_API_TAG):$(CONVOX_API_TAG_VERSION) .
	docker push $(CONVOX_API_TAG):$(CONVOX_API_TAG_VERSION)

templates:
	go get -u github.com/jteeuwen/go-bindata/...
	make -C api templates
	make -C cmd templates
	make -C provider templates
	make -C sync templates

test:
	env PROVIDER=test CONVOX_WAIT= bin/test

vendor:
	godep save ./...

devrelease:
	make -C provider devrelease VERSION=$(CONVOX_API_TAG_VERSION)
	docker build -t $(CONVOX_API_TAG):$(CONVOX_API_TAG_VERSION) .
	docker push $(CONVOX_API_TAG):$(CONVOX_API_TAG_VERSION)

devtools:
	mkdir -p dev
	cd cmd/convox; go build -o ../../dev/convox -tags devtools

nodevtools:
	cd cmd/convox; go build -o ../../dev/convox 
