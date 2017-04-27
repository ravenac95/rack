.PHONY: all build clean release

CONVOX_CUSTOM_RELEASE ?= convox

all: lambda.zip

clean:
	rm -f lambda.zip main

lambda.zip: index.js main
	zip -r lambda.zip main index.js

main: *.go
	GOOS=linux GOARCH=amd64 go build -o main

release: lambda.zip
	for region in $(shell cat ../../../../REGIONS); do \
		aws s3 cp lambda.zip s3://$(CONVOX_CUSTOM_RELEASE)-$$region/release/$(VERSION)/lambda/formation.zip --acl public-read --region $$region; \
	done

devrelease: lambda.zip
	aws s3 cp lambda.zip s3://$(DEV_RACK_SETTINGS_BUCKET)/dev/release/$(VERSION)/lambda/formation.zip --acl public-read --region $(DEV_RACK_REGION)
	make clean
