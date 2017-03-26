.PHONY: all release templates

all: templates

release:
	make -C lambda/fluentd release VERSION=$(VERSION)
	make -C lambda/formation release VERSION=$(VERSION)
	make -C lambda/lifecycle release VERSION=$(VERSION)
	mkdir -p /tmp/release/$(VERSION)
	cd /tmp/release/$(VERSION)
	jq '.Parameters.Version.Default |= "$(VERSION)"' dist/rack.json > formation.json
	aws s3 cp formation.json s3://convox/release/$(VERSION)/formation.json --acl public-read

devrelease:
	rm -r /tmp/release || true
	make -C lambda/fluentd devrelease VERSION=$(VERSION)
	make -C lambda/formation devrelease VERSION=$(VERSION)
	make -C lambda/lifecycle devrelease VERSION=$(VERSION)
	make -C lambda/cfevents devrelease VERSION=$(VERSION)
	make -C lambda/ecsevents devrelease VERSION=$(VERSION)
	mkdir -p /tmp/release/$(VERSION)
	jq '.Parameters.Version.Default |= "$(VERSION)"' dist/rack.json > /tmp/release/$(VERSION)/formation.json
	cd /tmp/release/$(VERSION) && aws s3 cp formation.json s3://$(DEV_RACK_SETTINGS_BUCKET)/dev/release/$(VERSION)/formation.json --acl public-read
	rm /tmp/release/$(VERSION)/formation.json


templates:
	go-bindata -nometadata -pkg=aws -o templates.go ./templates/...
