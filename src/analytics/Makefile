
VERSION=unknown

TOPDIR=$(shell git rev-parse --show-toplevel)

GOFILES=alert-handler

all: godeps build container

build: ${GOFILES}

${GOFILES}: %: %.go
	GOPATH=${TOPDIR} go build $<

godeps:
	GOPATH=${TOPDIR} ${TOPDIR}/bin/dep ensure -update || GOPATH=${TOPDIR} ${TOPDIR}/bin/dep ensure


container:
	docker build -t \
		gcr.io/trust-networks/analytics-alert-handler:${VERSION} \
	 	-f Dockerfile.alert-handler .

.PHONY: push
push:
	gcloud docker -- push \
	  gcr.io/trust-networks/analytics-alert-handler:${VERSION}

clean-bin:
	rm -f ${GOFILES}

clean:
	git clean -Xffdi
