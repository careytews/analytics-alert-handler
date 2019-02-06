
VERSION=$(shell git describe | sed 's/^v//')
BUILD_IMAGE=gcr.io/trust-networks/analytic-builder:5

# this is a specialisation for GoCD. But there MUST be a better way
ifeq ($(wildcard /var/go/.ssh), )
SSH_DIR=~/.ssh
else
SSH_DIR=/var/go/.ssh
endif


local:
	@if [[ $$(TOPDIR=$$(pwd) PATH=$${PATH}:$${TOPDIR}/bin which dep) == "" ]]; then echo "fetching dep"; GOPATH=$$(pwd) go get -u github.com/golang/dep/cmd/dep; fi
	(TOPDIR=$$(pwd) PATH=$${PATH}:$${TOPDIR}/bin; cd src/analytics; make godeps TOPDIR=$${TOPDIR} ; make build TOPDIR=$${TOPDIR})

build: clean-bin image
	docker run --rm -v $$(pwd):/working -v ${SSH_DIR}:/keys ${BUILD_IMAGE}

image:
	gcloud docker -- pull ${BUILD_IMAGE}

all: build container

container push clean clean-bin:
	(TOPDIR=$$(pwd); cd src/analytics; make $@ TOPDIR=$${TOPDIR} VERSION=${VERSION})

version:
	@echo ${VERSION}

BRANCH=master
PREFIX=resources/$(shell basename $(shell git remote get-url origin)  | sed -E 's@^(.*)\.git$$@\1@g' )
FILE=${PREFIX}/ksonnet/version.jsonnet
REPO=$(shell git remote get-url origin)

tools: phony
	if [ ! -d tools ]; then \
		git clone git@github.com:trustnetworks/cd-tools tools; \
	fi; \
	(cd tools; git pull)

phony:

bump-version: tools
	tools/bump-version

update-cluster-config: tools
	tools/update-cluster-config ${BRANCH} ${PREFIX} ${FILE} ${VERSION} \
	    ${REPO}
