all::

# Needs to be defined before including Makefile.common to auto-generate targets
DOCKER_ARCHS ?= amd64 armv7 arm64 ppc64le s390x

include Makefile.common

PROMTOOL_VERSION ?= 2.5.0
PROMTOOL_URL     ?= https://github.com/prometheus/prometheus/releases/download/v$(PROMTOOL_VERSION)/prometheus-$(PROMTOOL_VERSION).$(GO_BUILD_PLATFORM).tar.gz
PROMTOOL         ?= $(FIRST_GOPATH)/bin/promtool

DOCKER_REPO             ?=povilasv
DOCKER_IMAGE_NAME       ?= systemd-exporter
MACH                    ?= $(shell uname -m)

STATICCHECK_IGNORE =

ifeq ($(GOHOSTOS), linux)
	test-e2e := test-e2e
else
	test-e2e := skip-test-e2e
endif

# Use CGO for non-Linux builds.
ifeq ($(GOOS), linux)
	PROMU_CONF ?= .promu.yml
else
	ifndef GOOS
		ifeq ($(GOHOSTOS), linux)
			PROMU_CONF ?= .promu.yml
		else
			PROMU_CONF ?= .promu-cgo.yml
		endif
	else
		PROMU_CONF ?= .promu-cgo.yml
	endif
endif

PROMU := $(FIRST_GOPATH)/bin/promu --config $(PROMU_CONF)

all:: vet common-all

.PHONY: test-docker
test-docker:
	@echo ">> testing docker image"
	./test_image.sh "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)" 9558

.PHONY: promtool
promtool: $(PROMTOOL)

$(PROMTOOL):
	$(eval PROMTOOL_TMP := $(shell mktemp -d))
	curl -s -L $(PROMTOOL_URL) | tar -xvzf - -C $(PROMTOOL_TMP)
	mkdir -p $(FIRST_GOPATH)/bin
	cp $(PROMTOOL_TMP)/prometheus-$(PROMTOOL_VERSION).$(GO_BUILD_PLATFORM)/promtool $(FIRST_GOPATH)/bin/promtool
	rm -r $(PROMTOOL_TMP)

