PYTHON ?= python3
RELEASE_VERSION ?= dev
SOURCE_REVISION ?= $(shell git rev-parse HEAD 2>/dev/null)
VARIANT ?= cpu
PROFILES ?=
PROFILE_ARGS = $(if $(PROFILES),--profiles "$(PROFILES)",)
STAGING ?= $(if $(filter nvidia,$(VARIANT)),build/staging-nvidia,build/staging)
DIST ?= $(if $(filter nvidia,$(VARIANT)),dist-nvidia,dist)

.PHONY: all verify verify-offline build smoke tools measure package validate test clean

all:
	$(PYTHON) podvm.py all --variant "$(VARIANT)" $(PROFILE_ARGS) --release-version "$(RELEASE_VERSION)" --source-revision "$(SOURCE_REVISION)"

verify:
	$(PYTHON) podvm.py verify --variant "$(VARIANT)" $(PROFILE_ARGS)

verify-offline:
	$(PYTHON) podvm.py verify --variant "$(VARIANT)" $(PROFILE_ARGS) --offline

build: verify
	$(PYTHON) podvm.py build --variant "$(VARIANT)" $(PROFILE_ARGS) --release-version "$(RELEASE_VERSION)" --source-revision "$(SOURCE_REVISION)"

smoke:
	$(PYTHON) podvm.py smoke --variant "$(VARIANT)" $(PROFILE_ARGS)

tools:
	$(PYTHON) podvm.py tools --variant "$(VARIANT)" $(PROFILE_ARGS)

measure:
	$(PYTHON) podvm.py measure --variant "$(VARIANT)" $(PROFILE_ARGS)

package:
	$(PYTHON) podvm.py package --variant "$(VARIANT)" $(PROFILE_ARGS) --release-version "$(RELEASE_VERSION)" --source-revision "$(SOURCE_REVISION)"

validate:
	$(PYTHON) podvm.py validate --variant "$(VARIANT)" $(PROFILE_ARGS) --staging-dir "$(STAGING)" --dist-dir "$(DIST)"

test:
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -rf .work build dist dist-nvidia
