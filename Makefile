PYTHON ?= python3
RELEASE_VERSION ?= dev
SOURCE_REVISION ?= $(shell git rev-parse HEAD 2>/dev/null)
PROFILES ?= config/launch-profiles.yaml

.PHONY: all verify verify-offline build smoke measure package validate test clean

all:
	$(PYTHON) podvm.py all --profiles "$(PROFILES)" --release-version "$(RELEASE_VERSION)" --source-revision "$(SOURCE_REVISION)"

verify:
	$(PYTHON) podvm.py verify --profiles "$(PROFILES)"

verify-offline:
	$(PYTHON) podvm.py verify --profiles "$(PROFILES)" --offline

build: verify
	$(PYTHON) podvm.py build --profiles "$(PROFILES)"

smoke:
	$(PYTHON) podvm.py smoke --profiles "$(PROFILES)"

measure:
	$(PYTHON) podvm.py measure --profiles "$(PROFILES)"

package:
	$(PYTHON) podvm.py package --profiles "$(PROFILES)" --release-version "$(RELEASE_VERSION)" --source-revision "$(SOURCE_REVISION)"

validate:
	$(PYTHON) podvm.py validate --profiles "$(PROFILES)" --staging-dir build/staging --dist-dir dist

test:
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -rf .work build dist
