PYTHON ?= python3
RELEASE_VERSION ?= dev
SOURCE_REVISION ?= $(shell git rev-parse HEAD 2>/dev/null)

.PHONY: all verify verify-offline build smoke measure package validate test clean

all:
	$(PYTHON) podvm.py all --release-version "$(RELEASE_VERSION)" --source-revision "$(SOURCE_REVISION)"

verify:
	$(PYTHON) podvm.py verify

verify-offline:
	$(PYTHON) podvm.py verify --offline

build: verify
	$(PYTHON) podvm.py build

smoke:
	$(PYTHON) podvm.py smoke

measure:
	$(PYTHON) podvm.py measure

package:
	$(PYTHON) podvm.py package --release-version "$(RELEASE_VERSION)" --source-revision "$(SOURCE_REVISION)"

validate:
	$(PYTHON) podvm.py validate --staging-dir build/staging --dist-dir dist

test:
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -rf .work build dist
