# SPDX-License-Identifier: GPL-2.0-or-later
LOCAL_GOOSE := $(abspath .goose-toolchain/goose)
PARENT_GOOSE := $(abspath ../.goose-toolchain/goose)
GOOSE ?= $(if $(wildcard $(LOCAL_GOOSE)),$(LOCAL_GOOSE),$(if $(wildcard $(PARENT_GOOSE)),$(PARENT_GOOSE),goose))
BUILD_DIR ?= build
GOOSE_HOME ?= $(BUILD_DIR)/goose-home
SOURCE := src/gobjtool.goose
MODEL_CHECK := tests/model_check.goose
TARGET := $(BUILD_DIR)/gobjtool

export GOOSE_HOME

.PHONY: all check build test corpus decoder-oracle clean

all: build

check:
	$(GOOSE) check $(SOURCE)
	$(GOOSE) check $(MODEL_CHECK)

build:
	mkdir -p $(BUILD_DIR)
	$(GOOSE) build -o $(TARGET) $(SOURCE)

test:
	GOOSE=$(GOOSE) BUILD_DIR=$(abspath $(BUILD_DIR)/test) tests/run.sh

corpus: build
	@test -n "$(KERNEL_BUILD)" || \
		(echo "set KERNEL_BUILD=/path/to/x86-kernel-build" >&2; exit 2)
	python3 tests/corpus.py $(TARGET) $(KERNEL_BUILD)

decoder-oracle: build
	@test -n "$(KERNEL_BUILD)" || \
		(echo "set KERNEL_BUILD=/path/to/x86-kernel-build" >&2; exit 2)
	python3 tests/decoder-oracle.py --gobjtool $(TARGET) \
		$(if $(LINUX_DECODER),--linux-decoder $(LINUX_DECODER),) \
		$(if $(OBJDUMP),--objdump $(OBJDUMP),) $(KERNEL_BUILD)

clean:
	rm -rf -- "$(CURDIR)/$(BUILD_DIR)"
