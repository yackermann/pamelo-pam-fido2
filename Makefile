SHELL := /bin/bash

OUTPUT_DIR ?= dist
MODULE_SO ?= $(OUTPUT_DIR)/pam_fido2_server.so
CONFIGURATOR_BIN ?= $(OUTPUT_DIR)/pamfido2-configurator
GO_BUILD_TAGS ?= pam libfido2
GOCACHE ?= $(CURDIR)/.cache/go-build
LIBFIDO2_SUBMODULE_DIR ?= third_party/libfido2
LIBFIDO2_BUILD_DIR ?= $(CURDIR)/.cache/libfido2/build
LIBFIDO2_INSTALL_DIR ?= $(CURDIR)/.cache/libfido2/install
LIBFIDO2_STATIC_LIB ?= $(LIBFIDO2_INSTALL_DIR)/lib/libfido2.a
LIBFIDO2_CFLAGS ?= -I$(LIBFIDO2_INSTALL_DIR)/include
LIBFIDO2_LDFLAGS ?= $(LIBFIDO2_STATIC_LIB) -lcrypto -lcbor -lz -ludev

.PHONY: test build clean submodule libfido2 check-build-tools dpkg
OEM_FOLDER ?= examples/oem

test:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) go test ./...

submodule:
	@if [ -f "$(LIBFIDO2_SUBMODULE_DIR)/CMakeLists.txt" ]; then \
		echo "submodule source present: $(LIBFIDO2_SUBMODULE_DIR)"; \
	else \
		git submodule update --init --recursive $(LIBFIDO2_SUBMODULE_DIR); \
	fi

check-build-tools:
	@command -v cmake >/dev/null || (echo "cmake is required. Install it (Ubuntu: apt install cmake)." && exit 1)
	@command -v pkg-config >/dev/null || (echo "pkg-config is required. Install it (Ubuntu: apt install pkg-config)." && exit 1)

$(LIBFIDO2_STATIC_LIB): submodule check-build-tools
	mkdir -p $(LIBFIDO2_BUILD_DIR)
	mkdir -p $(LIBFIDO2_INSTALL_DIR)
	cmake -S $(LIBFIDO2_SUBMODULE_DIR) -B $(LIBFIDO2_BUILD_DIR) \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
		-DCMAKE_INSTALL_PREFIX=$(LIBFIDO2_INSTALL_DIR) \
		-DBUILD_SHARED_LIBS=OFF \
		-DBUILD_STATIC_LIBS=ON \
		-DBUILD_TESTS=OFF \
		-DBUILD_EXAMPLES=OFF \
		-DBUILD_TOOLS=OFF \
		-DBUILD_MANPAGES=OFF \
		-DUSE_PCSC=OFF
	cmake --build $(LIBFIDO2_BUILD_DIR) --target fido2
	cmake --install $(LIBFIDO2_BUILD_DIR)

libfido2: $(LIBFIDO2_STATIC_LIB)

build: libfido2
	mkdir -p $(OUTPUT_DIR)
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) CGO_ENABLED=1 CGO_CFLAGS="$(LIBFIDO2_CFLAGS)" CGO_LDFLAGS="$(LIBFIDO2_LDFLAGS)" go build -buildmode=c-shared -tags "$(GO_BUILD_TAGS)" -o $(MODULE_SO) ./cmd/pam_fido2_server
	GOCACHE=$(GOCACHE) CGO_ENABLED=0 go build -o $(CONFIGURATOR_BIN) ./cmd/pamfido2-configurator
	@# Keep deployment artifact to one file.
	rm -f $(OUTPUT_DIR)/pam_fido2_server.h

clean:
	rm -rf $(OUTPUT_DIR) $(LIBFIDO2_BUILD_DIR) $(LIBFIDO2_INSTALL_DIR)

dpkg:
	./scripts/make-dpkg.sh $(OEM_FOLDER)
