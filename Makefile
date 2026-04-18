# ──────────────────────────────────────────────────────────────────────
#  GoSigner — cross-platform build system
#
#  Usage:
#      make                 → build the native binary into build/<VERSION>/<host>/
#      make all             → build every supported OS/ARCH into build/<VERSION>/
#      make release         → `make all` + per-target tarball/zip archives
#      make install         → install the native binary to $(PREFIX)/bin
#      make clean           → remove build/
#      make distclean       → remove build/ AND the Go build cache
#      make checksums       → SHA-256 every artifact in build/<VERSION>/
#      make print-targets   → list every OS/ARCH combo this Makefile emits
#      make <goos>-<goarch> → build exactly one target (e.g. `make linux-arm64`)
# ──────────────────────────────────────────────────────────────────────

# ── Project ──────────────────────────────────────────────────────────
BINARY       := gosigner
PKG          := github.com/AzozzALFiras/GoSigner
MAIN_PKG     := .
VERSION      ?= $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)
COMMIT       := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE   := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Go toolchain ─────────────────────────────────────────────────────
GO           ?= go
GO_VERSION   := $(shell $(GO) version 2>/dev/null | awk '{print $$3}')
CGO_ENABLED  ?= 0

# ── Build output layout ──────────────────────────────────────────────
#   build/<version>/<os>-<arch>/gosigner[.exe]
#   build/<version>/checksums.sha256
#   build/<version>/gosigner-<version>-<os>-<arch>.tar.gz  (release)
BUILD_ROOT   := build
VERSION_DIR  := $(BUILD_ROOT)/$(VERSION)

# Host detection (for the default `make` / `make install` target)
HOST_OS      := $(shell $(GO) env GOOS)
HOST_ARCH    := $(shell $(GO) env GOARCH)

# Install prefix for `make install`
PREFIX       ?= /usr/local

# ── Compile-time metadata injected via -ldflags ──────────────────────
LDFLAGS_PKG  := $(PKG)/cli/commands
LDFLAGS      := -s -w \
                -X '$(LDFLAGS_PKG).Version=$(VERSION)' \
                -X '$(LDFLAGS_PKG).Commit=$(COMMIT)' \
                -X '$(LDFLAGS_PKG).BuildDate=$(BUILD_DATE)'

GO_BUILD     := CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -buildvcs=false \
                -ldflags "$(LDFLAGS)" -o

# ── Targets matrix ──────────────────────────────────────────────────
# Every (goos, goarch) combination that the Go toolchain supports natively
# without a C compiler — i.e. every target that `CGO_ENABLED=0 go build` can
# produce from any build host. Covers >95% of real-world deployment:
#
#   Linux:       amd64, arm64, 386, arm (v7), ppc64le, s390x, riscv64, mips64le
#   macOS:       amd64 (Intel), arm64 (Apple Silicon)
#   Windows:     amd64, arm64, 386
#   FreeBSD:     amd64, arm64, 386
#   OpenBSD:     amd64, arm64
#   NetBSD:      amd64, arm64
#   DragonflyBSD amd64
#   Solaris:     amd64
#   illumos:     amd64
#   Plan 9:      amd64
#
TARGETS := \
    linux-amd64    linux-arm64    linux-386       linux-arm \
    linux-ppc64le  linux-s390x    linux-riscv64   linux-mips64le \
    darwin-amd64   darwin-arm64 \
    windows-amd64  windows-arm64  windows-386 \
    freebsd-amd64  freebsd-arm64  freebsd-386 \
    openbsd-amd64  openbsd-arm64 \
    netbsd-amd64   netbsd-arm64 \
    dragonfly-amd64 \
    solaris-amd64 \
    illumos-amd64 \
    plan9-amd64

# Extract GOOS / GOARCH from a "<goos>-<goarch>" target name
os_of       = $(word 1,$(subst -, ,$1))
arch_of     = $(word 2,$(subst -, ,$1))
# GOARM only matters for linux-arm; we default to v7 (Raspberry Pi 2+ / any
# modern ARMv7 board). Override with `make linux-arm GOARM=5` if you need
# Raspberry Pi 1 or similar legacy hardware.
GOARM       ?= 7

# Binary extension for Windows hosts
ext         = $(if $(filter windows,$1),.exe,)

# ── Default target: native build ────────────────────────────────────
.PHONY: default
default: native

.PHONY: native
native:
	@echo ">>> building $(BINARY) $(VERSION) for host ($(HOST_OS)/$(HOST_ARCH))"
	@mkdir -p $(VERSION_DIR)/$(HOST_OS)-$(HOST_ARCH)
	@$(GO_BUILD) $(VERSION_DIR)/$(HOST_OS)-$(HOST_ARCH)/$(BINARY)$(call ext,$(HOST_OS)) $(MAIN_PKG)
	@ln -sf $(HOST_OS)-$(HOST_ARCH)/$(BINARY)$(call ext,$(HOST_OS)) $(VERSION_DIR)/$(BINARY)
	@cp -f $(VERSION_DIR)/$(HOST_OS)-$(HOST_ARCH)/$(BINARY)$(call ext,$(HOST_OS)) $(BINARY)
	@echo ">>> OK → $(VERSION_DIR)/$(HOST_OS)-$(HOST_ARCH)/$(BINARY)$(call ext,$(HOST_OS))"
	@echo ">>> symlinked → ./$(BINARY)"

# ── Per-target rules ─────────────────────────────────────────────────
# Generate a phony rule per GOOS-GOARCH so `make linux-arm64`, `make
# darwin-arm64`, etc. all work.
define build-target
.PHONY: $(1)
$(1):
	@echo ">>> building $$(BINARY) $$(VERSION) for $(call os_of,$(1))/$(call arch_of,$(1))"
	@mkdir -p $$(VERSION_DIR)/$(1)
	@GOOS=$(call os_of,$(1)) GOARCH=$(call arch_of,$(1)) \
	 $$(if $$(filter linux-arm,$(1)),GOARM=$$(GOARM),) \
	 $$(GO_BUILD) $$(VERSION_DIR)/$(1)/$$(BINARY)$(call ext,$(call os_of,$(1))) $$(MAIN_PKG)
	@echo "    → $$(VERSION_DIR)/$(1)/$$(BINARY)$(call ext,$(call os_of,$(1)))"
endef

$(foreach t,$(TARGETS),$(eval $(call build-target,$(t))))

# ── Umbrella targets ─────────────────────────────────────────────────
.PHONY: all
all: $(TARGETS)
	@echo ""
	@echo ">>> built $(words $(TARGETS)) targets into $(VERSION_DIR)/"

.PHONY: release
release: all archives checksums
	@echo ""
	@echo ">>> release $(VERSION) ready in $(VERSION_DIR)/"
	@ls -1 $(VERSION_DIR)/

# Per-target tarballs (.tar.gz) for Unix targets, .zip for Windows.
.PHONY: archives
archives: $(TARGETS)
	@echo ">>> creating release archives"
	@cd $(VERSION_DIR) && for t in $(TARGETS); do \
	  os=$${t%-*}; \
	  bin="$(BINARY)"; \
	  [ "$$os" = "windows" ] && bin="$(BINARY).exe"; \
	  base="$(BINARY)-$(VERSION)-$$t"; \
	  cp -f ../../README.md ../../LICENSE "$$t/" 2>/dev/null || true; \
	  if [ "$$os" = "windows" ]; then \
	    (cd "$$t" && zip -q -9 "../$$base.zip" "$$bin" README.md LICENSE 2>/dev/null) \
	      && echo "    → $(VERSION_DIR)/$$base.zip"; \
	  else \
	    tar -C "$$t" -czf "$$base.tar.gz" "$$bin" README.md LICENSE 2>/dev/null \
	      && echo "    → $(VERSION_DIR)/$$base.tar.gz"; \
	  fi; \
	done

.PHONY: checksums
checksums:
	@echo ">>> computing SHA-256 checksums"
	@cd $(VERSION_DIR) && find . -type f \
	  \( -name "$(BINARY)" -o -name "$(BINARY).exe" -o -name "*.tar.gz" -o -name "*.zip" \) \
	  -not -name "checksums.sha256" \
	  | sort | xargs -I{} sha256sum {} > checksums.sha256
	@echo "    → $(VERSION_DIR)/checksums.sha256"
	@cat $(VERSION_DIR)/checksums.sha256

# ── Convenience ──────────────────────────────────────────────────────
.PHONY: install
install: native
	@echo ">>> installing $(BINARY) to $(PREFIX)/bin/"
	@install -d "$(PREFIX)/bin"
	@install -m 0755 $(VERSION_DIR)/$(HOST_OS)-$(HOST_ARCH)/$(BINARY)$(call ext,$(HOST_OS)) \
	  "$(PREFIX)/bin/$(BINARY)"
	@echo ">>> installed: $(PREFIX)/bin/$(BINARY)"

.PHONY: uninstall
uninstall:
	@rm -fv "$(PREFIX)/bin/$(BINARY)"

.PHONY: test
test:
	@$(GO) test -count=1 ./...

.PHONY: vet
vet:
	@$(GO) vet ./...

.PHONY: fmt
fmt:
	@$(GO) fmt ./...

.PHONY: tidy
tidy:
	@$(GO) mod tidy

.PHONY: clean
clean:
	@rm -rf $(BUILD_ROOT) $(BINARY) $(BINARY).exe
	@echo ">>> cleaned $(BUILD_ROOT)/ and host binary"

.PHONY: distclean
distclean: clean
	@$(GO) clean -cache -modcache 2>/dev/null || true
	@echo ">>> cleared Go build + module caches"

.PHONY: print-targets
print-targets:
	@echo "supported targets ($(words $(TARGETS))):"
	@printf "  %s\n" $(TARGETS)

.PHONY: info
info:
	@echo "GoSigner build info"
	@echo "  version:     $(VERSION)"
	@echo "  commit:      $(COMMIT)"
	@echo "  build date:  $(BUILD_DATE)"
	@echo "  go:          $(GO_VERSION)"
	@echo "  host:        $(HOST_OS)/$(HOST_ARCH)"
	@echo "  build root:  $(VERSION_DIR)/"
	@echo "  targets:     $(words $(TARGETS))"

.PHONY: help
help:
	@awk 'BEGIN{FS=":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Common commands:"
	@echo "  make                 build native binary"
	@echo "  make all             build every supported OS/ARCH"
	@echo "  make release         build all + create tarballs + checksums"
	@echo "  make linux-arm64     build a single specific target"
	@echo "  make install         install to \$$(PREFIX)/bin (default /usr/local/bin)"
	@echo "  make print-targets   list every supported OS/ARCH"
	@echo "  make clean           remove build/"
