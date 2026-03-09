# Open Source Licenses

This document lists open-source components used by `pamelo-pam-fido2`.

## 1. Components bundled in build/distribution artifacts

### 1.1 libfido2
- Component: `libfido2`
- Upstream: https://github.com/Yubico/libfido2
- Included from: `third_party/libfido2` (git submodule)
- Current submodule revision: `8f4abc1852f6` (`1.16.0-61-g8f4abc1`)
- How used: built from source and statically linked into `pamelo_pam_fido2.so`
- License: BSD 2-Clause
- License file in repo: `third_party/libfido2/LICENSE`

BSD 2-Clause license text (from `third_party/libfido2/LICENSE`):

```text
Copyright (c) 2018-2025 Yubico AB. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SPDX-License-Identifier: BSD-2-Clause
```

## 2. Runtime/system dependencies (not bundled in this repository)

These dependencies are required by `libfido2` and/or runtime linking on Linux, but are generally supplied by the target OS packages (for example Debian/Ubuntu packages), not vendored in this repository:

- OpenSSL (`libcrypto`) — Apache License 2.0
- libcbor — MIT License
- zlib — zlib License
- libudev (systemd project, Linux) — LGPL-2.1-or-later

Source references:
- `third_party/libfido2/README.adoc` (dependency list)
- `third_party/libfido2/CMakeLists.txt` (dependency detection)
- `Makefile` (`CGO_LDFLAGS`: `-lcrypto -lcbor -lz -ludev`)

## 3. Go dependencies

`go.mod` currently declares no third-party Go modules; the project uses the Go standard library plus internal packages.
