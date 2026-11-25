# Third-party notices

## Go-derived binaries

The following single license text applies to the Go runtime and standard
library in the reviewed Go 1.26.4 toolchain, the portions of
`golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sys`, and
`golang.org/x/text` included through that toolchain, and the
`golang.org/x/sys v0.50.0` module where compiled into a target binary.

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Entries requiring release review

- Confirm the complete notice set against the actual Go toolchain, target and
  generated assets in the distributed binary.
- The backend image must preserve the applicable Python wheel license
  material. The licenses and attribution for all bundled native libraries and
  base image components require review against the exact image digest.
- Windows MSI embedded custom actions and other tool-supplied payloads require
  an artifact-level inventory and attribution review.
- Distributed advisory and lifecycle data retain the notices and provenance
  applicable to their specific catalog and source.

See the [distribution inventory](docs/DISTRIBUTION_LICENSE_INVENTORY.md)
and the [Source Licensing Registry](docs/SOURCE_LICENSING_REGISTRY.md).
