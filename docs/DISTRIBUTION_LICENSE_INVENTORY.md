# Distribution and license inventory

Reviewed 2026-11-24 against source revision
`0e51ef15cda080c53d52942551fc53265577692f`. This inventory ties committed
inputs to distribution paths and records which facts have artifact evidence.
A verified upstream license and a complete release obligation review are
separate decisions. Resolve open entries against the exact build being shipped.

## Go binaries

[go.mod](../go.mod) and [go.sum](../go.sum) name one external module,
`golang.org/x/sys v0.50.0`. The module download matched both committed Go
checksums. Its BSD-3-Clause text requires the copyright, conditions, and
disclaimer to accompany binary redistribution.
[Upstream license](https://raw.githubusercontent.com/golang/sys/v0.50.0/LICENSE)

A local Go 1.26.4 dependency graph for agent and sensor entry points, with CGO
disabled, located `x/sys/windows` and related service and registry packages on
Windows amd64, and `x/sys/unix` on Linux amd64. Darwin amd64 and arm64 showed no
direct `v0.50.0` import in those graphs. All four target graphs included Go
standard library packages and toolchain-vendored code from the modules below.
These are package-resolution observations. The release build's toolchain
version and binary SBOM still need to be recorded.

| Component | Observed version | License | Distribution |
| --- | --- | --- | --- |
| Go runtime and standard library | 1.26.4 local toolchain | BSD-3-Clause | Compiled into binaries. [Go license](https://raw.githubusercontent.com/golang/go/go1.26.4/LICENSE) |
| Toolchain-vendored `golang.org/x/crypto` | `v0.46.1-0.20251210140736-7dacc380ba00` | BSD-3-Clause | Standard library dependency. [Go vendor license](https://github.com/golang/go/blob/go1.26.4/src/vendor/golang.org/x/crypto/LICENSE) |
| Toolchain-vendored `golang.org/x/net` | `v0.47.1-0.20260417193450-705de46f8788` | BSD-3-Clause | Standard library dependency. [Go vendor license](https://github.com/golang/go/blob/go1.26.4/src/vendor/golang.org/x/net/LICENSE) |
| Toolchain-vendored `golang.org/x/sys` | `v0.39.0` | BSD-3-Clause | Standard library dependency. [Go vendor license](https://github.com/golang/go/blob/go1.26.4/src/vendor/golang.org/x/sys/LICENSE) |
| Toolchain-vendored `golang.org/x/text` | `v0.32.0` | BSD-3-Clause | Standard library dependency. Verify additional upstream data notices for generated Unicode tables. [Go vendor license](https://github.com/golang/go/blob/go1.26.4/src/vendor/golang.org/x/text/LICENSE) |

The [notice file](../THIRD_PARTY_NOTICES.md) reproduces the common verified
license text for these Go sources. Recheck generated tables, toolchain changes,
and all other Go entry points if included in a release.

## Python backend

The [direct requirements](../backend/requirements.in) resolve to 26 hash-locked
pins in [requirements.txt](../backend/requirements.txt). Each row links to
versioned package metadata. A matching pure Python or Linux x86-64 CPython 3.12
compatible wheel was downloaded in memory, verified against its lock hash, and
inspected for license files and separately shipped native libraries. This
samples one eligible artifact per pin. It does not determine the exact wheel
selected by every platform or capture all statically linked components.

| Locked package | Version | Top-level license | Distribution review |
| --- | --- | --- | --- |
| [annotated-doc](https://pypi.org/project/annotated-doc/0.0.4/) | 0.0.4 | MIT | Transitive. Keep the wheel's license and any applicable notices. |
| [annotated-types](https://pypi.org/project/annotated-types/0.7.0/) | 0.7.0 | MIT | Transitive. Keep the wheel's license and any applicable notices. |
| [anyio](https://pypi.org/project/anyio/4.14.2/) | 4.14.2 | MIT | Transitive. Keep the wheel's license and any applicable notices. |
| [cffi](https://pypi.org/project/cffi/2.1.0/) | 2.1.0 | MIT-0 | Transitive. Keep the wheel's license and any applicable notices. |
| [click](https://pypi.org/project/click/8.4.2/) | 8.4.2 | BSD-3-Clause | Transitive. Keep the wheel's license and any applicable notices. |
| [cryptography](https://pypi.org/project/cryptography/50.0.2/) | 50.0.2 | Apache-2.0 OR BSD-3-Clause | Direct. Native extension. Verify the statically bundled cryptographic library and build notices. |
| [fastapi](https://pypi.org/project/fastapi/0.141.1/) | 0.141.1 | MIT | Direct. |
| [greenlet](https://pypi.org/project/greenlet/3.5.3/) | 3.5.3 | MIT AND PSF-2.0 | Retain both license files. |
| [h11](https://pypi.org/project/h11/0.16.0/) | 0.16.0 | MIT | Transitive. Keep the wheel's license and any applicable notices. |
| [httptools](https://pypi.org/project/httptools/0.8.0/) | 0.8.0 | MIT | Wheel includes notices for vendored http-parser and llhttp. |
| [idna](https://pypi.org/project/idna/3.18/) | 3.18 | BSD-3-Clause | Verify generated Unicode data notices. |
| [packaging](https://pypi.org/project/packaging/26.3/) | 26.3 | Apache-2.0 OR BSD-2-Clause | Direct. Check generated SPDX data provenance and notices. |
| [psycopg2-binary](https://pypi.org/project/psycopg2-binary/2.9.13/) | 2.9.13 | LGPL-3.0-or-later with OpenSSL exception | Direct. Weak copyleft. Wheel ships separate native libraries. See below. |
| [pycparser](https://pypi.org/project/pycparser/3.0/) | 3.0 | BSD-3-Clause | Transitive. Keep the wheel's license and any applicable notices. |
| [pydantic](https://pypi.org/project/pydantic/2.14.4/) | 2.14.4 | MIT | Direct. |
| [pydantic-core](https://pypi.org/project/pydantic-core/2.50.5/) | 2.50.5 | MIT | Native extension. Resolve linked Rust crates and notices. |
| [pydantic-settings](https://pypi.org/project/pydantic-settings/2.15.0/) | 2.15.0 | MIT | Direct. |
| [python-dotenv](https://pypi.org/project/python-dotenv/1.2.4/) | 1.2.4 | BSD-3-Clause | Direct. |
| [pyyaml](https://pypi.org/project/pyyaml/6.0.3/) | 6.0.3 | MIT | Native wheel. Check bundled LibYAML version and notice. |
| [sqlalchemy](https://pypi.org/project/sqlalchemy/2.0.52/) | 2.0.52 | MIT | Direct. Confirm the installed wheel variant. |
| [starlette](https://pypi.org/project/starlette/1.3.1/) | 1.3.1 | BSD-3-Clause | Transitive. Keep the wheel's license and any applicable notices. |
| [typing-extensions](https://pypi.org/project/typing-extensions/4.16.0/) | 4.16.0 | PSF-2.0 | Transitive. Keep the wheel's license and any applicable notices. |
| [typing-inspection](https://pypi.org/project/typing-inspection/0.4.5/) | 0.4.5 | MIT | Transitive. Keep the wheel's license and any applicable notices. |
| [uvicorn](https://pypi.org/project/uvicorn/0.54.0/) | 0.54.0 | BSD-3-Clause | Direct with standard extras. |
| [uvloop](https://pypi.org/project/uvloop/0.22.1/) | 0.22.1 | MIT OR Apache-2.0 | Wheel carries both license texts. Verify vendored libuv and its separate notices. |
| [watchfiles](https://pypi.org/project/watchfiles/1.2.0/) | 1.2.0 | MIT | Native extension. Resolve linked Rust crates and notices. |
| [websockets](https://pypi.org/project/websockets/16.1.1/) | 16.1.1 | BSD-3-Clause | Confirm the installed wheel variant. |

The listed top-level terms are permissive except for the driver marked weak
copyleft. Component conclusions remain open where compiled or generated
material carries its own terms.

The sampled Linux `psycopg2-binary` wheel is
`psycopg2_binary-2.9.13-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`.
The backend loads the driver in-process. The wheel includes a Python extension
and 15 shared libraries in `psycopg2_binary.libs`. The OpenSSL exception
addresses a specific linking case. The review still needs the licenses and
obligation evidence of every included library.
[Psycopg license and exception](https://www.psycopg.org/docs/license.html)
[Psycopg binary packaging](https://www.psycopg.org/docs/install.html#binary-install-from-pypi)

| Shared libraries observed | Upstream context | Exact wheel decision |
| --- | --- | --- |
| `libpq` | PostgreSQL License, permissive. [Official license](https://www.postgresql.org/about/licence/) | Review required. Identify the exact version, platform patches, and notice. |
| `libcrypto`, `libssl` | Apache-2.0 for the upstream OpenSSL 3.0 series. [Upstream license](https://github.com/openssl/openssl/blob/openssl-3.0/LICENSE.txt) | Review required. Verify actual 3.x versions and corresponding notices. |
| `libkrb5`, `libkrb5support`, `libk5crypto`, `libgssapi_krb5` | MIT Kerberos publishes a package-wide collection of notices. [Upstream notices](https://web.mit.edu/kerberos/krb5-latest/doc/mitK5license.html) | Review required. Map wheel builds to exact source packages and their notices. |
| `liblber`, `libldap` | OpenLDAP Public License. [Official license](https://www.openldap.org/software/release/license.html) | Review required. Verify the actual license revision and notice set for the shipped libraries. |
| `libcrypt`, `libkeyutils`, `libcom_err`, `libpcre`, `libsasl2`, `libselinux` | Names recovered from the wheel. | Unknown for the exact builds. Obtain source package identities and versions, including evidence for any weak copyleft libraries and exceptions. |

**Release blocker for a redistributed backend image.** Preserve wheel license
materials, verify the platform's exact native closure, and record how
applicable LGPL, accompanying source, notice, and relinking requirements will
be fulfilled. Before distribution, record the license and copyright materials to deliver,
the corresponding source for the LGPL-covered library and local modifications,
and the chosen replacement or relinking mechanism where applicable. The
OpenSSL exception does not resolve the terms of other bundled libraries.
Qualified counsel should review the exception and the proposed distribution
method. Track cryptographic libraries in other wheels separately even if they
share a project name. [GNU LGPL version 3](https://www.gnu.org/licenses/lgpl-3.0.html)

## Collector, browser, and build tooling

| Surface | Evidence | Distribution disposition |
| --- | --- | --- |
| Python collector | [Collector manifest](../collector/pyproject.toml) declares no runtime dependencies and uses `setuptools>=68` to build. The reviewed source uses Python standard library and system tools for platform observation. [Collector implementation](../collector/openassetwatch_collector/main.py) | Operator's Python and host utilities are prerequisites. A collector wheel or bundled Python environment would need inspected license contents and artifact metadata. The manifest has no explicit project license field. |
| Control Tower browser assets | Inline JavaScript, CSS, HTML and system font stacks in [index.html](../backend/app/static/index.html). No tracked `package.json`, `pnpm-lock.yaml`, JavaScript bundler lock, npm runtime tree, or downloaded font was found. | The browser receives the first-party static page. |
| Generated API documentation | The [hub entry point](../backend/app/main.py) uses the framework defaults. The locked wheel references CDN-hosted Swagger UI 5 (Apache-2.0), ReDoc 2 (MIT), and a remote framework favicon. [Swagger UI license](https://github.com/swagger-api/swagger-ui/blob/main/LICENSE) [ReDoc license](https://github.com/Redocly/redoc/blob/main/LICENSE) | The API documentation page directs the browser to fetch these assets. The project does not bundle those CDN assets in its tracked dashboard. The major-version URLs float. Pin and review the exact bytes, licenses and attribution if self-hosting or redistributing them. Favicon provenance would need separate verification for bundling. |
| Diagrams, templates, examples and fixtures | [Architecture assets](architecture/assets/) contain first-party HTML and SVG. Source includes first-party sample configs, schemas, and synthetic sensor and advisory fixtures. | No packaged font binaries or separate image/icon libraries were identified in the tracked asset inventory. Verify provenance again if adding generated or external assets. |
| Build and CI tooling | Go compiler, Python packaging tooling, PowerShell and tar, native packaging tools, GitHub Actions, and source SBOM tooling. [Release workflow](../.github/workflows/agent-release.yml) | Separate build environment. Inventory any tool-supplied code that actually enters outputs. Check CI dependencies independently of product dependencies. |
| WiX 6.0.2 and Util extension | [Tool manifest](../.config/dotnet-tools.json), [MSI builder](../scripts/release/build_agent_msi.ps1), [MSI source](../packaging/agent/windows/OpenAssetWatchAgent.wxs). Util-based service and security actions can place tool-supplied custom actions in the MSI. | Review required. Upstream identifies MS-RL for source and separate maintenance-fee terms for official binary tooling. Inspect the MSI tables and redistribution terms for embedded actions. Record applicable fee, permissions, and notice decision before commercial use. [Versioned tool package](https://www.nuget.org/packages/wix/6.0.2) [Versioned extension package](https://www.nuget.org/packages/WixToolset.Util.wixext/6.0.2) |

## Container inputs

The [current Compose stack](../docker-compose.yml) references standalone
`postgres:16` and `nginx:1.27-alpine` images alongside the local backend. The
[backend Dockerfile](../backend/Dockerfile) inherits `python:3.12-slim`,
installs the locked Python dependencies, and copies application code and its
static UI. The backend build context does not include the root license or
notice files and the Dockerfile has no explicit copy for them. None of these
references pins the underlying image digest.

| Input | Role and upstream terms | Artifact-level review |
| --- | --- | --- |
| `python:3.12-slim` | Base layers, CPython and preinstalled utilities and packages. CPython ships a license bundle. [CPython license](https://github.com/python/cpython/blob/3.12/LICENSE) | Inspect the exact architecture and digest, packages, Python/pip tooling, native libraries, notices and source availability. A base does not inherit the application's license. |
| `postgres:16` and legacy `postgres:16-alpine` | Separate PostgreSQL process. PostgreSQL License applies to server code. [Official license](https://www.postgresql.org/about/licence/) | Inspect the exact image and its OS packages. Pulling an upstream image and redistributing it through a bundle or mirror are distinct delivery paths. |
| `nginx:1.27-alpine` | Separate static web server. NGINX upstream license is BSD-2-Clause. [Official license](https://nginx.org/LICENSE) | Inspect image packages, entrypoint scripts, modules and the healthcheck's `wget` provider. BusyBox upstream uses GPLv2. Verify whether that or other strong copyleft code is in the resolved image and document accompanying source for any redistributed copy. [BusyBox license](https://www.busybox.net/license.html) |
| Legacy `redis:7-alpine` | Separate container in the [legacy installer scaffold](../installers/docker/docker-compose.yml), outside the current hub stack. The observed tag resolves to Redis 7.4.12. Its source release offers RSALv2 or SSPLv1. [Versioned license](https://github.com/redis/redis/blob/7.4.12/LICENSE.txt) | Release blocker for bundling, mirroring, or commercial hosted use of this legacy service until the selected terms and exact image are approved. |
| Legacy `ghcr.io/openassetwatch/oaw-server:foundation` | Separate referenced application image in the same scaffold. | Anonymous manifest access returned HTTP 401. Image digest, contents, and provenance remain unverified. Resolve them before offering this legacy application image. |

### Legacy service tag resolution

On 2026-11-24, the registry reported the same image index digest for
`redis:7-alpine` and `redis:7.4.12-alpine`
(`sha256:7f7d30b7fdd09467bac58198a1f166dd69789d348d4fe859cccb20e0cf287fbe`).
It also reported the same index digest for `postgres:16-alpine` and
`postgres:16.16-alpine`
(`sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d`).
PostgreSQL 16.16 carries the PostgreSQL License for its server code. These
are registry observations. The legacy references still float, and the
per-platform image package closures require review before redistribution.
[Redis registry metadata](https://hub.docker.com/v2/repositories/library/redis/tags/7-alpine)
[PostgreSQL registry metadata](https://hub.docker.com/v2/repositories/library/postgres/tags/16-alpine)
[PostgreSQL 16.16 copyright](https://github.com/postgres/postgres/blob/REL_16_16/COPYRIGHT)

### Cached image evidence

A read-only SPDX scan inspected four locally cached Linux amd64 images.
These digests report what was present in the cache on the review date. They
do not establish what a fresh build resolves or what a release ships.
Package counts include the OCI package record and other scanner findings.

| Cached reference | Reported digest | SPDX packages | Selected observations |
| --- | --- | --- | --- |
| `openassetwatch-control-tower-backend:local` | `sha256:bf7f428b0b817ca5b84d27eeea7b47cfc2567a277bed16bef29db1526fdf75db` | 133, including 92 Debian and 30 PyPI records | This cache uses `psycopg2-binary 2.9.12` and `cryptography 50.0.0`. The current lock uses 2.9.13 and 50.0.2. Treat the cached image as an older build. |
| `python:3.12-slim` | `sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203` | 104, including 92 Debian records | Includes `dpkg 1.22.22`, `coreutils 9.7-3`, Bash, and the GNU C library. Package notices contain GPL and LGPL terms. Verify individual file terms and corresponding source for redistribution. |
| `postgres:16` | `sha256:4b7183ac05f8ef417db21fd72d71047a4238340c261d3cc3ddb6d579ab5071ae` | 157, including 147 Debian and 4 Go records | Includes `postgresql-16 16.14-1.pgdg13+1`, separately packaged client libraries, and GPL base utilities. Review all layers if redistributing this image. |
| `nginx:1.27-alpine` | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | 69, including 68 Alpine records | Contains NGINX 1.27.5-r1, musl, OpenSSL, and GPL-2.0-only declarations for BusyBox 1.37.0-r12 and apk-tools 2.14.6-r3. The scan did not resolve the full Alpine NGINX package license expression. |

The scan reads image package metadata. Scanner license expressions are
evidence to reconcile with versioned upstream and image-level license
material. Reproduce a snapshot with
`syft scan docker:<local-image-reference> -o spdx-json` and verify the resolved
image ID and architecture before comparing it with this table.

A repository SBOM cannot identify the OS package closure of a particular image.
Generate SBOMs from the actual image digests per architecture, inspect installed
package copyright files and image layer contents, and keep verified copies of
materials required by each distribution channel. These image-level checks
remain open.

## Installer and release inventory

Project source archives contain the tracked [LICENSE](../LICENSE),
[NOTICE](../NOTICE), [DCO](../DCO) and [brand policy](../TRADEMARKS.md).
The [release workflow](../.github/workflows/agent-release.yml) assembles
native agent artifacts with version, Git revision, package type, SHA-256
and signature metadata. A format's metadata declaration is separate from
its actual payload. A local Windows amd64 TAR.GZ archive inspection
confirmed it contains the binary, manifest, checksum, and README, with no
project license or notice files. A local Linux amd64 DEB passed the repository
package validator and contained the project license, notice, and copyright
files. The DEB lacked the third-party notice artifact. Both sample manifests
declared Apache-2.0. They establish the payloads produced by those local
builds.

| Format | Observed material | Release readiness |
| --- | --- | --- |
| Go agent binary dist | Platform binary, SHA-256 and JSON manifest. [Builder](../scripts/release/build_agent_dist.ps1) | Project and third-party texts are absent from the dist set. |
| TAR.GZ | Agent binary, binary digest, manifest and README. [Builder](../scripts/release/package_agent_targz.ps1) | Project license, NOTICE and linked Go attributions are absent from the archive path. |
| DEB | Agent binary and symlink, configuration/identity examples, service and timer, scoped sudo/helper scripts, maintainer scripts, copyright, project LICENSE/NOTICE, and manifest. Host `systemd`, `passwd` and system `ip` are dependencies or prerequisites. [Linux packaging](../scripts/release/linux_packaging.py) | Verify final bytes. Add required Go notices. Record release-level SBOM and signature evidence. |
| RPM | Agent binary, examples, systemd metadata, helpers and sudoers, ownership and lifecycle scriptlets, project LICENSE/NOTICE, checksums and manifests. [RPM spec](../packaging/agent/linux/rpm/openassetwatch-agent.spec.in) | Verify final bytes. Add required Go notices. Record release-level SBOM and signature evidence. |
| Windows MSI | Agent binary, compressed payload, example configs, ACL/service/event metadata, embedded custom actions, checksum and manifest. [MSI source](../packaging/agent/windows/OpenAssetWatchAgent.wxs) | Project and Go notices missing from the package definition. Review exact tool-supplied embedded code and signing. |
| macOS PKG | Agent binary, examples and manifest, LaunchDaemon, pre/post-install scripts, receipt/signing and notarization paths. [Builder](../scripts/release/build_agent_macos_pkg.sh) [Stager](../scripts/release/stage_agent_macos_install.py) | Project and Go notices missing from the staged payload. Verify signed outputs and notarization evidence on macOS. |
| Linux sensor | Binary supplied to local installer, systemd unit, configuration example, and state layout. [Sensor installer](../scripts/release/install_sensor_linux.py) | Separate deployment path without a reviewed release bundle. Include project license and applicable Go notices and verify binary and installer provenance before distribution. |
| Collector | Local install scripts create a runtime environment and service registration. [Collector installer](../collector/install/install.py) | Verify any future standalone wheel, installer, or bundled interpreter and preserve project and dependency notices. |
| Legacy installer and container scaffolds | Source scripts and service/Compose examples. [Installer overview](INSTALLERS.md) | Keep production claims limited to supported assets. Review legacy source or image distribution if offered. |

## External and generated material

- The [Source Licensing Registry](SOURCE_LICENSING_REGISTRY.md) records narrow
  approvals for normalized `PYSEC-*` data with verified source links and for
  the reviewed CISA KEV path. Their license, provenance and attribution belong
  with their catalog and mirror artifacts.
- Synthetic signed catalog examples and product-owned synthetic vendor,
  advisory, and passive-sensor fixtures belong to the repository. Candidate
  OUI, fingerprint, external rule, and advisory datasets remain subject to the
  registry. No production redistribution of the candidate fingerprint or OUI
  corpora was identified by the scoped repository review.
- Schema files, rules, templates, and examples are inspectable in the source.
  Review upstream terms for content generated from external data and for any
  upstream-generated table embedded in a binary or wheel.
- Local inference is an optional external runtime boundary. The source
  repository does not ship model weights. A separately supplied inference
  runtime or weight artifact needs its own version-specific review before
  packaging or commercial hosting. [Model artifact provenance](../backend/app/model_artifact_provenance.py)
