# Local Development Setup

This guide describes the current local validation setup for OpenAssetWatch on
Windows. It keeps generated dependencies out of Git and avoids adding product
features.

## Go Setup

Install Go for Windows, then verify it:

```powershell
go version
where.exe go
```

If the current shell does not resolve `go` through PATH, use the installed
binary directly:

```powershell
& 'C:\Program Files\Go\bin\go.exe' version
```

Format and test the Go foundation:

```powershell
gofmt -w cmd internal pkg
go test ./...
```

Equivalent absolute-path commands:

```powershell
& 'C:\Program Files\Go\bin\gofmt.exe' -w cmd internal pkg
& 'C:\Program Files\Go\bin\go.exe' test ./...
```

## Windows Go Cache Workaround

In the Codex Windows environment, `go test ./...` hit an access denied error
creating the default cache under:

```text
%LOCALAPPDATA%\go-build
```

Use writable temp cache directories when needed:

```powershell
$env:GOCACHE = Join-Path $env:TEMP 'oaw-system-go-cache'
$env:GOMODCACHE = Join-Path $env:TEMP 'oaw-system-go-modcache'
& 'C:\Program Files\Go\bin\go.exe' test ./...
```

For CI or Codex automation, set `GOCACHE` and `GOMODCACHE` to a writable
workspace, runner, or temp path before running Go tests.

## Python Setup

System `python` and `pip` may not be available on PATH in the Codex Windows
environment. Use a normal Python 3.10+ install when available. In this
workspace, validation used the bundled Codex Python runtime to create a
project-local `.venv/`.

Create the venv:

```powershell
%USERPROFILE%\.cache\codex-runtimes\<runtime>\dependencies\python\python.exe -m venv <project-root>\.venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install backend dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

The collector currently has `collector/pyproject.toml` and no additional
runtime dependency file.

## Python Validation

Run collector tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s collector\tests -t collector
```

Run backend tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend\tests -t backend
```

Run the backend startup import check:

```powershell
$env:PYTHONPATH = 'backend'
.\.venv\Scripts\python.exe -c "from app.main import app; print(app.title); print(app.version)"
```

## Git Hygiene

Do not commit generated environments or caches. `.gitignore` excludes `.venv/`,
Python cache directories, pytest cache, build/dist output, and local Go cache
directories.
