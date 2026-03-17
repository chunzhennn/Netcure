# Netcure

Netcure is a Windows network diagnostics application that collects system, adapter, Wi-Fi, routing, ping, and proxy data, then generates both JSON and standalone HTML reports.

## What It Does

- Enumerates network adapters and their addressing details
- Collects host environment information such as computer name, OS, architecture, and adapter models
- Inspects Wi-Fi connection state and nearby networks
- Captures IPv4 and IPv6 routing tables
- Runs ping diagnostics against configured targets
- Checks proxy-related settings
- Produces:
  - `netcure-report.json`
  - `netcure-report.html`

The HTML report is rendered by an embedded Vue frontend and is bundled into the native application during build.

## Repository Layout

```text
Netcure.sln                Visual Studio solution
Netcure/                   Native Windows application
Netcure/checkers/          Diagnostic modules
Netcure/report/            JSON and HTML report generation
frontend/                  Embedded Vue frontend for the HTML report
frontend/src/              Vue app source
frontend/scripts/          Frontend build helpers
```

## Requirements

- Windows
- Visual Studio with C++ desktop development tools, or MSBuild-compatible Build Tools
- Node.js and npm for the embedded frontend build

## Build

Build the full solution from the repository root:

```powershell
msbuild Netcure.sln /p:Configuration=Release /p:Platform=x64
```

The native project automatically runs:

```powershell
powershell -ExecutionPolicy Bypass -File frontend/scripts/build-frontend.ps1
```

That script restores frontend dependencies when needed and rebuilds the embedded report bundle before resource compilation.

## Frontend Development

Install dependencies once:

```powershell
cd frontend
npm install
```

Start the Vite development server:

```powershell
npm run dev
```

Build the frontend only:

```powershell
npm run build
```

If dependencies become out of sync, rerun:

```powershell
powershell -ExecutionPolicy Bypass -File frontend/scripts/build-frontend.ps1
```

## Run

After building, run the generated executable. Netcure will:

1. execute all diagnostic checkers,
2. write a JSON report,
3. write an HTML report,
4. attempt to open the HTML report in the default browser.

## Current Checkers

- `adapter_checker`
- `environment_checker`
- `wifi_checker`
- `route_checker`
- `ping_checker`
- `proxy_checker`
