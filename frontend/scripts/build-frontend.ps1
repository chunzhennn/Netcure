param()

$ErrorActionPreference = "Stop"

$frontendRoot = Split-Path -Parent $PSScriptRoot
$nodeModulesDir = Join-Path $frontendRoot "node_modules"
$packageLockPath = Join-Path $frontendRoot "package-lock.json"
$packageJsonPath = Join-Path $frontendRoot "package.json"
$dependencyStampPath = Join-Path $nodeModulesDir ".netcure-deps-hash"
$viteCliPath = Join-Path $nodeModulesDir "vite\bin\vite.js"

function Get-DependencyStateHash {
    if (Test-Path $packageLockPath) {
        return "lock:" + (Get-FileHash -Path $packageLockPath -Algorithm SHA256).Hash
    }

    return "package:" + (Get-FileHash -Path $packageJsonPath -Algorithm SHA256).Hash
}

Push-Location $frontendRoot
try {
    $expectedDependencyState = Get-DependencyStateHash
    $installedDependencyState = if (Test-Path $dependencyStampPath) {
        (Get-Content $dependencyStampPath -Raw).Trim()
    }
    else {
        ""
    }

    $needsInstall =
        (-not (Test-Path $nodeModulesDir)) -or
        ($installedDependencyState -ne $expectedDependencyState) -or
        (-not (Test-Path $viteCliPath))

    if ($needsInstall) {
        if (Test-Path $packageLockPath) {
            npm ci
        }
        else {
            npm install
        }

        if (-not (Test-Path $nodeModulesDir)) {
            throw "Dependency installation completed but node_modules was not created."
        }

        Set-Content -Path $dependencyStampPath -Value $expectedDependencyState -NoNewline
    }

    npm run build
}
finally {
    Pop-Location
}
