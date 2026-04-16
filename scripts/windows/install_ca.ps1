<#
.SYNOPSIS
  Installs the Strac Auditor root CA into the LocalMachine Root store so
  the GenAI proxy can transparently decrypt TLS to catalog'd providers.

.DESCRIPTION
  Invoked by the MSI postinstall action. Idempotent: if a certificate with
  the expected Common Name already exists in Root, we leave it alone. The
  agent itself generates the CA on first run; this script only installs it
  into the trust store.

.NOTES
  - Must run as Administrator. The MSI runs the postinstall elevated so
    this is satisfied.
  - The agent ships the CA cert at the path below. If you move it, update
    $CertPath.
#>

[CmdletBinding()]
param(
    [string]$CertPath = "$env:ProgramData\auditor\strac-auditor-root.pem",
    [string]$CommonName = "Strac Auditor Root"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $CertPath)) {
    Write-Error "CA cert not found at $CertPath -- run the agent once to generate it."
    exit 1
}

# Check for existing installation
$existing = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match $CommonName }
if ($existing) {
    Write-Host "Strac Auditor Root already trusted (thumbprint $($existing.Thumbprint))."
    exit 0
}

Write-Host "Importing $CertPath into LocalMachine\Root ..."
Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Write-Host "Done."
