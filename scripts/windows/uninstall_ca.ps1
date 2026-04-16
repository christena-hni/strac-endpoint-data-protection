<#
.SYNOPSIS
  Removes the Strac Auditor root CA from the LocalMachine Root store.
  Invoked by the MSI uninstall sequence.
#>

[CmdletBinding()]
param(
    [string]$CommonName = "Strac Auditor Root"
)

$ErrorActionPreference = "Continue"

$targets = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match $CommonName }
if (-not $targets) {
    Write-Host "No Strac Auditor Root cert found to remove."
    exit 0
}

foreach ($cert in $targets) {
    Write-Host "Removing $($cert.Thumbprint) ($($cert.Subject))"
    Remove-Item -Path "Cert:\LocalMachine\Root\$($cert.Thumbprint)" -Force
}
Write-Host "Done."
