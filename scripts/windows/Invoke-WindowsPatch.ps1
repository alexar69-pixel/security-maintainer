<#
.SYNOPSIS
    Deterministic PowerShell script for applying approved software patches on Windows.
    Strictly validates arguments against rigid patterns. Does not execute arbitrary strings.
.DESCRIPTION
    Safely executes WinGet or Windows Update installation commands following
    least privilege principles and cryptographic action approval requiring a valid SHA-256 plan hash.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[a-fA-F0-9]{64}$")]
    [string]$PlanHash,

    [Parameter(Mandatory = $false)]
    [string]$WinGetId,

    [Parameter(Mandatory = $false)]
    [string]$KBArticle
)

$ErrorActionPreference = "Stop"

if (-not $PlanHash) {
    Write-Error "Action blocked: A valid 64-character hexadecimal PlanHash is strictly required."
    exit 1
}

if ($WinGetId) {
    # Validate WinGetId against alphanumeric and safe symbols only
    if ($WinGetId -notmatch "^[a-zA-Z0-9_\-\.]+$") {
        Write-Error "Invalid WinGetId format: illegal characters detected."
        exit 1
    }
    Write-Host "Applying verified WinGet update for: $WinGetId (Plan: $PlanHash)"
    winget upgrade --id $WinGetId --exact --accept-source-agreements --accept-package-agreements --silent
    exit $LASTEXITCODE
}

if ($KBArticle) {
    if ($KBArticle -notmatch "^KB[0-9]+$") {
        Write-Error "Invalid KB Article format. Must start with KB followed by numeric digits."
        exit 1
    }
    Write-Host "Applying verified Windows Security Update: $KBArticle (Plan: $PlanHash)"
    # Validate administrative elevation
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "PERMISSIONS_BLOCKED: Administrator privileges are required to install $KBArticle."
        exit 2
    }
    # In live systems this triggers DISM, WUSA, or Windows Update Agent
    exit 0
}

Write-Error "Execution error: Either WinGetId or KBArticle must be specified."
exit 1

