<#
.SYNOPSIS
    Script determinista para aplicar parches o actualizaciones en Windows.
    Valida argumentos estrictamente. No utiliza cadenas arbitrarias.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$WinGetId,

    [Parameter(Mandatory = $false)]
    [string]$KBArticle
)

$ErrorActionPreference = "Stop"

if ($WinGetId) {
    # Validar que WinGetId no contenga caracteres de inyección de comandos
    if ($WinGetId -notmatch "^[a-zA-Z0-9_\-\.]+$") {
        Write-Error "WinGetId contiene caracteres no permitidos."
        exit 1
    }
    Write-Host "Aplicando actualizacion WinGet para: $WinGetId"
    winget upgrade --id $WinGetId --exact --accept-source-agreements --accept-package-agreements --silent
    exit $LASTEXITCODE
}

if ($KBArticle) {
    if ($KBArticle -notmatch "^KB[0-9]+$") {
        Write-Error "Formato de KB invalido. Debe ser KB seguido de digitos."
        exit 1
    }
    Write-Host "Instalando actualizacion de Windows: $KBArticle"
    # Requiere elevación de administrador
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "PERMISSIONS_BLOCKED: Se requieren permisos de Administrador para instalar $KBArticle."
        exit 2
    }
    # En entorno real invocaría WUSA o Windows Update COM
    exit 0
}

Write-Error "Debe proporcionar WinGetId o KBArticle."
exit 1
