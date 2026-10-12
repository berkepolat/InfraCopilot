<#
.SYNOPSIS
Registers the EEAP.Posture JEA endpoint on a Windows host (run as administrator).

.DESCRIPTION
The EEAP scanner account (or a group containing it) may connect to this endpoint and run exactly
one command: Get-EeapSecurityPosture, which only reads configuration. No other cmdlet, script or
language feature is available in the session (NoLanguage mode).

On member servers the session runs as a temporary virtual account (local administrator for the
session only). On domain controllers a virtual account would be a domain administrator, so pass a
group managed service account (-GroupManagedServiceAccount) with read access instead.

.EXAMPLE
.\Install-EeapJea.ps1 -ScannerPrincipal 'CORP\EEAP-Scanners'

.EXAMPLE
.\Install-EeapJea.ps1 -ScannerPrincipal 'CORP\EEAP-Scanners' -GroupManagedServiceAccount 'CORP\gmsa-eeap$'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $ScannerPrincipal,
    [string] $GroupManagedServiceAccount,
    [string] $EndpointName = 'EEAP.Posture'
)

$ErrorActionPreference = 'Stop'
$moduleRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\EeapPosture'
$roleDir = Join-Path $moduleRoot 'RoleCapabilities'
New-Item -ItemType Directory -Path $roleDir -Force | Out-Null

# Trusted module (FullLanguage) holding the single read-only function.
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Get-EeapSecurityPosture.ps1') `
    -Destination (Join-Path $moduleRoot 'EeapPosture.psm1') -Force
New-ModuleManifest -Path (Join-Path $moduleRoot 'EeapPosture.psd1') -RootModule 'EeapPosture.psm1' `
    -ModuleVersion '1.0.0' -FunctionsToExport 'Get-EeapSecurityPosture' -Description 'EEAP read-only posture endpoint'
New-PSRoleCapabilityFile -Path (Join-Path $roleDir 'EeapPosture.psrc') `
    -Description 'EEAP read-only security posture' -ModulesToImport 'EeapPosture' `
    -VisibleFunctions 'Get-EeapSecurityPosture'

$sessionFile = Join-Path $env:TEMP "$EndpointName.pssc"
$common = @{
    Path                = $sessionFile
    SessionType         = 'RestrictedRemoteServer'
    LanguageMode        = 'NoLanguage'
    RoleDefinitions     = @{ $ScannerPrincipal = @{ RoleCapabilities = 'EeapPosture' } }
    TranscriptDirectory = Join-Path $env:ProgramData 'EEAP\JeaTranscripts'
}
if ($GroupManagedServiceAccount) {
    New-PSSessionConfigurationFile @common -GroupManagedServiceAccount $GroupManagedServiceAccount
} else {
    New-PSSessionConfigurationFile @common -RunAsVirtualAccount
}
if (-not (Test-PSSessionConfigurationFile -Path $sessionFile)) { throw "invalid session configuration $sessionFile" }

if ($PSCmdlet.ShouldProcess($EndpointName, 'Register JEA endpoint')) {
    if (Get-PSSessionConfiguration -Name $EndpointName -ErrorAction SilentlyContinue) {
        Unregister-PSSessionConfiguration -Name $EndpointName -Force
    }
    Register-PSSessionConfiguration -Name $EndpointName -Path $sessionFile -Force | Out-Null
    Write-Output "Registered JEA endpoint '$EndpointName' for $ScannerPrincipal."
}
Remove-Item -LiteralPath $sessionFile -Force
