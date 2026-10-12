<#
.SYNOPSIS
Removes the EEAP.Posture JEA endpoint and module (run as administrator).
#>
[CmdletBinding(SupportsShouldProcess)]
param([string] $EndpointName = 'EEAP.Posture')

$ErrorActionPreference = 'Stop'
if ($PSCmdlet.ShouldProcess($EndpointName, 'Unregister JEA endpoint')) {
    if (Get-PSSessionConfiguration -Name $EndpointName -ErrorAction SilentlyContinue) {
        Unregister-PSSessionConfiguration -Name $EndpointName -Force
    }
    $moduleRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\EeapPosture'
    if (Test-Path -LiteralPath $moduleRoot) { Remove-Item -LiteralPath $moduleRoot -Recurse -Force }
    Write-Output "Removed JEA endpoint '$EndpointName'."
}
