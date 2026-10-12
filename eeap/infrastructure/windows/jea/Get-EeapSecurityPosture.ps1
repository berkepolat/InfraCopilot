function Get-EeapSecurityPosture {
    <#
    .SYNOPSIS
    Read-only security posture for EEAP (WIN-003, WIN-004, WIN-005, WIN-007, WIN-009 … WIN-012).

    .DESCRIPTION
    Reads registry values, the local Administrators group, endpoint protection status and update
    state, and returns them as one JSON document. Changes nothing: pending updates come from the
    Windows Update Agent's local cache (offline search), so nothing is downloaded or installed and no
    update server is contacted. This is the only command exposed by the EEAP.Posture JEA endpoint.
    #>
    [CmdletBinding()]
    param()

    function Read-Value([string] $Path, [string] $Name) {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $null }
        return $item.$Name
    }

    function Format-Date($Value) {
        if ($null -eq $Value -or $Value -isnot [datetime] -or $Value.Year -lt 2000) { return $null }
        return $Value.ToUniversalTime().ToString('o')
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $isDc = $cs.DomainRole -ge 4
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $msv = "$lsa\MSV1_0"
    $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $nt = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $result = [ordered]@{
        schema   = 'eeap.windows.posture/1'
        host     = [ordered]@{
            computer_name = $env:COMPUTERNAME
            dns_domain    = $cs.Domain
            domain_role   = [int]$cs.DomainRole
            is_domain_controller = $isDc
            os_caption    = $os.Caption
            os_version    = $os.Version
            os_build      = $os.BuildNumber
            os_ubr        = Read-Value $nt 'UBR'
            display_version = Read-Value $nt 'DisplayVersion'
            edition_id    = Read-Value $nt 'EditionID'
            installation_type = Read-Value $nt 'InstallationType'
            product_type  = [int]$os.ProductType
            last_boot     = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        }
        updates  = $null
        ntlm     = [ordered]@{
            lm_compatibility_level      = Read-Value $lsa 'LmCompatibilityLevel'
            no_lm_hash                  = Read-Value $lsa 'NoLMHash'
            restrict_sending_ntlm       = Read-Value $msv 'RestrictSendingNTLMTraffic'
            restrict_receiving_ntlm     = Read-Value $msv 'RestrictReceivingNTLMTraffic'
            ntlm_min_server_sec         = Read-Value $msv 'NtlmMinServerSec'
        }
        ldap     = $null
        local_admins = $null
        endpoint_protection = $null
        errors   = @()
    }

    if ($isDc) {
        $result.ldap = [ordered]@{
            server_integrity          = Read-Value $ntds 'LDAPServerIntegrity'
            enforce_channel_binding   = Read-Value $ntds 'LdapEnforceChannelBinding'
        }
    } else {
        try {
            $result.local_admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
                [ordered]@{
                    name         = $_.Name
                    sid          = $_.SID.Value
                    object_class = $_.ObjectClass
                    source       = "$($_.PrincipalSource)"
                }
            })
        } catch {
            $result.errors += "local_admins: $($_.Exception.Message)"
        }
    }

    $protection = [ordered]@{ defender = $null; services = @() }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $protection.defender = [ordered]@{
            antivirus_enabled        = $mp.AntivirusEnabled
            service_enabled          = $mp.AMServiceEnabled
            real_time_protection     = $mp.RealTimeProtectionEnabled
            tamper_protection        = $mp.IsTamperProtected
            signature_last_updated   = if ($mp.AntivirusSignatureLastUpdated) { $mp.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') } else { $null }
            running_mode             = "$($mp.AMRunningMode)"
        }
    } catch {
        $result.errors += "defender: $($_.Exception.Message)"
    }
    # Well-known EDR / antivirus services (presence and state only).
    $known = 'Sense', 'WinDefend', 'CSFalconService', 'SentinelAgent', 'CylanceSvc', 'CbDefense', 'cyserver',
             'xagt', 'elastic-agent', 'ekrn', 'SophosFileScanner', 'Sophos Endpoint Defense Service', 'TmCCSF',
             'mfemms', 'SAVService'
    $protection.services = @(Get-Service -Name $known -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ name = $_.Name; display_name = $_.DisplayName; status = "$($_.Status)" }
    })
    $result.endpoint_protection = $protection

    $updates = [ordered]@{
        hotfixes = @(); last_search_success = $null; last_install_success = $null
        pending = $null; pending_truncated = $false; reboot_required = $false
    }
    try {
        $updates.hotfixes = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop |
            Select-Object -First 500 | ForEach-Object {
                $installed = $null
                if ($_.InstalledOn) { $installed = Format-Date ([datetime]$_.InstalledOn) }
                [ordered]@{ id = $_.HotFixID; description = $_.Description; installed_on = $installed }
            })
    } catch {
        $result.errors += "hotfixes: $($_.Exception.Message)"
    }
    try {
        $wua = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
        $updates.last_search_success = Format-Date $wua.LastSearchSuccessDate
        $updates.last_install_success = Format-Date $wua.LastInstallationSuccessDate
    } catch {
        $result.errors += "wua_results: $($_.Exception.Message)"
    }
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $searcher.Online = $false
        $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
        $updates.pending_truncated = $found.Count -gt 200
        $updates.pending = @(for ($i = 0; $i -lt [Math]::Min($found.Count, 200); $i++) {
            $u = $found.Item($i)
            [ordered]@{
                title        = $u.Title
                kbs          = @($u.KBArticleIDs | ForEach-Object { "KB$_" })
                severity     = $u.MsrcSeverity
                cves         = @($u.CveIDs)
                categories   = @($u.Categories | ForEach-Object { $_.Name })
                released     = Format-Date $u.LastDeploymentChangeTime
                is_downloaded = [bool]$u.IsDownloaded
            }
        })
    } catch {
        $result.errors += "wua_search: $($_.Exception.Message)"
    }
    $updates.reboot_required = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    $result.updates = $updates

    return ($result | ConvertTo-Json -Depth 6 -Compress)
}
