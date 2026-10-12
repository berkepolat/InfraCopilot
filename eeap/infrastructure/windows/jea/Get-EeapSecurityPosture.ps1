function Get-EeapSecurityPosture {
    <#
    .SYNOPSIS
    Read-only security posture for EEAP (WIN-003, WIN-004, WIN-005, WIN-007, WIN-009).

    .DESCRIPTION
    Reads registry values, the local Administrators group and endpoint protection status, and
    returns them as one JSON document. Changes nothing. This is the only command exposed by the
    EEAP.Posture JEA endpoint.
    #>
    [CmdletBinding()]
    param()

    function Read-Value([string] $Path, [string] $Name) {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $null }
        return $item.$Name
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $isDc = $cs.DomainRole -ge 4
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $msv = "$lsa\MSV1_0"
    $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

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
            last_boot     = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        }
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

    return ($result | ConvertTo-Json -Depth 6 -Compress)
}
