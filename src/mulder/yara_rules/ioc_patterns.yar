rule Encoded_PowerShell
{
    meta:
        description = "Detects encoded or obfuscated PowerShell execution"
        severity = "high"

    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $enc3 = "-ec " ascii wide nocase
        $bypass1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $bypass2 = "-ep bypass" ascii wide nocase
        $bypass3 = "-exec bypass" ascii wide nocase
        $hidden1 = "-WindowStyle Hidden" ascii wide nocase
        $hidden2 = "-w hidden" ascii wide nocase
        $noprof = "-NoProfile" ascii wide nocase
        $nonint = "-NonInteractive" ascii wide nocase
        $iex1 = "Invoke-Expression" ascii wide nocase
        $iex2 = "IEX(" ascii wide nocase
        $iex3 = "IEX (" ascii wide nocase
        $dl1 = "Net.WebClient" ascii wide nocase
        $dl2 = "DownloadString" ascii wide nocase
        $dl3 = "DownloadFile" ascii wide nocase
        $dl4 = "Invoke-WebRequest" ascii wide nocase
        $dl5 = "wget " ascii wide nocase
        $dl6 = "curl " ascii wide nocase

    condition:
        (any of ($enc*)) or
        (any of ($bypass*) and any of ($hidden*)) or
        (any of ($iex*) and any of ($dl*))
}

rule Base64_Payload_Blob
{
    meta:
        description = "Detects large base64-encoded blobs that may contain payloads"
        severity = "medium"

    strings:
        $b64_ps = "powershell" ascii wide nocase
        $b64_tv = "TVqQAA" ascii wide
        $b64_tv2 = "TVpQAAIAAAA" ascii wide
        $b64_tv3 = "TVroAAAAAA" ascii wide
        $b64_h4s = "H4sIA" ascii wide
        $b64_uf8 = "77u/" ascii wide

    condition:
        any of them
}

rule Suspicious_WMI_Activity
{
    meta:
        description = "Detects suspicious WMI/WMIC usage for execution or reconnaissance"
        severity = "high"

    strings:
        $wmi1 = "wmic process call create" ascii wide nocase
        $wmi2 = "wmic /node:" ascii wide nocase
        $wmi3 = "Win32_Process" ascii wide nocase
        $wmi4 = "Win32_ScheduledJob" ascii wide nocase
        $wmi5 = "ActiveScriptEventConsumer" ascii wide nocase
        $wmi6 = "CommandLineEventConsumer" ascii wide nocase
        $wmi7 = "Win32_ProcessStartup" ascii wide nocase

    condition:
        2 of them
}

rule Suspicious_C2_UserAgents
{
    meta:
        description = "Detects user-agent strings commonly used by C2 frameworks"
        severity = "medium"

    strings:
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.0;" ascii
        $ua2 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" ascii
        $ua3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)" ascii
        $ua4 = "Internet Explorer" ascii wide

    condition:
        any of them
}

rule Credential_Dumping_Tools
{
    meta:
        description = "Detects references to common credential dumping tools and techniques"
        severity = "critical"

    strings:
        $tool1 = "gsecdump" ascii wide nocase
        $tool2 = "wce.exe" ascii wide nocase
        $tool3 = "pwdump" ascii wide nocase
        $tool4 = "procdump" ascii wide nocase
        $tool5 = "lazagne" ascii wide nocase
        $tool6 = "rubeus" ascii wide nocase
        $tool7 = "kekeo" ascii wide nocase
        $tool8 = "sharpdump" ascii wide nocase
        $tool9 = "safetykatz" ascii wide nocase
        $tech1 = "lsass.exe" ascii wide nocase
        $tech2 = "NTDS.dit" ascii wide nocase
        $tech3 = "SAM database" ascii wide nocase

    condition:
        any of ($tool*) or 2 of ($tech*)
}

rule Suspicious_Scheduled_Task
{
    meta:
        description = "Detects suspicious scheduled task creation patterns"
        severity = "high"

    strings:
        $s1 = "schtasks /create" ascii wide nocase
        $s2 = "schtasks.exe /create" ascii wide nocase
        $s3 = "Register-ScheduledTask" ascii wide nocase
        $s4 = "New-ScheduledTaskAction" ascii wide nocase

    condition:
        any of them
}

rule Suspicious_Service_Creation
{
    meta:
        description = "Detects suspicious Windows service creation for persistence or lateral movement"
        severity = "high"

    strings:
        $s1 = "sc create" ascii wide nocase
        $s2 = "sc.exe create" ascii wide nocase
        $s3 = "New-Service" ascii wide nocase
        $s4 = "binPath=" ascii wide nocase

    condition:
        ($s1 or $s2 or $s3) and $s4
}
