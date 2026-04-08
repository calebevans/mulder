rule Suspicious_PE_No_Imports
{
    meta:
        description = "PE file with no import table — common in shellcode loaders and injected DLLs"
        severity = "medium"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_imports == 0
}

rule Suspicious_PE_Section_Names
{
    meta:
        description = "PE with suspicious or non-standard section names"
        severity = "medium"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $aspack = ".aspack" ascii
        $adata = ".adata" ascii
        $nsp0 = ".nsp0" ascii
        $nsp1 = ".nsp1" ascii

    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Reflective_DLL_Injection
{
    meta:
        description = "Detects reflective DLL injection markers"
        severity = "critical"
        reference = "https://github.com/stephenfewer/ReflectiveDLLInjection"

    strings:
        $s1 = "ReflectiveLoader" ascii wide
        $s2 = "_RDI" ascii
        $s3 = "NtFlushInstructionCache" ascii wide
        $s4 = "RtlCreateUserThread" ascii wide

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Process_Injection_APIs
{
    meta:
        description = "Binary imports common process injection API sequence"
        severity = "high"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide
        $api5 = "QueueUserAPC" ascii wide
        $api6 = "NtMapViewOfSection" ascii wide
        $api7 = "SetThreadContext" ascii wide
        $api8 = "NtUnmapViewOfSection" ascii wide

    condition:
        ($api1 and $api2 and $api3) or
        ($api1 and $api2 and $api4) or
        ($api5 and $api1) or
        ($api6 and $api8)
}

rule Process_Hollowing
{
    meta:
        description = "Detects process hollowing technique indicators"
        severity = "critical"

    strings:
        $api1 = "NtUnmapViewOfSection" ascii wide
        $api2 = "ZwUnmapViewOfSection" ascii wide
        $api3 = "VirtualAllocEx" ascii wide
        $api4 = "WriteProcessMemory" ascii wide
        $api5 = "SetThreadContext" ascii wide
        $api6 = "ResumeThread" ascii wide
        $api7 = "CREATE_SUSPENDED" ascii wide

    condition:
        ($api1 or $api2) and $api3 and $api4 and ($api5 or $api6)
}

rule Suspicious_Debug_Privilege
{
    meta:
        description = "References to SeDebugPrivilege escalation"
        severity = "high"

    strings:
        $s1 = "SeDebugPrivilege" ascii wide
        $s2 = "AdjustTokenPrivileges" ascii wide
        $s3 = "LookupPrivilegeValue" ascii wide

    condition:
        $s1 and ($s2 or $s3)
}
