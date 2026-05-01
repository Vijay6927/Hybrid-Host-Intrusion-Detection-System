"""
YARA Rules Module for HIDS
Contains all security detection rules for malware and suspicious activity
"""

import yara

# YARA rules definition
yara_rules_text = r"""
import "pe"

rule malicious_script {
    meta:
        description = "Detects malicious PowerShell patterns"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $iex1 = /Invoke-Expression\s+\(.*DownloadString/ nocase
        $iex2 = /iex\s+\(.*DownloadString/ nocase
        $iex3 = /IEX\s*\(.*DownloadString/ nocase
        $webclient = /New-Object\s+Net\.WebClient.*Download/ nocase
        $webclient2 = /Net\.WebClient.*DownloadString/ nocase
        $hidden = /Start-Process\s+-WindowStyle\s+Hidden/ nocase
        $hidden2 = /-w\s+hidden/ nocase
        $base64 = /FromBase64String\s*\(/ nocase
        $nop = /-nop/ nocase
    condition:
        $ps1 and (
            ($iex1 or $iex2 or $iex3) or
            ($webclient or $webclient2) or
            ($webclient and ($hidden or $hidden2)) or
            ($nop and $hidden2) or
            ($base64 and filesize < 50KB)
        )
}

rule suspicious_executable {
    meta:
        description = "Detects suspicious executables"
        severity = "critical"
    strings:
        $mz = "MZ"
        $s1 = "mimikatz" nocase wide
        $s2 = "cobaltstrike" nocase wide
        $s3 = "empire" nocase wide
        $s4 = /powershell.*-nop.*-w\s+hidden/ nocase
        $s5 = "meterpreter" nocase wide
        $s6 = "shellcode" nocase wide
        // Suspicious API combinations (beyond normal system tools)
        $api1 = "VirtualAllocEx" nocase wide
        $api2 = "WriteProcessMemory" nocase wide
        $api3 = "CreateRemoteThread" nocase wide
    condition:
        $mz at 0 and (
            // Malware tool names
            any of ($s1, $s2, $s3, $s5, $s6) or
            // Suspicious PowerShell patterns
            $s4 or
            // Process injection techniques (requires multiple suspicious APIs, not just privilege APIs)
            (2 of ($api1, $api2, $api3))
        )
}

rule temp_executable {
    meta:
        description = "Detects executables in temp folders"
        severity = "medium"
    strings:
        $temp1 = /\\Temp\\/ nocase
        $temp2 = /\\Temporary\\/ nocase
        $temp3 = /AppData\\Local\\Temp\\/ nocase
    condition:
        uint32(0) == 0x5A4D and
        any of ($temp*) and
        filesize < 10MB
}
"""


def compile_rules():
    """
    Compile YARA rules and return the compiled rules object
    """
    try:
        rules = yara.compile(source=yara_rules_text)
        return rules
    except Exception as e:
        raise Exception(f"Failed to compile YARA rules: {e}")
