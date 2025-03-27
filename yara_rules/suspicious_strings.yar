rule Suspicious_Strings {
    meta:
        description = "Generic suspicious strings"
    
    strings:
        $cmd_exec = /cmd\.exe\s+\/c/i
        $powershell = /powershell\s+-[eEncodedCommand]/i
        $base64 = /[A-Za-z0-9+\/]{30,}={0,2}/i
        $ip_address = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}/
        $registry_persistence = /CurrentVersion\\Run/i
    
    condition:
        any of them
}