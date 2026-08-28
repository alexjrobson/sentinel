rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (benign standard test string)"
        attack = "T1204.002"
        severity = "high"
        rule_id = "eicar_test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell encoded command / FromBase64String tradecraft"
        attack = "T1059.001"
        severity = "high"
        rule_id = "powershell_encoded"
    strings:
        $enc = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $b64 = "FromBase64String" nocase
        $iex = "Invoke-Expression" nocase
    condition:
        any of them
}

rule Suspicious_Cmd_Interpreter
{
    meta:
        description = "Windows command interpreter execution strings"
        attack = "T1059.003"
        severity = "medium"
        rule_id = "cmd_interpreter"
    strings:
        $cmd = "cmd.exe /c" nocase
        $wscript = "wscript.exe" nocase
        $cscript = "cscript.exe" nocase
    condition:
        any of them
}

rule VBA_Macro_Keywords
{
    meta:
        description = "Office/VBA auto-execution keywords (static strings)"
        attack = "T1566.001"
        severity = "medium"
        rule_id = "vba_macro"
    strings:
        $auto = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $shell = "Shell(" nocase
        $create = "CreateObject" nocase
    condition:
        2 of them
}

rule Packed_Or_UPX_Hint
{
    meta:
        description = "UPX packer section name"
        attack = "T1027.002"
        severity = "medium"
        rule_id = "upx_packer"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        any of them
}
