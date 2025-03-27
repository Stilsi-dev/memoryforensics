rule Packed_Executable {
    meta:
        description = "Detects common executable packers"
        author = "Your Team"
        date = "2023-11-15"
    
    strings:
        $upx = "UPX!" ascii wide
        $aspack = "ASPack" ascii wide
        $fsg = "FSG!" ascii wide
        $pecompact = "PEC2" ascii wide
    
    condition:
        any of them
}

rule Entropy_High {
    meta:
        description = "Detects high entropy regions (possible packed code)"
    
    condition:
        pe.entropy(0) > 7.0
}