/*
    Packer Detection Rules
    These rules detect common packers and protectors
*/

rule UPX_Packer {
    strings:
        $upx0 = "UPX0" ascii wide
        $upx1 = "UPX1" ascii wide
        $upx2 = "UPX2" ascii wide
        $upx_sig = "UPX!" ascii wide
        
    condition:
        any of them
}

rule ASPack {
    strings:
        $aspack = ".aspack" ascii wide
        $adata = ".adata" ascii wide
    condition:
        any of them
}

rule PECompact {
    strings:
        $a = "PEC2" ascii wide
        $b = "PECompact2" ascii wide
    condition:
        any of them
}

rule Themida {
    strings:
        $a = "Themida" ascii wide
        $b = ".themida" ascii wide
    condition:
        any of them
}

rule VMProtect {
    strings:
        $a = "VMProtect" ascii wide
        $b = ".vmp0" ascii wide
        $c = "VMP 1." ascii wide
        $d = "VMP 2." ascii wide
    condition:
        any of them
}

rule MPRESS {
    strings:
        $a = "MPRESS1" ascii wide
        $b = "MPRESS2" ascii wide
    condition:
        any of them
}

rule FSG {
    strings:
        $a = "FSG!" ascii wide
        $b = "FSG!!" ascii wide
    condition:
        any of them
}

rule PEtite {
    strings:
        $a = "PEtite" ascii wide
        $b = "petite" ascii wide
    condition:
        any of them
}

rule ASProtect {
    strings:
        $a = ".ASPack" ascii wide
        $b = "ASProtect" ascii wide
    condition:
        any of them
}

rule MEW {
    strings:
        $a = "MEW" ascii wide
    condition:
        $a
}

rule Y0da {
    strings:
        $a = "Y0da" ascii wide
    condition:
        $a
}

rule Confuser {
    strings:
        $a = "ConfuserEx v" ascii wide
        $b = "Confuser v" ascii wide
    condition:
        any of them
}

rule Generic_Packer_Indicators {
    strings:
        $a1 = ".packed" ascii wide
        $a2 = ".compressed" ascii wide
        $a3 = ".crypted" ascii wide
        $a4 = ".protected" ascii wide
        $a5 = ".encrypted" ascii wide
        
    condition:
        any of them
} 