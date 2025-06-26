import "pe"
import "elf"

rule Detect_cx_Freeze_MainStub
{
    meta:
        description = "Detect cx_Freeze main stub on PE or ELF"
        author = "Emirhan Ucan"
        license = "GPLv2"
        reference = "https://github.com/marcelotduarte/cx_Freeze/blob/7ae7fc3bf7422dc24ed5c5f1c08041b5646ad286/source/legacy/Win32GUI.c#L17"
        sha256 = "a715be2a6784804be97884a45f847011d8f1c7c546607e5fef1bf1accaad8dec"
        date = "2025-06-04"

    strings:
        $s1 = "cx_Freeze: Python error in main script" ascii
        $s2 = "cx_Freeze Fatal Error" ascii

    condition:
        pe.is_pe and all of ($s1, $s2) or
        elf.type != 0 and all of ($s1, $s2)
}
