
rule HideProtect_V10X_SoftWar_Company: PEiD {
  strings:
    $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    $b = { 90 90 90 E9 D8 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule HideProtect_V10X_SoftWar_Company_additional: PEiD {
  strings:
    $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $a at pe.entry_point

}

rule _PENightMare_2_Beta_ {
  meta:
    description = "PENightMare 2 Beta"

  strings:
    $0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $0 at pe.entry_point
}

rule PENinja: Packer PEiD {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $a0 at pe.entry_point
}
