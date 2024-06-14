import "elf"
rule linux_generic_ipv6_catcher
{
    meta:
    author      = "@_lubiedo"
    date        = "2020-04-27"
    description = "ELF samples using IPv6 addresses"

    strings:
        // regex credit: https://stackoverflow.com/a/37355379
        $ipv6 = /([a-f0-9:]+:+)+[a-f0-9]+/ fullword ascii nocase

    condition:
        ( elf.type == elf.ET_EXEC and filesize < 1MB ) and $ipv6
}
