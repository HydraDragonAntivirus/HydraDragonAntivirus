import "elf"
rule linux_generic_ipv6_variants_catcher
{
    meta:
    author      = "@_lubiedo"
    description = "Find IPv6 capable malware for a set of IoT variants"

    strings:
        // Tsunami
        $t1 = "RANDOMFLOOD"
        $t2 = "RSHELL"
        $t3 = "KEKSERVER"
        $t4 = "GETSPOOFS"
        $t5 = "HACKPKG"
        $t6 = "FUCKIT"
        $t7 = "VERSION"
        $t8 = "KILLALL"
        
        // QBot
        $q1 = "GETLOCALIP"
        $q2 = "SCANNER"
        $q3 = "PONG!"
        $q4 = "PROBING"
        $q5 = "FUCKOFF"

        // Gafgyt strings
        $s1 = "LOLNOGTFO"
        $s2 = "/proc/net/route"
        $s3 = "admin"
        $s4 = "root"

        // Mirai strings
        $dir1 = "/dev/watchdog"
        $dir2 = "/dev/misc/watchdog"
        $pass1 = "PMMV"
        $pass2 = "FGDCWNV"
        $pass3 = "OMVJGP"
        
        // try to get any IPv6 address
        $ipv6_1 = "fe80::" ascii // link-local
        $ipv6_2 = "2001::" ascii // teredo
        $ipv6_3 = "2001:41d0:" ascii // OVH hosting
        $ipv6_4 = "2604:A880:" ascii // DigitalOcean hosting
        $ipv6_5 = "2607:f298:" ascii // DreamHost hosting
        
        // printf formatting for IPv6 addresses
        $ipv6_fmt = "%x:%x:%x:%x:%x:%x:%x:%x"
        
    condition:
        ( elf.type == elf.ET_EXEC and filesize < 1MB ) and (
            // check mirai
            ( $dir1 and $pass1 and $pass2 and not $pass3 and not $dir2 ) or
            // check gafgyt
            ( all of ($s*) ) or
            // check qbot
            ( 2 of ($q*) ) or
            // check tsunami
            ( 2 of ($t*) )
        ) and ( any of ($ipv6_*) or $ipv6_fmt )
}
