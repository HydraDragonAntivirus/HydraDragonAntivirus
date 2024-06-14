/*
Looks for IRC samples using yara
this will only look for executable ELFs
*/
import "elf"
rule linux_generic_irc_catcher
{
    meta:
    author      = "@_lubiedo"
    date        = "2020-04-07"
    description = "Find new ELF IRC samples"
    hash0       = "02209779f6e65533b35868464c144ac8c144392cf774c5feb0a66f7af4005268"

    strings:
    $cmd1 = "PING" fullword ascii
    $cmd2 = "PONG" fullword ascii
    $cmd3 = "NICK" fullword ascii
    $cmd4 = "JOIN" fullword ascii
    $cmd5 = "PRIVMSG" fullword ascii
    $cmd6 = "NOTICE" fullword ascii
    $cmd7 = "USER" fullword ascii

  condition:
    ( elf.type == elf.ET_EXEC and filesize < 1MB )
        and 3 of them
}
