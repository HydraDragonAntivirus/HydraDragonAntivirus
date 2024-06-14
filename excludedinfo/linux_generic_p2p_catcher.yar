import "elf"
rule linux_generic_p2p_catcher
{
  meta:
    author      = "@_lubiedo"
    date        = "2020-04-10"
    description = "Generic catcher for P2P capable linux ELFs"
    hash0       = "af629ae5a79f715cdbcf9e1faf389a39bd96b887b019984e50798d013f38a466"
    hash1       = "7cd7966d7e472d659b427bedc76dac24cdf598e09defd8d86262efb2bdf55929"

  strings:
    /**
    * BitTorrent
    **/
    // BT public trackers (some found in the wild)
    $trackers1= "router.utorrent.com" ascii nocase
    $trackers2= "router.bittorrent.com" ascii nocase
    $trackers3= "dht.transmissionbt.com" ascii nocase
    $trackers4= "bttracker.debian.org" ascii nocase
    // ref.: hash1
    $trackers5= "212.129.33.59" ascii
    $trackers7= "82.221.103.244" ascii
    $trackers8= "130.239.18.159" ascii
    $trackers9= "87.98.162.88" ascii

    // BT DHT (https://github.com/jech/dht/blob/master/dht.c)
    $dht_str1 = "Get_peers with no info_hash" fullword ascii
    $dht_str2 = "Announce_peer with no info_hash" fullword ascii
    $dht_str3 = "Announce_peer with wrong token" fullword ascii
    $dht_str4 = "Announce_peer with forbidden port number" fullword ascii

    $dht_msg1   = "1:y1:ee" fullword ascii
    $dht_msg2   = "2:n6" fullword ascii
    $dht_msg3   = "d1:ad2:id20:" fullword ascii
    $dht_msg4   = "6:target20:" fullword ascii
    $dht_msg5   = "4:wantl%s%se" fullword ascii
    $dht_msg6   = "e1:q9:find_node1:t%d:" fullword ascii
    $dht_msg7   = "1:y1:qe"  fullword ascii
    $dht_msg8   = "9:info_hash20:" fullword ascii
    $dht_msg9   = "4:porti%ue5:token%d:" fullword ascii
    $dht_msg10  = "e1:q13:announce_peer1:t%d:" fullword ascii
    $dht_msg11  = "e1:q9:get_peers1:t%d:" fullword ascii
    $dht_msg12  = "e1:q4:ping1:t%d:" fullword ascii
    $dht_msg13  = "1:v4:" fullword ascii
    $dht_msg14  = "5:token" fullword ascii
    $dht_msg15  = "5:nodes" fullword ascii
    $dht_msg16  = "6:nodes6" fullword ascii
    $dht_msg17  = "4:wantl" fullword ascii
    $dht_msg18  = "1:y1:r" fullword ascii
    $dht_msg19  = "1:y1:e" fullword ascii
    $dht_msg20  = "1:y1:q" fullword ascii
    $dht_msg21  = "1:q4:ping" fullword ascii
    $dht_msg22  = "1:q9:find_node" fullword ascii
    $dht_msg23  = "1:q9:get_peers" fullword ascii
    $dht_msg24  = "1:q13:announce_peer" fullword ascii
    $dht_msg25  = "2:n4" fullword ascii

    /**
     * libp2p
     **/
    $gomod1= "github.com/libp2p/go-libp2p" ascii

  condition:
    (filesize < 2MB and elf.type == elf.ET_EXEC) and (
            // bittorrent
        (any of ($trackers*) or (2 of ($dht_str*) and any of ($dht_msg*))) or
        // libp2p
        $gomod1
    )
}
