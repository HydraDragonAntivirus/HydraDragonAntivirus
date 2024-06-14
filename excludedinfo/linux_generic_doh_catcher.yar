rule linux_protocol_doh
{
    meta:
        author      = "@_lubiedo"
        date        = "2020-08-04"
        description = "DNS-over-HTTPS yara rule"
    strings:
        $path = "dns-query"

        // servers
        $s0 = "cloudflare-dns.com"
        $s1 = "mozilla.cloudflare-dns.com"
        $s2 = "dns.google"
        $s3 = "dns.quad9.net"
        $s4 = "dns9.quad9.net"
        $s5 = "dns10.quad9.net"
        $s7 = "dns11.quad9.net"
        $s9 = "security-filter-dns.cleanbrowsing.org"
        $s10= "family-filter-dns.cleanbrowsing.org"
        $s11= "adult-filter-dns.cleanbrowsing.org"
        $s12= "dns.adguard.com"
        $s13= "dns-family.adguard.com"
        $s14= "doh.xfinity.com"

    condition:
        uint32(0) == 0x464c457f and $path and any of ($s*)
}
