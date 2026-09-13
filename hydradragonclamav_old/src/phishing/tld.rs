//! IANA TLD and country-code-TLD sets, ported verbatim from ClamAV's
//! `clamav/libclamav/iana_tld.h` (`in_tld_set`) and `iana_cctld.h`
//! (`in_cctld_set`). Used by `get_domain` to find the registrable domain
//! TLD-aware, matching ClamAV byte-for-byte. Both arrays are sorted for
//! binary search; lookups are case-insensitive on already-lowercased hosts.

/// True if `s` is in ClamAV's IANA TLD set (`iana_tld.h`).
pub fn is_tld(s: &str) -> bool {
    TLD_SET.binary_search(&s).is_ok()
}

/// True if `s` is in ClamAV's IANA country-code TLD set (`iana_cctld.h`).
pub fn is_cctld(s: &str) -> bool {
    CCTLD_SET.binary_search(&s).is_ok()
}

/// Sorted IANA TLD set (from `iana_tld.h` gperf wordlist).
static TLD_SET: &[&str] = &[
    "ac", "ad", "ae", "aero", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "arpa", "as",
    "asia", "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "biz",
    "bj", "bm", "bn", "bo", "br", "bs", "bt", "bv", "bw", "by", "bz", "ca", "cat", "cc", "cd", "cf",
    "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "com", "coop", "cr", "cu", "cv", "cx", "cy",
    "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "edu", "ee", "eg", "er", "es", "et", "eu", "fi",
    "fj", "fk", "fm", "fo", "fr", "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn",
    "gov", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", "hu", "id",
    "ie", "il", "im", "in", "info", "int", "io", "iq", "ir", "is", "it", "je", "jm", "jo", "jobs",
    "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li",
    "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg", "mh", "mil", "mk", "ml",
    "mm", "mn", "mo", "mobi", "mp", "mq", "mr", "ms", "mt", "mu", "museum", "mv", "mw", "mx", "my",
    "mz", "na", "name", "nc", "ne", "net", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz",
    "om", "org", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "pro", "ps", "pt", "pw",
    "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj",
    "sk", "sl", "sm", "sn", "so", "sr", "st", "su", "sv", "sy", "sz", "tc", "td", "tel", "tf", "tg",
    "th", "tj", "tk", "tl", "tm", "tn", "to", "tp", "tr", "travel", "tt", "tv", "tw", "tz", "ua",
    "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws",
    "xn--0zwm56d", "xn--11b5bs3a9aj6g", "xn--80akhbyknj4f", "xn--9t4b11yi5a", "xn--deba0ad",
    "xn--g6w251d", "xn--hgbk6aj7f53bba", "xn--hlcj6aya9esc7a", "xn--jxalpdlp", "xn--kgbechtv",
    "xn--zckzah", "ye", "yt", "yu", "za", "zm", "zw",
];

/// Sorted IANA country-code TLD set (from `iana_cctld.h` gperf wordlist).
static CCTLD_SET: &[&str] = &[
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "as", "at", "au", "aw",
    "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bl", "bm", "bn", "bo", "br",
    "bs", "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm",
    "cn", "co", "cr", "cu", "cv", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee",
    "eg", "eh", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb", "gd", "ge",
    "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk",
    "hm", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je",
    "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb",
    "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mf", "mg", "mh",
    "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz",
    "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf",
    "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru",
    "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr",
    "st", "su", "sv", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to",
    "tp", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "um", "us", "uy", "uz", "va", "vc", "ve",
    "vg", "vi", "vn", "vu", "wf", "ws", "ye", "yt", "yu", "za", "zm", "zw",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_are_sorted_for_binary_search() {
        assert!(TLD_SET.windows(2).all(|w| w[0] < w[1]), "TLD_SET unsorted");
        assert!(CCTLD_SET.windows(2).all(|w| w[0] < w[1]), "CCTLD_SET unsorted");
    }

    #[test]
    fn known_membership() {
        assert!(is_tld("com") && is_tld("co") && is_tld("uk"));
        assert!(is_cctld("uk") && is_cctld("jp"));
        assert!(!is_tld("zzz") && !is_cctld("com"));
    }
}
