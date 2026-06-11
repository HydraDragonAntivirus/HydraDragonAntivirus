rule infostealer_win_mars_stealer_xor_routine {
    meta:
        id = "3e2c7440b2fc9e4b039e6fa8152ac8ff"
        version = "1.0"
        description = "Detect Mars Stealer based on a specific XOR routine"
        author = "Sekoia.io"
        creation_date = "2022-04-06"
        classification = "TLP:CLEAR"
        
    strings:
        $xor = {8b 4d ?? 03 4d ?? 0f be 19 8b 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 ?? 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 0c 10 33 d9 8b 55 ?? 03 55 ?? 88 1a eb be}
        
    condition:
        uint16(0)==0x5A4D and $xor
}
rule infostealer_win_aurora {
    meta:
        version = "1.0"
        description = "Finds Aurora samples based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2022-11-15"
        id = "22ae81b4-647f-4b46-9b2a-dd96e0615d65"
        classification = "TLP:CLEAR"
        
    strings:
        $str00 = "I'm a teapot" ascii
        $str01 = "wmic cpu get name" ascii
        $str02 = "wmic path win32_VideoController get" ascii
        $str03 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones" ascii
        $str04 = "Exodus\\exodus.wallet" ascii
        $str05 = "PaliWallet" ascii
        $str06 = "cookies.sqlite" ascii
        $str07 = "Startup\\Documents\\User Data" ascii
        $str08 = "atomic\\Local Storage\\leveldb" ascii
        $str09 = "com.liberty.jaxx\\IndexedDB" ascii
        $str10 = "Guarda\\Local Storage\\leveldb" ascii
        $str11 = "AppData\\Roaming\\Telegram Desktop\\tdata" ascii
        $str12 = "Ethereum\\keystore" ascii
        $str13 = "Coin98" ascii
        $str14 = ".bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png.svg.xml.zip" ascii
        $str15 = "type..eq.main.Grabber" ascii
        $str16 = "type..eq.main.Loader_A" ascii
        $str17 = "type..eq.net/http.socksUsernamePassword" ascii
        $str18 = "powershell" ascii
        $str19 = "start-process" ascii
        $str20 = "http/httpproxy" ascii
        
    condition:
        uint16(0)==0x5A4D and 15 of them and filesize > 4MB
}
rule infostealer_win_acrstealer_str {
    meta:
        id = "63b4d6ff-0cab-44ec-9d53-bb2612371a48"
        version = "1.0"
        description = "Finds ACR Stealer standalone samples based on specific strings."
        author = "Sekoia.io"
        creation_date = "2024-04-22"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "ref.txt" ascii
        $str02 = "Wininet.dll" ascii
        $str03 = "Content-Type: application/octet-stream; boundary=----" ascii
        $str04 = "POST" ascii
        $str05 = "os_c" ascii fullword
        $str06 = "en_k" ascii fullword
        $str07 = "MyApp/1.0" ascii
        $str08 = "/Up/b" ascii
        $str09 = "Hello, World!" ascii
        $str10 = "/ujs/" ascii
        $str11 = "/Up/" ascii fullword
        $str12 = "ostr" ascii fullword
        $str13 = "brCH" ascii fullword
        $str14 = "brGk" ascii fullword
        $str15 = "https://steamcommunity.com/profiles/" ascii
        
    condition:
        uint16(0)==0x5A4D and 10 of them
}
