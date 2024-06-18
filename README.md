# Hydra Dragon Antivirus
<p align="center">
<img src="assets/HydraDragonAntivirus.png" width= 400px>
</p>
<p align="center">
<img src="assets/HydraDragonAntivirusGUI.png" width= 800px>
</p>
Cross-platform antivirus GUI for ClamAV, YARA and my machine learning AI module also Snort.
Guide:
Video: https://www.youtube.com/watch?v=L4oVZrEYaEY
Please install ClamAV based on your platform and enter database directory and please run clamd
Please copy the database folder signatures into your ClamAV database folder and copy freshclam.conf into your ClamAV config folder.
Also do the update definitions yourself, it's just a cross-platform interface for ClamAV and Hydra Dragon Antivirus.
Don't forget to install the modules via pip with requriements.txt and don't forget to compile the python script yourself.
Please don't use hash signatures as they are easily bypassed and take up too much space.
Also, don't forget to add ClamAV's clamdscan to the console so that the program can be run with just the clamdscan command on Windows, Linux, MacOS, FreeBSD, etc.
compiled_rule.yrc source code: https://sourceforge.net/p/xylent/git/ci/master/tree/backend/rules/yara I have just compiled the largest file or you can look at compiled_rule.yar.
I recommend killing malicious processes first, then using quarantine, delete or something. For Windows, first install clamav from clamav.net/downloads.
Then add C:\Program Files\ClamAV to the terminal, as this script uses ClamAV directly from the terminal, then run the script to use it. 
Also install Python from python.org Note: If you can't add ClamAV to the console on Windows etc, then copy it to the ClamAV folder
For Windows you also need download https://npcap.com/#download for scapy and netsh advfirewall reset for reset firewall settings
For Snort download at there: https://www.snort.org/downloads and add to console
If you want run web signatures then you need load website signatures by button
HIPS folder things should be add Snort rules folder also config things
If you want do scan, you first need enable it by button
You need stop clamd manually after close this program or after update definations
For more protection for Windows please install MBRFilter at mbrfilter folder
Don't quarantine any files during the scan or delete.
To avoid crashes pause or stop scan while scan is running at scan manager screen.
Don't forget clean temp files older than 24 hours.
Just comment Example in clamd.conf.sample and rename it with clamd.conf then copy to config folder of ClamAV.
You can install clamd with clamd --install
# Snort Notes
Notes
Snort on Windows does not like SO rules - that is why they are disabled.

If Snort can't find blacklists, whitelists and other files - an error will be thrown. They need to be presented, even if empty.

Current files that you must create: C:\Snort\rules\black.list and C:\Snort\rules\white.list. If you want to use different files - you must modify the configuration file manually.

Also the configuration presumes that your installation is C:\Snort, if it is different, then change it manually from the config file.

https://rules.emergingthreats.net/open/ Download Rules From There

Don't forget to check all boxes at npcap also if you get this warning then ignore it. Wireshark is not required:  https://ask.wireshark.org/question/33483/why-do-i-get-this-wireshark-is-installed-but-cannot-read-manuf-when-i-use-wireshark/

# Download Machine Learnin Malware And Benign Database
- Malware Database: https://mega.nz/file/1CcGTRoQ#Chp5oNpk2ExhcCjrlY1Q_n0w9ToF5ozGdyn5hjfmQdk
- Benign Database: https://mega.nz/file/wOVmTJTS#qywYEZWYBKmvc8z6CtLNxJh4L9MBcvQIY9Mb7pQapik
- Notice: Only contains PE files.
  
# Tests
![Winnerishydra](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus/assets/142328963/5575279e-906b-42b4-a49a-3f1251076473)
![losernorton](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus/assets/142328963/c52e9ac1-b533-4e25-9c2f-837ad432792c)
![KVRTuptodatebutloses](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus/assets/142328963/1968d793-9b26-430d-aab9-f1afe31c3938)
MalwareBazaar 16.0.6.2024 samples
----------- SCAN SUMMARY -----------
Infected files: 120
Clean files: 11
Total files scanned: 131
Scan Time: 00:02:44
-----------------------------------

----------- DETECTED THREATS -----------
- Scanned file: C:/Users/victim/Downloads/2024-06-16\0c5787229f775fcbdd5d466b411c628480c0a0b655b1f7705b90448296916112.zip - Virus: Sanesecurity.Foxhole.Zip_exe.UNOFFICIAL
-Scanned file: C:/Users/victim/Downloads/2024-06-16\03f84e09687b4311d9367965fbe59e34a9202f1d7ab9cafc0872a16c6077621e.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\0c482c7a001606464d69a2ea0abb3861aa82835228abddac485dc1d279b9d43c.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\19a6d211adfa41d815d800f6c7849983fd6543cc178f4d048a3a615c4c8ea521.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\033056e2a4dc8e10c9ba7d7ec078376a565d02046bb632bcd6c3be336a92a36e.exe - Virus: SIGNATURE_BASE_CN_Honker_Injection_Transit, CN_Honker_Injection_transit
- Scanned file: C:/Users/victim/Downloads/2024-06-16\1420b45b7ca1b037bc1e4c2653065fa46069dc3c7d271557c7f6f26801323b32.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\0466159525cb3fab5109b4067f0a429f9880275f7e37aee7b3311fb3356c59c9.exe - Virus: Sanesecurity.Malware.30425.UnRegNetReactor.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\27d133a8db57514821b08fbb3aad34677c7f195b01e181d2202095c40c9a56fe.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\20da682ddbb5d3742dcee36b331d65ded9e97a90b38794659495777d8be7cb16.exe - Virus: Win.Trojan.Scar-6903585-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\1eb7992ca97e8bb0b65faeaf69b30d9ac84406b1f35d6a900f8de748ab6a6a64.exe - Virus: Win.Packed.Msilmamut-9950860-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\21b427d71be2fdfa820c0595fa034c22a8b9c8140bc24d8ba22fbc248d2801b1.exe - Virus: win_whispergate_auto, MALPEDIA_Win_Whispergate_Auto, PYAS_Rules_8598, PYAS_Rules_14245, PYAS_Rules_15302, PYAS_Rules_15303, PYAS_Rules_53720, PYAS_Rules_8598, PYAS_Rules_14245, PYAS_Rules_15302, PYAS_Rules_15303, PYAS_Rules_53720
- Scanned file: C:/Users/victim/Downloads/2024-06-16\1e75d30c8ce7cfc4bc719410167139676349c2c48c1836f96a260d5222a182b9.elf - Virus: Sanesecurity.Malware.29325.LC.Pl.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\0d96380fc93472acb731850bf6bd0c4adfea039fc3b58d9433f6ad48870cb24c.exe - Virus: COD3NYM_SUSP_OBF_NET_Confuserex_Name_Pattern_Jan24
- Scanned file: C:/Users/victim/Downloads/2024-06-16\3d991779371d48196dc0df05cdac8aff0f72025795404843421ab8c8afd116d6.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\338ff4db92ec9799acbef90b2260f32f794f1066acc1fd0513258b107124f696.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\376e55fb475cdb496f46f8a7457af4bbe082c1697504e5af2b21175d01a2908e.elf - Virus: Unix.Trojan.Mirai-9950938-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\412dde5b06d7bd1c11f90045fc823818a690c87b044c1aa3a86e1a3fe8150f98.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\345557501b7f40267acc895d2e2c883652858df816f7ea3b2dd8779fd4c1c6cf.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
-Scanned file: C:/Users/victim/Downloads/2024-06-16\3f122e8743aa6eb1f85ca9c84189ba0c58f078a2d9b45d026e941da8263c00e5.exe - Virus: Win.Malware.Metasploit-10022275-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\311763efffec17158382ebb545b5e34116ff3ed5f4ccdbd2f00db805992d928c.exe - Virus: Win.Packed.Msilmamut-9950860-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\1079681f1afa4959cb06f3d4a3725783331a490bbef656af5277f8bac1485e43.exe - Virus: ttp_lib_openssl_no_version_str_unsigned, n26bb_1bc59c94cee30932, n26bb_1bcac6a793bb0b32, n26bb_2b48a699c2220b32, n3e9_0b1215a1ca000b16, n3e9_15b2d122d3bb1932, n3e9_1bc2948dee610b16, n3e9_1bc2948dee650b16, n3e9_1bc29498dee30b16, n3e9_1bc2949dee220b16, n3e9_1bc2968dee610b16, n3e9_1bc2b44bbe630b16, n3e9_1bc49cd6dae30932, n3e9_1bc6844bbe630b16, n3e9_1bc6949dc6210b32, n3e9_1bc694a2d3bb1b32, n3e9_1bc69c94ce830916, n3e9_1bc69c99c6210b16, n3e9_1bc7444fee610b16, n3e9_1bc746a8d9fb0b16, n3e9_1bcac44f6e210b16, n3e9_1bcac48dee210b16, n3e9_1bcac4cfee630b16, n3e9_2b2a93b9ca200932, n3e9_2b542b1dca210b32, n3e9_2b54ca98c2210b36, n3e9_393173c395964b26, n3e9_393173d396566b2e, n3e9_529913e9c8801912, n3e9_52993ec1cc001912, n3e9_529993e9c8801912, n3e9_529b33a9c8800912, n3e9_53d99ec1c4000b12, win_biodata_auto, borland_delphi_6_7, Win_Downloader_Dadobra_31, Win_Downloader_Banload_78, Win_Spyware_Zbot_1279, TrojanGBotSampleA_Malex
- Scanned file: C:/Users/victim/Downloads/2024-06-16\41d3bee31509daf10b377cfb3bd612380b90cb2d90d4731497997f76bad7bc72.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\311198eeb76c5cb081151452a73159c194300121515e3fd875429152ae7761aa.exe - Virus: Win.Trojan.Farfli-9645812-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\44fbc00485c6ccd92bad4364ed91dc775d4b97698f58795b92abc228d9827bf2.elf - Virus: Sanesecurity.Malware.28880.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\419c6a1949a650419b4669a77e213ae90b186e03a2d5ef559ebaaf2344293b5f.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\2f2a657e78d19142f29590d7356400838486c7365da53e457de448eb49f90ddc.exe - Virus: Sanesecurity.Malware.30425.UnRegNetReactor.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\458bd31442fcac3f42d3cf0acb8bcd13b4115c355280f44172a6ef8a3d877ff8.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\4833f6e7b2beb3821ccd544a936f3d6db6403ee58c05038f15f2d1544f2acd3c.exe - Virus: Win.Malware.Generic-9883083-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\0452c003c4793d304121fdc3fa8ddf9f39f4eccc452fe1506dc89998c2e6129a.exe - Virus: Win_Spyware_Zbot_1279, shellcode_at_entry_point
- Scanned file: C:/Users/victim/Downloads/2024-06-16\473521836838a2e2a1c21ea30514c47b14b29536df436e553b6b177b15142c08.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\58bb15a0a0281ab6ae6831dbd00e7d72528c9a45c047aee36abeae698de8e909.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\4add78141d7a40f568b18603b21f9888b90344a446ab50f8bd76bdaafbebd984.elf - Virus: Sanesecurity.Malware.28880.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\43e6dfa30f18980c797aff5199f16a00a9a315e7f2da3691b1c5d2f67f44564d.exe - Virus: Win.Malware.Gotango-7000352-0
 - Scanned file: C:/Users/victim/Downloads/2024-06-16\63967c45251f1094e81ae4859415409165b2d449d0dea56276b7d9523da3051d.rar - Virus: Sanesecurity.Foxhole.Rar_fs2695.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\603f5bbac15c3091a446f42fb9c9fcb26892a9a2d14c40f572b526307c502f10.elf - Virus: Sanesecurity.Malware.28880.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\573c9cd50b73dbd409af40dc852bc5f77d03164a1cb484f920ba6b3ec1072811.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\581a31b1ddaa6eea7b78a57b4615d8def8c688aeb0dd38da8a0ef3d248e88892.exe - Virus: Win.Trojan.Uztuby-9855059-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\72d50d7d7710258906eaf576bfda655d3fe04cd5c580ca2863f7e31c2aca3e86.elf - Virus: Sanesecurity.Malware.28880.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\5c303db4d277fac2db0c0b38eb814081cbb53f694169c7c583b750c3e498db54.exe - Virus: Win.Keylogger.Lazy-10031941-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\6152d7d9336d0430a447f14bcd5f5566e13d8180afa86146a91a07474811f7c0.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\599ba59f51a3bb9db2dc7a572df715182d049fefa829e6ff6debdd38d20b7632.exe - Virus: SIGNATURE_BASE_CN_Honker_Injection_Transit, CN_Honker_Injection_transit
- Scanned file: C:/Users/victim/Downloads/2024-06-16\5fa00282686fe881e4a1942db16fb40ed6632482e922afac231ce98bfcc58790.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\651dd96a90091b85c380db91123753a1a1bfb4182519bdf4d8ee4f387a900e16.exe - Virus: Sanesecurity.Malware.29063.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\6931722698fe79bcb6fc2c39545452d799b9e32ea64a4efcf0df72c82469cf09.apk - Virus: APT_malware_1, Dragonfly_APT_malware_1, PYAS_Rules_1974, PYAS_Rules_1975, PYAS_Rules_9201, PYAS_Rules_49486, PYAS_Rules_1974, PYAS_Rules_1975, PYAS_Rules_9201, PYAS_Rules_49486
- Scanned file: C:/Users/victim/Downloads/2024-06-16\7d6bfc385f9082e2e1136dfc049e683e50f302dedac19aabb80132546f88cc32.exe - Virus: Win.Malware.Metasploit-10022275-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\69f05dd68aee3409475f267cdfed99e3bf77c08c4ee04979318eb78ddd96bd9e.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\1e09aac18f6374804e04c6ba11b5b96d766fca4c9cd3d7085c25c59489168fcb.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\6fe66b1bf0aa4b138f7d4e1c3021128dd87e99ef7da3193f267acb92c0e8d909.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\7453c9ff4240a0cf563eb28176f8478fac4b076cd6a7ad0ac3d727338a0734af.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\84190ffd7bf746a33d14ba1daa4b242a351db1e77c9aa41f495faa19a98def04.exe - Virus: Win.Packed.Msilzilla-9952790-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\8c3ec0d50dcb3d53ed59b59bdeed03a2b612eb621e5165abcac10b2263e5b2bd.exe - Virus: PEiD_01090_Microsoft_Visual_C___8_0_, PEiD_01247_MSVC___v_8__procedure_1_recognized___h__, Win_Trojan_Obfus_6, PYAS_Rules_7582, PYAS_Rules_47446, PYAS_Rules_7582, PYAS_Rules_47446
- Scanned file: C:/Users/victim/Downloads/2024-06-16\934dd6cd9571839de7c40a6d26881b56759bd1267a5f4baab39e47f42c8c8206.exe - Virus: Sanesecurity.Malware.30425.UnRegNetReactor.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\832fe81a4ccd85cc237685d8928c51c5cde53d74086700858c09a42c795a6cba.elf - Virus: Sanesecurity.Malware.28880.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\8ff4a66cbb6e2c5d533470e6b3c01dc0658f859a291604158df7f631ded35e2d.exe - Virus: Win.Dropper.Farfli-9950040-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\52e7510e97f558788067937c97a268ad4951d22f8b94d87855bcb3dd4d6e6708.exe - Virus: _Nullsoft_PiMP_Stub__SFX_, Nullsoft_PiMP_Stub_SFX, PYAS_Rules_817, PYAS_Rules_817
- Scanned file: C:/Users/victim/Downloads/2024-06-16\76fc0359cb26a2df509d072b2b5e925de39dc95d502f5173b45d11406bab815d.exe - Virus: Win.Packed.Msilmamut-9950860-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\5c9c8ee0fd56497f8d1662c9d9347211761e969ab2af67d2c02ccb8588519f6e.exe - Virus: DotNET_Reactor
- Scanned file: C:/Users/victim/Downloads/2024-06-16\433a35efdecf92cc7d6943cbce288405666becb1206ad42374781f237bf86467.exe - Virus: o26bb_4986b4c59ee30932, o26bb_4986b4cbc6210b32, o26bb_4c83a949c4000b12, o26bb_4ea6e849c0000912, o26bb_594a4e43ca210932, o26bb_594a4e6bee208932, o26bb_594a4ecbc6620932, o26bb_594a5c9cce620932, o26bb_594e4a6bca200932, o3e7_33b31ce9c8800b32, o3e9_594e4a629bd30932, o3e9_594e4e6adceb0932, borland_delphi_6_7, FGint_FindPrimeGoodCurveAndPoint, Win_Spyware_Zbot_1279
- Scanned file: C:/Users/victim/Downloads/2024-06-16\9659a1ba632b34f7b3e22c5b7b96d01902a5ae3e3c3a4e3a9dd2269695c7cef0.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\83bbc1a455c7f36e56e703447fabea46228304ca9ea110a857e4a0f06c0fab69.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\b505f68abadced947bf0e934b518cad13569bc46e9ae37b5918585acb5dc45af.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\bfb4f258b9600f86e43da9ac8137972db7168cb99b7d81814d5092249a66fd20.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\8fbaa2a402ad9a256fe27289c41d45836870fe804126679a076b0f6e0116808c.apk - Virus: APT_malware_1, Dragonfly_APT_malware_1
- Scanned file: C:/Users/victim/Downloads/2024-06-16\9958bfa83b27cdb9af34ce4a108130721242038478d6134a952fdbc28e8e7e5a.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\b48630434487e7b216a761b18f5781340abb1d9da5a2af54cfe62dfd676a256e.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\a6aa41c4146d958de74395c388ef2af7cc1b47c381c8d4661130d510143e7329.exe - Virus: Win.Keylogger.Lazy-10031941-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\c2cf72416cd1a5cba005636dfa5ca341c92ed72a62ca0423ed55d3d4eb33721a.exe - Virus: Win.Trojan.Uztuby-9855059-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\9ad7cace6812744fbe11bb1357a60e831783856c0595dca5a4a538db282682f1.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\b50c81f34cf0fb3b8a520fb81b64c747b768e853ab4b768a0a8b0539111e4616.exe - Virus: Win.Malware.Lazy-9969515-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\d7c6de7b8a029adc20b7548bcd774e5b563d83093fc8815f1d2a2a341e788d70.elf - Virus: Sanesecurity.Malware.28880.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\c93a840e32e2ea251cbffb9c73c1c8f72ff6eed85a74ded6b06956dcc2175ad8.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\7f1c2b5a8663e5ee11535c88bbe738b844552145b8703af21a4f6f82365bfb32.elf - Virus: Sanesecurity.Malware.28880.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\dada6a3924a4b19b5393e303599642dda1c603ebe0e7620dbfd4eddc5a1f4b8d.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\7945232c2c74f1feb5f2711e2bfb1de7c3f04b4781cc34821350d831da89bdeb.exe - Virus: Prime_Constants_long, Win_Trojan_Obfus_6
- Scanned file: C:/Users/victim/Downloads/2024-06-16\a2b34479327477c185736f3d540ab29f6a4d1b9f3b66109e4e706760daec5b61.zip - Virus: Sanesecurity.Foxhole.Zip_exe.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\dc288149929d93cc33f1edfe82d4b92cb05c5b681e992dc18936df829b2b5e0e.exe - Virus: Win.Packed.Msilmamut-9950860-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\a252e2467a01c3162af02783db4fa0f1144fa7b9f1f25e1bfdacff2404dc4c51.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\c58049ff195a22aae0ea2347da63b2a135fe1e5295d427e2edf7cbc611715242.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\ba13ce53a9e5427803d6f1a70a46823277474be01f80349399b856ce299a627e.exe - Virus: Sanesecurity.Malware.30425.UnRegNetReactor.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\957f74c37efd8bcf5182bb523fc0b384e3ec7b0e130c556ad2f62d8b42716530.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\f684c1d7d38edb825e69e4974de3235927a99a17cbd1b483697d436fa4036709.elf - Virus: Unix.Dropper.Mirai-7135890-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\7b04123c12624c5861df853aebebc1261279624b1ddd28ce6e8585ab61669421.exe - Virus: ttp_lib_openssl_no_version_str_unsigned, n26bb_1bc59c94cee30932, n26bb_1bcac6a793bb0b32, n26bb_2b48a699c2220b32, n3e9_0b1215a1ca000b16, n3e9_15b2d122d3bb1932, n3e9_1bc2948dee610b16, n3e9_1bc2948dee650b16, n3e9_1bc29498dee30b16, n3e9_1bc2949dee220b16, n3e9_1bc2968dee610b16, n3e9_1bc2b44bbe630b16, n3e9_1bc49cd6dae30932, n3e9_1bc6844bbe630b16, n3e9_1bc6949dc6210b32, n3e9_1bc694a2d3bb1b32, n3e9_1bc69c94ce830916, n3e9_1bc69c99c6210b16, n3e9_1bc7444fee610b16, n3e9_1bc746a8d9fb0b16, n3e9_1bcac44f6e210b16, n3e9_1bcac48dee210b16, n3e9_1bcac4cfee630b16, n3e9_2b2a93b9ca200932, n3e9_2b542b1dca210b32, n3e9_2b54ca98c2210b36, n3e9_393173c395964b26, n3e9_393173d396566b2e, n3e9_529913e9c8801912, n3e9_52993ec1cc001912, n3e9_529993e9c8801912, n3e9_529b33a9c8800912, n3e9_53d99ec1c4000b12, win_biodata_auto, borland_delphi_6_7, Win_Downloader_Dadobra_31, Win_Downloader_Banload_78, Win_Spyware_Zbot_1279, TrojanGBotSampleA_Malex
-Scanned file: C:/Users/victim/Downloads/2024-06-16\e124f61974fb41bc429b019e78e2c899c66601046269b9d8374020ce37026fb9.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\ba2b1c201c311909fe2f99c2314ef45de4da25100e91d38504412040824b4a39.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\cbeb7eeb2ba0e370efa87676217c68f0de0067a465d4d0b422d78ddb3168ec1e.exe - Virus: Win.Ransomware.Bandook-9859375-1
- Scanned file: C:/Users/victim/Downloads/2024-06-16\ecec0cf3a79928b39ebaedccd677cf4a168441801c99cf5d9ee333cf1a161d2f.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\e5d62ab8315f16292765038ccf6c4f46d69b6c9ca988d89211ac1d590c57e35d.exe - Virus: Win.Trojan.Scar-6903583-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\fbbaa8d10be4b287a9f85e4899380d1294fecce6d25f49a5d49ff9bb54d3fba2.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\eeeb3abb1dc4f7439ea12706fd5879ea4e25ee356b6c000eed646b21a18d0d37.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\e791ccfbf3d108a3ef4c0122579866566a6401e81c3869033e7b3e39c2c11420.unknown - Virus: win_stop_auto, Windows_Ransomware_Stop_1e8d48ff, ELASTIC_Windows_Ransomware_Stop_1E8D48Ff, MALPEDIA_Win_Stop_Auto, Generic_squared_map__32_big_64_, Generic_squared_map__32_lil_64_, PYAS_Rules_9275, PYAS_Rules_44182, PYAS_Rules_9275, PYAS_Rules_44182
- Scanned file: C:/Users/victim/Downloads/2024-06-16\f6ec0b8d3141cec258d8ce4122112e4c31f78f5f2651632d827bfcc91d0da81d.elf - Virus: Sanesecurity.Malware.29524.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\b030a9aaa27be2c9db6c0f15e95626025f51430466b13a196908b1ec4172160c.exe - Virus: Win.Dropper.Nanocore-9189507-1
- Scanned file: C:/Users/victim/Downloads/2024-06-16\2a0b637d456f574fe026f530496918f7735999c587205295daf3084344c00b3e.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\a9dd6da84775261c48db7a25f937586a5c7d79e802d8e5bf22466e936b3643ac.exe - Virus: Sanesecurity.Malware.29063.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\dd1b3e859dabe893249b1084e998bdd90537a3451df527a46ecea958e15c10f8.elf - Virus: Sanesecurity.Malware.28880.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\f5df8a6c7c08a5d9ae2104613cfb332dd636aaf3d22e67da18cda744b2b0e7d0.exe - Virus: Win.Packer.pkr_ce1a-9980177-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\d343a781dec5fea6f9e8bb491fe8334889fdd4c4d5b4f0c768ca2233da8f41bd.exe - Virus: Sanesecurity.Malware.28889.FZF.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\f702ce107528b41bd2d6f725779f898d63a2dd1139cd5ae6da85d2eb6b51ca8e.exe - Virus: Win.Trojan.MSILPacked-9942256-0
- Scanned file: C:/Users/victim/Downloads/2024-06-16\a5faf4e08934c3e4dd4bc630084f0a6839bc4d454ea369b47ec955c2f62f8f16.exe - Virus: SIGNATURE_BASE_CN_Honker_Injection_Transit, CN_Honker_Injection_transit
- Scanned file: C:/Users/victim/Downloads/2024-06-16\c33619d1f7681d927b9a01e641821fe9cb8dc232bada4447a80a716d4cc8d978.exe - Virus: ttp_pe_size_of_code_gt_filesize, INDICATOR_EXE_Packed_VMProtect, _VMProtect_1704_phpbb3_, VMProtectSDK, VMProtect_1704_phpbb3
- Scanned file: C:/Users/victim/Downloads/2024-06-16\f6e6b144db80e7002029cd92af455a5a211e150489f97d51a1e48e30b426ff76.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\fe87477d6c1b71ba3de4d7c46b4015143ae94fb23a68f1ba34498ac11c14df23.elf - Virus: Sanesecurity.Malware.28940.LC.UNOFFICIAL
- Scanned file: C:/Users/victim/Downloads/2024-06-16\955701e22db690273e0b58ceed5dba69a98430886d5650efabe369736d8a1332.exe - Virus: ttp_lib_openssl_no_version_str_unsigned, ELASTIC_Windows_Virus_Expiro_84E99Ff0, RNG__original_numbers___32_lil_AND_
- Scanned file: C:/Users/victim/Downloads/2024-06-16\ab5b46359799fbe4eeb71dd98eef602b5f6d061b75313269af094468620cb231.apk - Virus: APT_malware_1, Dragonfly_APT_malware_1, PYAS_Rules_1974, PYAS_Rules_1975, PYAS_Rules_9201, PYAS_Rules_49486, PYAS_Rules_1974, PYAS_Rules_1975, PYAS_Rules_9201, PYAS_Rules_49486
- Scanned file: C:/Users/victim/Downloads/2024-06-16\aafd3c081285567e3964f9cbe40ad879d082c33a3b45019de4c7e6b2d20aed4e.dll - Virus: PEiD_01903_PureBasic_DLL____Neil_Hodgson_, PureBasicDLLNeilHodgson, _PureBasic_DLL__Neil_Hodgson_, PureBasicDLL, PureBasic_DLL_Neil_Hodgson, PureBasic_DLL_Neil_Hodgson_additional
- Scanned file: C:/Users/victim/Downloads/2024-06-16\0dbd951b6a7b43300cf161aa7df612560c38a92743c47b71b034aec4f54c51c7.exe - Virus: o26c0_59eb2802d0000132, Process_Doppelganging
- Scanned file: C:/Users/victim/Downloads/2024-06-16\5c459e473131fcebab88c0c098a1b9f14477a5974186dfd84b15e03f40b7f071.exe - Virus: IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\b8a2c872548f815d005ffca0cfb1cd1980f9c9b86b413ad2477f5ee2c81ccb26.exe - Virus: o26c0_59eb2802d0000132
- Scanned file: C:/Users/victim/Downloads/2024-06-16\e316fdd76cef9a954dd1013b45bf6ab2254a294570d57ec7126fb1444af771b1.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\c86218367d0caf1b3939762afbb20f97e941da48d10725eb49239126dacd2422.exe - Virus: Algorithm_DESBuffers, PYAS_Rules_368, PYAS_Rules_809, PYAS_Rules_817, PYAS_Rules_847, PYAS_Rules_968, PYAS_Rules_3179, PYAS_Rules_56751, PYAS_Rules_57182, PYAS_Rules_63782, PYAS_Rules_65516, PYAS_Rules_65804, PYAS_Rules_67704, PYAS_Rules_67883, PYAS_Rules_368, PYAS_Rules_809, PYAS_Rules_817, PYAS_Rules_847, PYAS_Rules_968, PYAS_Rules_3179, PYAS_Rules_56751, PYAS_Rules_57182, PYAS_Rules_63782, PYAS_Rules_65516, PYAS_Rules_65804, PYAS_Rules_67704, PYAS_Rules_67883
- Scanned file: C:/Users/victim/Downloads/2024-06-16\dcfc164e662e2129e5119359b0c448a73f0fe879c425a13a0ecbd660bb347cb4.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\d3de5c5a55f88b083d686f83f84b095748a8dad746facd372ac55243bfa30325.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\dbc0286944b0a1c33ac03695f3cdba2c69b151b9552afe7504d743fa9b392bc0.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\929804f60f8f3a0b0d7862cd91eb6be0a2ba694c4a28e3f9fa2d65ff171469a6.exe - Virus: PYAS_Rules_817, PYAS_Rules_16686, PYAS_Rules_16687, PYAS_Rules_16688, PYAS_Rules_817, PYAS_Rules_16686, PYAS_Rules_16687, PYAS_Rules_16688
- Scanned file: C:/Users/victim/Downloads/2024-06-16\dbe8b9d981660b11fd58e0acd0fc254ca74782db2f79ea664d076005b38f6013.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\fbd864050124a7e4bca9f618b6343125f8a38041d99a5ecceca3686a3da57e32.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\9232fd1e7662b3c2ef8bce1e720c6c5ea44606001fd78a59cae59079b3d1c074.exe - Virus: Win_Spyware_Zbot_1279, shellcode_at_entry_point
- Scanned file: C:/Users/victim/Downloads/2024-06-16\c8e1f18ea3447d842600e7fd16cefba9bf010845a9e455a5803548c46f481cc3.exe - Virus: ttp_pe_size_of_code_gt_filesize, IsBeyondImageSize
- Scanned file: C:/Users/victim/Downloads/2024-06-16\f07465ea271cedaffa98eb8fe5160e9f50c71b326826cf32c6ce618955bc18bb.exe - Virus: XOR_hunt, ttp_pe_size_of_code_gt_filesize, SIGNATURE_BASE_SUSP_Xored_URL_In_EXE, SUSP_XORed_URL_in_EXE
- Scanned file: C:/Users/victim/Downloads/2024-06-16\f511b148321d0f3bcbf624f59b103da5f868e92e67a068c3f86c0b584b5fc620.exe - Virus: Algorithm_DESBuffers, Blank_Grabber, Luna_Grabber, PYAS_Rules_368, PYAS_Rules_809, PYAS_Rules_817, PYAS_Rules_844, PYAS_Rules_847, PYAS_Rules_1646, PYAS_Rules_3179, PYAS_Rules_5185, PYAS_Rules_47308, PYAS_Rules_49341, PYAS_Rules_51695, PYAS_Rules_53480, PYAS_Rules_56751, PYAS_Rules_57182, PYAS_Rules_61509, PYAS_Rules_65516, PYAS_Rules_65638, PYAS_Rules_65804, PYAS_Rules_67704, PYAS_Rules_67883, PYAS_Rules_368, PYAS_Rules_809, PYAS_Rules_817, PYAS_Rules_844, PYAS_Rules_847, PYAS_Rules_1646, PYAS_Rules_3179, PYAS_Rules_5185, PYAS_Rules_47308, PYAS_Rules_49341, PYAS_Rules_51695, PYAS_Rules_53480, PYAS_Rules_56751, PYAS_Rules_57182, PYAS_Rules_61509, PYAS_Rules_65516, PYAS_Rules_65638, PYAS_Rules_65804, PYAS_Rules_67704, PYAS_Rules_67883
## VirusTotal Undetected Samples By Hydra Dragon AntiVirus
- https://www.virustotal.com/gui/file/1f7002c62e393d341095fcff64984ff4940ef7c11b9009d2a533ea485f9084a6 Kaspersky: Clean
- https://www.virustotal.com/gui/file/5b58d926eed5092379ee1a476cb4faa6b5ea3f8ad79e8c2e0c52c0b91784bc38 Kaspersky: Malware
- https://www.virustotal.com/gui/file/4b4c5aed86e3530fe1a847c367cd0ed5ec050b7d6ff95d09838bea52c9df470a Kaspersky: Malware
- https://www.virustotal.com/gui/file/d7fef2df3f4f1d7222ee156cb6f56410c9b17587f0614940b03ce062e8fcca65 Kaspersky: Malware
- https://www.virustotal.com/gui/file/ecc6b2506aeaac13da0562a6a5d35c802eea9c6232c49cc4583d7c5c13bbbc0f Kaspersky: Malware
- https://www.virustotal.com/gui/file/30af33cc275298269f2f8bb65529f0861090d49984d2200fa21812bdd558174a Kaspersky: Malware
- https://www.virustotal.com/gui/file/80a6c864b32e7f7b497629806ace23b4eb1f71419de8064e99dc6299299dbc88 Kaspersky: Clean
- https://www.virustotal.com/gui/file/e96b455245e3e29c30bcbaf2836654435beca58d7e0e740fef3d5449caa6cfca Kaspersky: Malware
- https://www.virustotal.com/gui/file/f9a8439b27e33b82578b1bac2e1abef4e8bf15cbef1bb935b242bbdda0535478 Kaspersky: Malware ClamAV: Malware
- https://www.virustotal.com/gui/file/6b5c2e9a2ef36412b2636236ade5530c59573b51b07fe224fd980911cbb7b976 Kaspersky: Malware
- https://www.virustotal.com/gui/file/7f40bfb86707faf0ec8978614840ab858320d1978bc351546833272b7b70c854 Kaspersky: Malware ClamAV: Malware
# Hydra Dragon Antivirus AI Generated Text
Overview
Hydra Dragon Antivirus is a cross-platform antivirus GUI that integrates ClamAV, YARA, a machine learning AI module, and Snort to provide comprehensive security solutions. This policy outlines the security measures, practices, and guidelines for users to follow when using Hydra Dragon Antivirus to ensure optimal protection and system stability.

Installation and Setup
ClamAV Installation:

Install ClamAV based on your operating system (Windows, Linux, MacOS, FreeBSD).
Configure the database directory and run clamd.
Copy the provided database folder signatures into your ClamAV database folder.
Copy freshclam.conf into your ClamAV config folder.
Update the definitions manually.
Python Environment:

Install required Python modules via pip using the requirements.txt file.
Compile the Python script yourself.
Command Line Configuration:

Add clamdscan to the system path for easy access to ClamAV functionalities.
On Windows, add C:\Program Files\ClamAV to the terminal path.
Additional Software:

Download and install npcap for Scapy support: Npcap Download.
Reset firewall settings using netsh advfirewall reset.
Download and configure Snort: Snort Downloads.
Install MBRFilter from the mbrfilter folder for enhanced protection.
Usage Guidelines
Malicious Process Handling:

Kill malicious processes before performing quarantine or delete operations.
ClamAV and ClamDScan:

Ensure ClamAV is added to the console path.
Manually stop clamd after closing the program to free system resources.
Snort Configuration:

Snort on Windows does not support SO rules; ensure they are disabled.
Create necessary files such as C:\Snort\rules\black.list and C:\Snort\rules\white.list, even if they are empty.
Adjust the Snort configuration file if your installation directory is different from C:\Snort.
Signature and Rule Management:

Avoid using hash signatures as they can be easily bypassed and are space-consuming.
For web signatures, use the appropriate button to load them.
Add HIPS folder contents to the Snort rules folder, including configuration files.
Scanning Practices:

Enable scanning via the designated button before starting a scan.
Do not quarantine or delete files during an active scan to avoid system crashes.
Pause or stop scans using the scan manager screen if necessary.
Clean temporary files older than 24 hours to maintain system performance.

Maintenance and Updates
Regularly update ClamAV definitions and Snort rules to ensure the latest protection.
Follow best practices for security updates and patch management.
Contact Information
For any security concerns or issues, please contact the Hydra Dragon Antivirus support team.
