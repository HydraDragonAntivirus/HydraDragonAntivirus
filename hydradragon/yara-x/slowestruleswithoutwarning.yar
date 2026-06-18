
rule HiddenInAFile
{
    strings:
        $gif = {47 49 46 38 ?? 61} // GIF8[version]a
        $png = {89 50 4E 47 0D 0a 1a 0a} // \X89png\X0D\X0A\X1A\X0A
        $jpeg = {FF D8 FF E0 ?? ?? 4A 46 49 46 } // https://raw.githubusercontent.com/corkami/pics/master/JPG.png

    condition:
        ($gif at 0 or $png at 0 or $jpeg at 0) and (_PasswordProtection or _ObfuscatedPhp or _DodgyPhp or _DangerousPhp) and not IsWhitelisted
}


rule _ObfuscatedPhp
{
    strings:
        $eval = /(<\?php|[;\{\}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/ nocase  // ;eval( <- this is dodgy
        $eval_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/ nocase  // eval/*lol*/( <- this is dodgy
        $b374k = "'ev'.'al'"
        $align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/  //b374k
        $weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/  // weevely3 launcher
        $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/  // http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
        $nano = /\$[a-z0-9-_]+\[[^]]+\]\(/ //https://github.com/UltimateHackers/nano
        $ninja = /base64_decode[^;]+getallheaders/ //https://github.com/UltimateHackers/nano
        $variable_variable = /\$\\\{\$[0-9a-zA-z]+\\\}/
        $too_many_chr = /(chr\([\d]+\)\.){8}/  // concatenation of more than eight `chr()`
        $concat = /(\$[^\n\r]+\.){5}/  // concatenation of more than 5 words
        $concat_with_spaces = /(\$[^\n\r]+\. ){5}/  // concatenation of more than 5 words, with spaces
        $var_as_func = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/
        $comment = /\/\*([^*]|\*[^\/])*\*\/\s*\(/  // eval /* comment */ (php_code)
condition:
        (any of them) and not IsWhitelisted
}
