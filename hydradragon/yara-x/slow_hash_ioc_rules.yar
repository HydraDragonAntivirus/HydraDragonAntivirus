
rule IOC_NA_7z {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-15 19:09:26"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "7z"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "23c1510d3d22c30ed9ef184edf9f2e078906915b5e37e67b023230b8cd60403f" or
    hash.sha256(0, filesize) == "f52747475852e8cf7e34f28be8946365d35d52a8d2b5339ec8ce9a302a4bf049" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_xlsx {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-15 18:46:34"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "xlsx"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "ad208fe787c74f455a317a5050c3462c8236ed6e3c58f9c6082147ca09902335" or
    hash.sha256(0, filesize) == "e583e248ba55bfc925e3ea9bb9f45bbf4473b87cdec850a62dff5f25f4945dff" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_FORMBOOK___exe_ {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_FORMBOOK_LAB"
    date_IOC   = "2023-11-15 07:39:10"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "FORMBOOK"
    file_type  = "__exe_"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "a0a6a1c54775713ad3e884b6bc49f2c74f393464a69175c8713221504ae6d72a" or
    hash.sha256(0, filesize) == "cf33cf1b99aec2e58ebff495b327734f9d444884af6846ea086c210bd4ee2623" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_FORMBOOK___ace_ {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_FORMBOOK_LAB"
    date_IOC   = "2023-11-15 07:38:59"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "FORMBOOK"
    file_type  = "__ace_"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "4b0088a5ea5b554b183064229db63803bac5538cd7cb9f5f1092e50dce0d4ade" or
    hash.sha256(0, filesize) == "7d3b00a4fcda70ad6620192068b141cc01d43f1d4ed650ddd65593cb24f7f9c1" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NJRAT_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NJRAT_LAB"
    date_IOC   = "2023-11-15 03:31:26"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NJRAT"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "dd1200655c6acff2c7a4d4d3a0c86399a9f23823535e9e6224860a521f360678" or
    hash.sha256(0, filesize) == "ac8753ced58a7ac1ee13dc6de9f1007cdc10e9be93e398f4fa64689f2ff22ae7" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_COINMINER_msi {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_COINMINER_LAB"
    date_IOC   = "2023-11-14 18:22:54"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "COINMINER"
    file_type  = "msi"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "c29a303468ce5c3274902765deac7a76d4fa98c10657be06acd7d1a358341c93" or
    hash.sha256(0, filesize) == "ca4a43510da2087936b6a7aa6790d506f4aba6b1ff1f1d9fcc8fcba37fb47749" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_DCRAT_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_DCRAT_LAB"
    date_IOC   = "2023-11-14 12:45:44"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "DCRAT"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "07fa9ac4502b2a0ba83036450abbe28d6656c8941abf5180e81650550aa50a4e" or
    hash.sha256(0, filesize) == "b84309a3904c7956ca30b8803e41862ab7b4de1dd943f57ce5a211f2479e48c4" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_AGENTTESLA_z {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 12:24:08"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "z"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "f225748d809c050133e79a599b01e18472d8bd66591e679c54e66c2b33c43509" or
    hash.sha256(0, filesize) == "7a8f27f3ad544c3c482f04e8fcb92fdeb4d19250228b3522ad4490aad2ae4b8d" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_REMCOSRAT_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_REMCOSRAT_LAB"
    date_IOC   = "2023-11-14 11:57:52"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "REMCOSRAT"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "12b615a29aa38f8084b6e23828007897953c887037a8ebea8828c62cfb396831" or
    hash.sha256(0, filesize) == "392624a0ee0d3c34ae9ad9607e9f8683156447379beac0ec8519c70dedbb74d0" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_FORMBOOK_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_FORMBOOK_LAB"
    date_IOC   = "2023-11-14 09:03:02"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "FORMBOOK"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "7be9d6679205f724ef08f8aeb900ff19e0ccc47bda06a458cf84138406056de4" or
    hash.sha256(0, filesize) == "54991e3f6afe4b0c7f2d6d43dada59b2614ce28f0af811eadf2bf7a213b13b58" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_PRIVATELOADER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_PRIVATELOADER_LAB"
    date_IOC   = "2023-11-14 08:19:34"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "PRIVATELOADER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "2cb5b2678054dd2f1b93d37a96b927830c4a7da699f061adee370807088257de" or
    hash.sha256(0, filesize) == "38981ca59bd6187df55f92af67932a165b44a30587be906232e42f87c160d523" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_LOKI_xls {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_LOKI_LAB"
    date_IOC   = "2023-11-14 06:53:30"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "LOKI"
    file_type  = "xls"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "174489d70aa181c2994b063518b349b1b23eabd988f192b37ea3112241d93f44" or
    hash.sha256(0, filesize) == "542e4e849b04fa8953a08ecb6ddd300120855e69c9f5df0975ddf1935eacf408" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 03:38:16"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "dda58e02acca78a978c8ae8a82b34e3dee6db965b3c101731cbec2850cf5477f" or
    hash.sha256(0, filesize) == "90e4f566d5c15666ff4037b6876350c449e5b0f0f9a87bd0f950012d0d42541b" or
    hash.sha256(0, filesize) == "39c8e9229a2789a66a452eb9ccc656198aef60ab761f4a24794159b91ad67a4b" or
    hash.sha256(0, filesize) == "c99f57b763d90598609eb0b585ca8399057531d171021d3052efdefe26289117" or
    hash.sha256(0, filesize) == "c5c00a192d1427f8d60b64e3e769c7f16b2fee7133dee7c63c042faaea4919fb" or
    hash.sha256(0, filesize) == "4249959b292b1ff31e325395430cd1f438e432fa578d219bdb78983a30019873" or
    hash.sha256(0, filesize) == "3e23c3ee33d73dfaa575173e9467fd32e7bf14c33723b19691a91abefb283ef8" or
    hash.sha256(0, filesize) == "9526a4e0b40f262bc5cd1e07a8b80f465e052c18b3698e496ba0e2dd6549127a" or
    hash.sha256(0, filesize) == "827f8d64cd3023b078e30dcc014306c90fb3383b75b58b9479d0d19dcfc15894" or
    hash.sha256(0, filesize) == "f4bdddb45e727c8699340ba8d520a37e07b0becb4c571a67b3c9f4ce3a138213" or
    hash.sha256(0, filesize) == "8094ecda8ca0f8d5adb805dfef15a5d13c1dd670c3fd701ea98c36d19fde8cfd" or
    hash.sha256(0, filesize) == "08cb1432c512df0370577dc50549ad06f729858143017fe00f79fcb218872d01" or
    hash.sha256(0, filesize) == "b760fd1b8d86af6b67ac24e6a269f2ffbc818d37f7930fb562cce1331213d031" or
    hash.sha256(0, filesize) == "14b8daae29a4a354bdb62a5c3034941a1be3a161193489a624c8de3450a9442d" or
    hash.sha256(0, filesize) == "02d956d1f2c9ecdc43ebcbfef06dc160cdd9e5e31f50c692bde9ed1dd9797040" or
    hash.sha256(0, filesize) == "e5f25600b1e6483536bae239c5ff59e496fad54cd9ca1d82be94e26f27be5fa8" or
    hash.sha256(0, filesize) == "0985988c4ec01ce89ab73cd68d1e4d3944c8eafc4b5a69d0cd451487e97ff6a8" or
    hash.sha256(0, filesize) == "5772ac53f3ea00ee06f592ea27fe7f119f2027de5dcf72005a35a4302eb2d524" or
    hash.sha256(0, filesize) == "41b8a012d8dd2aa525aa05e5d296e13d4994110cefa41068adfb80eec0e3efe7" or
    hash.sha256(0, filesize) == "c3f6354c94ae880d0254f356f2836aaf4aec81b903e4054f75f6e517183e9fce" or
    hash.sha256(0, filesize) == "2aaa4c723b5868576aa1be98426763d3c75b1255aa639516c46d5867d2e970a4" or
    hash.sha256(0, filesize) == "36464f131691f5a812e22d4255377f79a475700185352606586f671b9ab63b66" or
    hash.sha256(0, filesize) == "d6e31c14d40784a2ff3b92ddea17ceb6eace0d64c4526bf17f8932700528dfe1" or
    hash.sha256(0, filesize) == "871c57f351c6debafe3210ce09ccdb78f8ec84223ac7d70ab96126b1bf5f6d6c" or
    hash.sha256(0, filesize) == "ca45f40c10f30d2c60b2ab67afffc295763d61c890f92b4bc71885d96ac56e18" or
    hash.sha256(0, filesize) == "8a119d3b9fce9c74bec4f0a150d29ff043af16ec7202b42c23b4c77da5266676" or
    hash.sha256(0, filesize) == "02ee3096c2471e5645404518b3fefd9c72b473bcefbd7c2ee167256546cdd030" or
    hash.sha256(0, filesize) == "d102730f766be0466151499f76d91af1c8f4c57ed3d973fcf60f1ff16a0b2594" or
    hash.sha256(0, filesize) == "12e7cbc39bce880ee356a8946fe22b8dfe01a8a21b90c0291ec774d5bc640f44" or
    hash.sha256(0, filesize) == "e3ca09965edf62f810d4889f9650b4669791102332ed761769f0ca9dabed1908" or
    hash.sha256(0, filesize) == "c9fcea3aed96b45b349ee794e0cd17c073b76a251f5dbc2285a2025e76225654" or
    hash.sha256(0, filesize) == "d09f9f6cdc590384d14c7aa5e5580fc0a358d0aa0f05199d12faf6ee17937646" or
    hash.sha256(0, filesize) == "ee36161c6b3635240df4c30f370420483174cc1a4999a386952d452d0de03c40" or
    hash.sha256(0, filesize) == "e61ed0d2ac83d2875180b1a33e04834aa6ca7dba7a5663e8d6e65a4482537576" or
    hash.sha256(0, filesize) == "03c4bbba0969018b4e4e048b8f3c52ce0d99a3e37da9ed11a18997e8a836f28f" or
    hash.sha256(0, filesize) == "c28c4cec1d98e3f612108826f92aef8d25da93ec22ac1b91523e944126ad0dbb" or
    hash.sha256(0, filesize) == "78a194ef979ef86b3001e42bde28be13a7efa2f5744ac4b5126036bbce309606" or
    hash.sha256(0, filesize) == "ecbff5a6e21170f5156f18ae42e78f6b2c38c36889fee23121683151b5e6e698" or
    hash.sha256(0, filesize) == "a56f0f054bd35ec2153c00022e9c811c24e2a352e7e1a0e7c23daa96d86da910" or
    hash.sha256(0, filesize) == "2d779ca15bff11fdaeaaead808f4887d4bbd30b441ce9d4ef6dfb28b748e8769" or
    hash.sha256(0, filesize) == "1c5682f07fcc6d16f137dc06f714388e040eb5a3209152bfff09563b545ff4ee" or
    hash.sha256(0, filesize) == "ff625dd0483caccac07b4233e3f8174a2237b8382da090067dc66213f5d9c8f5" or
    hash.sha256(0, filesize) == "588f49a1ba2f244d08911daaf351bc36ac8bffa5802eefe73a0ef1b7c4fc2a7e" or
    hash.sha256(0, filesize) == "047c2fb47c8227863ce3f9e4fe5c1e8fee7e3172019d56a27734178bb20a718c" or
    hash.sha256(0, filesize) == "686d46dc014ea066ed05b568eacffa901ab77f09ea65773ecd7ce8daed8b6b14" or
    hash.sha256(0, filesize) == "694b86530d202beb35223e351fe7cf8d5221b8b61b9326571039451a76272564" or
    hash.sha256(0, filesize) == "f4c4986fd011f3ef1223329e0433fd0d8766d27596bb02566b7afdcba0f21ea7" or
    hash.sha256(0, filesize) == "fe87527ba3585e4e2437669ad1d4922dca958a78ed2416ed8426a8abf0ee2f6b" or
    hash.sha256(0, filesize) == "7639d10533c0fbbe7a72fbc584a77b48b2758d6b8e4587a6f2e78bb7dd715a2d" or
    hash.sha256(0, filesize) == "9a4b6b2f92768653a963bc7658be529a27e94bf082d8c8843f189ecb85dcc653" or
    hash.sha256(0, filesize) == "f33cdca93db97c4b84af9f01216f3b7bcb3cf1865df84cb3b64fbbeed7057a2a" or
    hash.sha256(0, filesize) == "4be5f0cbc0f19546855afc9e8af0eafea9f10fb751ec9c1dea7ab88fb4543c21" or
    hash.sha256(0, filesize) == "764e1d6e17b2bf3ff9beab19e067594d2a7f1fdcd9f3fe74031c11f650aa2f49" or
    hash.sha256(0, filesize) == "470cf66bec58f48d4290d8440bef7c00fcfbd0f334504c5d2ac6739b8929ea7b" or
    hash.sha256(0, filesize) == "3bad32b4a4a4a24f88120c59519a942f29c71bbc638fda3c0b06655c29742c43" or
    hash.sha256(0, filesize) == "5bba406a5a9d3739ec90e3d6d5e619c849807e6e8d50d80ff80f7a34bb4b30a8" or
    hash.sha256(0, filesize) == "296a2dbc2d3de1c05763952fb82b7cdd2d5f6deccad03c9617da144761993413" or
    hash.sha256(0, filesize) == "4dafdfbf52d678a0138311e426f4b5681b0adfcbf63eacf941040be1a1b62508" or
    hash.sha256(0, filesize) == "94e606d5814003e1ad02da673542321ff27f3c0900e5d80c10f5a2b163e9be95" or
    hash.sha256(0, filesize) == "0808202fc3bd5e570b2106a4f991de5beeee739960b1167a590da92727b813a6" or
    hash.sha256(0, filesize) == "6c485e5e8e555eea6d9df398da467fc006baa7b621dcc8d87730b32b037e5525" or
    hash.sha256(0, filesize) == "a31e66233b55244dea9219f5b5a4df56732ea52b4d2c7dac246851fcb9b9c318" or
    hash.sha256(0, filesize) == "97cd6e5130cbaa45bd0281318c61c122cca866764dcfc87670422dbe4bfa8d6b" or
    hash.sha256(0, filesize) == "7aa30ac897fcf18158968453dcaa7a57d39aea3f5292a949bfede803e55bc8f1" or
    hash.sha256(0, filesize) == "a0b708c25e2fce2346235d0bb42abc98432e664bec6e925a04e9636277ead082" or
    hash.sha256(0, filesize) == "d790818dae55b8474612f9a1d45d4cffd35d083dc4ee2215b94ad9acb1aad808" or
    hash.sha256(0, filesize) == "2e3b753447ccd7d4a766dce1392d884fc6a3632d858f77ad19465a6504708ae6" or
    hash.sha256(0, filesize) == "24c0f541525bb734bd6ee6ce4328b752fba618092cbad8131e7418341da99134" or
    hash.sha256(0, filesize) == "e51d0b81ca8d23771538b6f9f787293c86fb78ad2d30fb09a57a9f8bc301dac7" or
    hash.sha256(0, filesize) == "6006d9cff2c3f472eeb4ca93ecf66a5e77014079508b6b0e75e1d58a0335ff62" or
    hash.sha256(0, filesize) == "29c63521ac9ec647a95c3330a23aced7ce53f1101c23a71f2d30350bfcaa7b27" or
    hash.sha256(0, filesize) == "444ed0d8b62bdd8da294c6a49e47a7f8a15fcec43409780ea00997a0bf53ffe5" or
    hash.sha256(0, filesize) == "6f40d5c35c41245183c6866fb0a4f8a60c5a70079213b1c76792c269f174364f" or
    hash.sha256(0, filesize) == "c957b6e7aeb2e6b6af16e5da1a09ccd6d5eb139a0db5429cfcc67a0a954c9bbf" or
    hash.sha256(0, filesize) == "46a95f00106f48d7ecf75c41fac059e5f5766f7cefec73e2638d9dfbe27e7f10" or
    hash.sha256(0, filesize) == "7c31d4fe105e60a9729dbd33357ddc20f3526a5ec2dfd1fc69eaa1668f289804" or
    hash.sha256(0, filesize) == "6927a9e73bf55a3401c967648cfc9f0d1d6cbf7cf452dd483620992d7d8b34e2" or
    hash.sha256(0, filesize) == "7e512bb8c1dade78162ab6116b93dd3db2cbf91dddf09d05955fa5fdcdbd7113" or
    hash.sha256(0, filesize) == "557e98b9d9d27da718e9ea7e20535535f3b0f796fe85a636eb14c418cc28c21a" or
    hash.sha256(0, filesize) == "bb4d377bc3a7dd434ee93d3de114df09e1985dfcca00d344d9ad656dbbc07493" or
    hash.sha256(0, filesize) == "dd69c8ab0e6f97b1e877054189d93360498d5bde5a61ec6aa100e04741c303f9" or
    hash.sha256(0, filesize) == "cf03c50f7197f7511f36824745a247f4dcedb427689fcb1f34074f07ed99b5ce" or
    hash.sha256(0, filesize) == "28dc1b057af09d247f9bdede84202dd18aa81b30a6583a152a101d1b2d91f26b" or
    hash.sha256(0, filesize) == "a4a651ae85e06287fdbd48c3d753856b07429f1c8b9566312cab224980f7895c" or
    hash.sha256(0, filesize) == "93f4f7dd1458ebc9caa287fe4a81737a417a75ab8e3a4a150c5c907f87b51d11" or
    hash.sha256(0, filesize) == "235f5430842be63a9bca58fb148480b6d6a1f0a0631ace17e78bf8430c5f98e0" or
    hash.sha256(0, filesize) == "d61440747490d4b403f4436639207f3a665dca0cd035267ae044ceff6a0c80e9" or
    hash.sha256(0, filesize) == "1809dddc2ed1656288e8932cf69022e58b688310423dcb7159fc73b38ee5abb0" or
    hash.sha256(0, filesize) == "b3b3761301129116546060fdda707826c64c631f45c7af948a809fc4e81cd87c" or
    hash.sha256(0, filesize) == "ff8973e265cde0ecfc91cb81ae4af75946b2cfcaa772b5cd1390c176e788175f" or
    hash.sha256(0, filesize) == "dcf2b30da73634394e398e44c84ea1f525a6e2b5f29114a0c504c50e119515b5" or
    hash.sha256(0, filesize) == "e40ee5b484b1f3e630bb257ab3424acefd5b2bc9979664415774a080e69623ad" or
    hash.sha256(0, filesize) == "f51088a42ffcbd2b95644e0861da35421244abe85928ada80ad383345ff0167f" or
    hash.sha256(0, filesize) == "84ff81ced73bc59be766c505ef9e65c6f898f334d3de0510d18248254119b326" or
    hash.sha256(0, filesize) == "c3efd2ad3d87e34d909c43790872b69e41232c05d8d498d1e1ee6c928573a33e" or
    hash.sha256(0, filesize) == "86951a2c31972c2d34d5eb44f518c05a449c00d751163282639f41bc5fac09f3" or
    hash.sha256(0, filesize) == "75386126b0ae0fb4e2f71f083c56ac8fa726482058e2b44274c6bbd51cd88b59" or
    hash.sha256(0, filesize) == "9b1d3802c41f21dcfc6ae41d795a56f200bd4298424b5fd9f4f66a4e5de88d65" or
    hash.sha256(0, filesize) == "f890008561d6268df4e91f4d14c9ec70e42bbb8f7af20fb68e368e542edebc16" or
    hash.sha256(0, filesize) == "1ded59a79c592a70a138f44b71118e2a7f86663902557cf6b8a109989ea53c7d" or
    hash.sha256(0, filesize) == "604c88cf909edfb72deda4ba7e0a78a7981fb9420df6e367c174d098e7460f3b" or
    hash.sha256(0, filesize) == "8022240f5a37f269d0a553c7dff56748864cadeafd8a603ff2920cc69c6bbf76" or
    hash.sha256(0, filesize) == "67b6d2863ac03575f1643fd37379908ece6763943a26163d8f72d345bf1dbcbf" or
    hash.sha256(0, filesize) == "f6a51523b06781d76acee7cc96c996852e35ef0e053e5c4ec5604084cbbdaf3a" or
    hash.sha256(0, filesize) == "ffede509da3e56af0d1a53dbac78a5d9fa35ce43b35f4df847f88f9b583ea709" or
    hash.sha256(0, filesize) == "d363c2dc7eadf1fbfc9bee1983f948677d4495ec13682c6298cfc8647fa47b54" or
    hash.sha256(0, filesize) == "76ea6fc5e2e808633b789fd8c300e15bca434185c6007de3eb98ed1e6dc70070" or
    hash.sha256(0, filesize) == "044058594de29392ad9bb466f082e9f276a19c7ebe6718f15be2075fd4351d69" or
    hash.sha256(0, filesize) == "0f49b20d665b676b9747fb999382df30f011d8d70284898338b27b80cba3ff1e" or
    hash.sha256(0, filesize) == "2f9666700b7a72f77462a3bf62380c47989a0a47e80c544a91b46c3b39d023c0" or
    hash.sha256(0, filesize) == "2018c59cb48d035db9403e9a6c647c8054369fdaff3fc8bf2284607a6a792e97" or
    hash.sha256(0, filesize) == "a6f065630c7b482267b7fd73a39c55615b8e6e35e258c1798ca42878ea989905" or
    hash.sha256(0, filesize) == "3f5c81d5d3aedabfaf11533ea280b538a65b2f5dd9ee6129f38f1684399366f3" or
    hash.sha256(0, filesize) == "7f25012f931ae9d691b9b2e393ec959eec7bad5987805440f325b13b3c033957" or
    hash.sha256(0, filesize) == "6521d0033c9c95469564c86efaefe94eb653f46a1ccb7750968d7c54e0fd90ca" or
    hash.sha256(0, filesize) == "efc9826c30aba11a06834d0e31c10f7ddb804fda6c05a02b796f4084d3e2ffab" or
    hash.sha256(0, filesize) == "9672eb651f72a3dc2a2b676d56d5e3424392123e3ae883719097af836129eb34" or
    hash.sha256(0, filesize) == "eec69f942751816a1f48afa25f329d5ea8e630fda1604be8e1a688046d63338a" or
    hash.sha256(0, filesize) == "9084ecef307c10374f2b4f6d54f7ab929a33ae254b349abf3f7399a8e6cb381f" or
    hash.sha256(0, filesize) == "eedbc0caf5c43d780e840abda5c3dc64721dfd24c0da7143440418317ba1502f" or
    hash.sha256(0, filesize) == "df5397b08e1b72fbf42290033aa11934e895488c93b76e608542fbb49d2e0f98" or
    hash.sha256(0, filesize) == "8538681af5bcf6c5742e9407c89c6caabe24b0453397b1712448177bff21f6d1" or
    hash.sha256(0, filesize) == "320f28727f308f0af628c0c1caf800bcb1754bd14df74361d5cefbaa5e148a8f" or
    hash.sha256(0, filesize) == "38d18a3ec97b64fa831a7521126687baa6cdbf0a859a92c500549fd25df7ebbc" or
    hash.sha256(0, filesize) == "c9a332638e2409f1b8366c9f4ede9b939540c367eab9eba3aa2f935ad74c2a9c" or
    hash.sha256(0, filesize) == "aa0668633c7c710b0a09adc99362b4a3547307f0b3f1338ae731c35d9b071d88" or
    hash.sha256(0, filesize) == "59bc63fd20252adcfdb6ccd58c036c0938354e467d47bec626c1063791f1151f" or
    hash.sha256(0, filesize) == "7f17d3d47f053498a3efecab532932dcc8018e3ee0da60fb090be0abc3fa5a82" or
    hash.sha256(0, filesize) == "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-15 03:14:40"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "cd378b012d0bdef2786e3d488cee11fd34b93d1cad9339351bcbbcf6b0214017" or
    hash.sha256(0, filesize) == "3a43116d507d58f3c9717f2cb0a3d06d0c5a7dc29f601e9c2b976ee6d9c8713f" or
    hash.sha256(0, filesize) == "edc9e39acb46cb0fd23edf9df42e7b94c3f33e20c01aa3eac58f02eb95a97f76" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_LUMMASTEALER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_LUMMASTEALER_LAB"
    date_IOC   = "2023-11-14 09:55:08"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "LUMMASTEALER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "eb2a0541c88a8d839a3506d67260951e8f6bcf4e46741658cb69c7178da93634" or
    hash.sha256(0, filesize) == "56f2f2548297d7b72af40b7898d1dabe2dcb8090388985b218f4452d1a9c6ebf" or
    hash.sha256(0, filesize) == "2d43530c81da22814e9debab6cc5dc8583d87b50c374e84c4ef153b0e51e4430" or
    hash.sha256(0, filesize) == "c309b4f0f99e1686e9bc954da81701b3fd26cfccd17627cde55df929fb712311" or
    hash.sha256(0, filesize) == "48e0956022211b6dde5b2f63169f3b1330bd010f61b19435faa54ad183709a48" or
    hash.sha256(0, filesize) == "5911b3af7d48ce74fc6644064f176990a34230786598cfd97b90cf5208be7f5d" or
    hash.sha256(0, filesize) == "371178f2c72748b41e33d1862f900e09d955f884f4b59857073c409e61b254ce" or
    hash.sha256(0, filesize) == "4567eee3f0b37c6ce2e213d54820f1fcc2093f97743354bff6f98c57456c182f" or
    hash.sha256(0, filesize) == "970dd198cf22fd0add061581be379fac2403bc071ebd495d32050e0c7ce5d75e" or
    hash.sha256(0, filesize) == "4d201919a0ebca66c9444a66f9324fb870e4af25252f27aa405255cca0167379" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 04:21:40"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "929c3cadc1a37a6f11f9f2b473fa9518d3c4162480b90e517204842f1f809429" or
    hash.sha256(0, filesize) == "c0aa81cd918caf90384d90ebafbe293b25968bb1a6063d74e2ee998f471bb635" or
    hash.sha256(0, filesize) == "576f6ca3dae804a4f50f29d5e46731890f23998b77dd4bd0a5ef92ee58809bdb" or
    hash.sha256(0, filesize) == "95d14e055fde0847733890ca247d22a1ef9ad581389e6beead1de46d3147ff90" or
    hash.sha256(0, filesize) == "85899457d67ec7a33751203ce6af4f98699d6832f0cf0264db1163c21e70b8ba" or
    hash.sha256(0, filesize) == "b312181bf94aea26d5f11a6bc046b8e8858328f1c8ac2b199100a08d5c0d4e87" or
    hash.sha256(0, filesize) == "19b739c72921a6b24a4c9ae99f3371f2f25e4d6a7bab90c256a8c44e924f8e85" or
    hash.sha256(0, filesize) == "a7382872a48a55f433257999b847b4ba8c26bfa1a565a819967a410033aa346d" or
    hash.sha256(0, filesize) == "592f4ee0f178de6162247010bf85d4eaccfa123d8a26a9db120bea1e13a830cd" or
    hash.sha256(0, filesize) == "65cf59b3533759dd226925d14d2923b4ff5e6077518af382552cc01c6d98bafe" or
    hash.sha256(0, filesize) == "1847e53f0b2d743d51ee222f85372eb4dd452877635ed83f962d76c7293ebd74" or
    hash.sha256(0, filesize) == "253c97514805ad5ee0dab272a842169a639faccdd38ce24bf08054b49e2c9fe9" or
    hash.sha256(0, filesize) == "378a0fb9073a81918cdfc7a87508df39acfc751a9d646cab83cf7eee919081e0" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_REDLINESTEALER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_REDLINESTEALER_LAB"
    date_IOC   = "2023-11-14 04:33:16"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "REDLINESTEALER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "ba87c237b03a3a5a54273ccded35d16559f33678a76f05ce856389e207b68046" or
    hash.sha256(0, filesize) == "5f718ca24fcd480d7daad2d100dd55b7491c8704765b1fefc09884b3e1f31ebe" or
    hash.sha256(0, filesize) == "154977c01029dd441484b65ac21a15ecd7f6144d48eccc5b2ecb67a56bf7cd90" or
    hash.sha256(0, filesize) == "16a1c64a64c741f354cfa13e4640e2c10917a6968dc0ac075d0c3c13270a87cf" or
    hash.sha256(0, filesize) == "195256a242e1a4f2a1833194d97951ebb74ac0091b0cd6be50a3e2f01691b421" or
    hash.sha256(0, filesize) == "0bbc5d27d984dd680feb23e3aeae57f7139953d3efb11926b65952b5f664cf10" or
    hash.sha256(0, filesize) == "26bb80ea94240a03b487cb1f62459d06a8ba4f9abc207cb5372a49609bfbabcf" or
    hash.sha256(0, filesize) == "743754530bf3cdcf57d1f00030b109ffce1431d59d3bb0db3af2c45a57523928" or
    hash.sha256(0, filesize) == "d2c19e15edee855176d5dbf18b19833779e009573573b419c0513e3cf82e6650" or
    hash.sha256(0, filesize) == "6965c5ea91cea03b9a1204a762277a3ee3f4f89f02f2fea0599b6db6ea49e6f0" or
    hash.sha256(0, filesize) == "23943b3d6938425abb71b4e82e9b8d3e93979091c175128c9f167dfc67118968" or
    hash.sha256(0, filesize) == "f7c6af19e272f9017f27afa2699e68759a231edfcb1386f854121257d405e167" or
    hash.sha256(0, filesize) == "90c9d40878861fb8a41fe65b46aab0a2a7153866619beb2efa2be92d71ffd240" or
    hash.sha256(0, filesize) == "e3ba3128521529aa94345e7afbff46bee7a4c38eadce2e4f3a931afb22fad365" or
    hash.sha256(0, filesize) == "7db04ddb55518c98493c17e533c6607d28a10d5385aa236d9a84a10670c49574" or
    hash.sha256(0, filesize) == "cdd3fc19ff6129cd6a4ce32c48a2eceb0ed91e3f129e6f660bcfcebeac1296bc" or
    hash.sha256(0, filesize) == "93851cdb575d5ef907a563962037853c8a59f77a8912db9ec637ef33a9d608b7" or
    hash.sha256(0, filesize) == "fe3b975cd1b89dcd4ec203a5c74a6b612a2df2df4f200d40b5bd2efd9ab5d73f" or
    hash.sha256(0, filesize) == "929e07936c124aca9a998c29cc6c75e91ec2f0f6a45acdc4b5d55ebcd453292c" or
    hash.sha256(0, filesize) == "e69fa17979f4dc03a37fbe37f92d686092271a6d610ae3d31d59d52441dd812a" or
    hash.sha256(0, filesize) == "d2df430d281ad78bc0690d63df9896fe195e2df53f2e9182c6f459094f70aa45" or
    hash.sha256(0, filesize) == "c9c5798e7a3d4bd33f48a62c21591a50d890d25d509aa359798720ea4ba3fb14" or
    hash.sha256(0, filesize) == "1114fd06909159c440fadc3bdb3ce6a5fc1c2ac3bcac48dc3a6b4402eb245fcf" or
    hash.sha256(0, filesize) == "4f3d3b8e805a031fe8eeb47dca418fcbcade5d0190ecdee8930e942c9b4028ea" or
    hash.sha256(0, filesize) == "0965997e1ccaef06f3bb54b93e0e7b3723bb9d99a0944f5550dc5c69cc9c42b8" or
    hash.sha256(0, filesize) == "a3cc4fff4aac80dd379ae09712229eff389c1172d888180dbce61715965f4885" or
    hash.sha256(0, filesize) == "dd49ae56ccd5824fe4f6b62ed6b3b3466a40e56163c23adee63b9b26d96b09c5" or
    hash.sha256(0, filesize) == "fdad89fe9db1c6caa09660a2abd2a99e73a8f442dec417ff49b22614057c74ca" or
    hash.sha256(0, filesize) == "6e627ca700a4794c9e46a849daed709312bacf1587109607e2f6c5eebb8a2598" or
    hash.sha256(0, filesize) == "8e658be1287f69327c68a575863888918e1ca90e2bd09247170a81af6b3cd34b" or
    hash.sha256(0, filesize) == "07df78604d9da2c127e1ab1b9dcf77cece0d2ba536746a7615c65d6689debeb8" or
    hash.sha256(0, filesize) == "3e5d50f9256e94ff3a0e33bd30c01998a5cf299daf96808747729fb72650eab1" or
    hash.sha256(0, filesize) == "2bccfd325ef0ae6b5522b4be977a4d25f81b42a2240c8a072773ef6ed6517900" or
    hash.sha256(0, filesize) == "b4fc50feb3200e9f998dbb7b89dc252220c913c039624fb599aaaab413ede44e" or
    hash.sha256(0, filesize) == "bbe4b4a0aab75cfdeb067064f73e05d793d699247ecd0ec93ef576cc115baca9" or
    hash.sha256(0, filesize) == "19034212e12ba3c5087a21641121a70f9067a5621e5d03761e91aca63d20d993" or
    hash.sha256(0, filesize) == "443fecbe6006903b09fa090230b790dd28249f5b17927c4989bc8c8eaad3ea3d" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_AGENTTESLA_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 03:19:49"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "f873fc0535d38b4ced119b8d2d555e23496174f01b5747b148c50925c2f60424" or
    hash.sha256(0, filesize) == "cbebcef944dc8b96250fa57c98bef408a1f3f053f303871f89f8f3035b4b3e7a" or
    hash.sha256(0, filesize) == "00e245b9a6266afb2eb6b81cf96520ca093b7242dd39b1b74daf4d5811ce35fe" or
    hash.sha256(0, filesize) == "f112d1e7c8414255846131a14109ae12e45ad65296bd014601d0a83c9ea90cb2" or
    hash.sha256(0, filesize) == "f6b96b0e4ca1b30e8f8973036205314b80f9ac4ebff7f0e46c1c74d51c72202a" or
    hash.sha256(0, filesize) == "8c69f8ddbe47d5020425853ec7cc411a6656b7f411862d1de7f1081e1f6739c9" or
    hash.sha256(0, filesize) == "dbe5ea4fdeec96fa6dbd4e378dd10f4c6b89a921adaff45fe358f3dbb55da1fb" or
    hash.sha256(0, filesize) == "0f6154350e73fcd971f98f7bf3fd43773edd1cca24c16d259a4c755958970332" or
    hash.sha256(0, filesize) == "6398b922ae61c54c8ccc93725d584c8e3f0c3005716cd21fd63fb79e3bc78836" or
    hash.sha256(0, filesize) == "8632a6cdacd3c2ca44c427d1ef6bea4a9c16a7089a31f12fe79ba6e108860902" or
    hash.sha256(0, filesize) == "df5e129f51b16e5dec57270b57c8c742242d83d3fe7c556184cb004ef353eea5" or
    hash.sha256(0, filesize) == "b051fc9f064e736c6293b5f0d074f4fd3cbf145d0885b9a44539c8fbd4a15621" or
    hash.sha256(0, filesize) == "64cf760478ae702e8157d46821cfdb8fad6ac6bf640b511ca736d7315db70632" or
    hash.sha256(0, filesize) == "b1e5d0c3a97d2c9fd511f7991e33b2782f6dfc92ce9310e098e7fb53f6c4e3be" or
    hash.sha256(0, filesize) == "4dc4ade4ae2d4abc759ac2fd298eeca6a88f1669fb1f3e761c46d134b5620a0f" or
    hash.sha256(0, filesize) == "10f79a0bcff0aa1bd3c2ee942bb6894627ad897317413a354df70b50f4e0f56e" or
    hash.sha256(0, filesize) == "dc7b17accaba0cbe8edc9a22bf625eb3e74f64b6e17046175095e4197792bd98" or
    hash.sha256(0, filesize) == "5e32a7b5320ee9b3277092e547033be4d247629a4cfe396c19ed326bc2063210" or
    hash.sha256(0, filesize) == "ca75c3b3a4278d054eac12a4c06addf6b48ab936ed5a21f1ba652d0d209c0f97" or
    hash.sha256(0, filesize) == "c29c56a3681fb8d2f46ca4e7070f088e2e7c8f8b11c3d4218c79b91778c3536e" or
    hash.sha256(0, filesize) == "8af6097b2ebe610f5f0602bfc6f5414f797cfbaef62ebf522f8c93e1f23eadf5" or
    hash.sha256(0, filesize) == "259e6fc89c741d8f3a240402ffb767e833317bea4e190ba44e516adf63cd5b82" or
    hash.sha256(0, filesize) == "69e82246e2a2444321ad9c8c84a445b8ec6b18702c2407565cae60e07b3823ef" or
    hash.sha256(0, filesize) == "2d63c7065f4924e91461a07ccefafbddc4d7944cc5cbf0ad543a7c7f8103d36e" or
    hash.sha256(0, filesize) == "9df6347fd6d4c18024e5330a6d05ab03d7f85f7aa70d7f083bf80f764852a367" or
    hash.sha256(0, filesize) == "ee87b91b6480592bf45354a624ef6b478ed812f5ef33e36dbb6775fe057dbcfa" or
    hash.sha256(0, filesize) == "22e6002a6d91fa1b1776f6b2e1cea01312a95ba504643bead0deaa0b90e193eb" or
    hash.sha256(0, filesize) == "e3b762b0f49f604badd73ea22cd90861766a1568211b461ce08f687ff9d22f6f" or
    hash.sha256(0, filesize) == "a999fa0b2c139c85ebb6a33cc1785777a333ee9b491ca696d776887f6d0400bc" or
    hash.sha256(0, filesize) == "777c4e75052752ee1f5ccad536e28dc1bc5d8436892bbbcc86a7cf69d581ab8f" or
    hash.sha256(0, filesize) == "8645bdb895457e08db9625bba8903490cecaad66c6cd3c0af3688afa60a425c1" or
    hash.sha256(0, filesize) == "a245bbcd8bd89a1b4d24f79630212fed50905ac410132678fcea552048b66792" or
    hash.sha256(0, filesize) == "a3e10f92baec9fd3a6ac12cfdc393f4031a94b4843300a767e89b0dfbc026a6d" or
    hash.sha256(0, filesize) == "79b5b0596a21d1d0642a64198c45d8662e9eede03347ce5f50eaac73f31c32e7" or
    hash.sha256(0, filesize) == "b74c35fff28c2545faae06261ed6ee1649067638169ef24dfa449bb201fd6039" or
    hash.sha256(0, filesize) == "7a26f105efac6daa9226f4ab1b6bf0ff600fe2140da9fcf3e91e502ed359ee5f" or
    hash.sha256(0, filesize) == "da21ece2f4aa50ee504970a2fefed88038ade14bb3f68b0d6e388da6f40628c9" or
    hash.sha256(0, filesize) == "fa86b4d3e3e4217d2c502925eb6c41fb7a9bf0a17a976fc6a11a849d5861c8d0" or
    hash.sha256(0, filesize) == "aa7afebfd032006687eddefc5578bbc1933f1477aeaef5a17427677a4de08d95" or
    hash.sha256(0, filesize) == "db5791df9f9164152525e6564a5984cc23ff98593c92d0ad167b8d7fbb0e3111" or
    hash.sha256(0, filesize) == "047575bd81b3dc7b788d1f33b92ccd8e42804e7bb9b578246a1284d0e565a6b9" or
    hash.sha256(0, filesize) == "421bff513232de6adf60e78f45df28ed50b3897a27570596e12f661d2bb4e8d9" or
    hash.sha256(0, filesize) == "50174c869349bc2bbb082345c016fb75442f9858a91208180f5ca49ada8e9c5d" or
    hash.sha256(0, filesize) == "f1a6e53beb7e03091a732ba8d1093eb5162dd620c85f7ee44bdc6efe25c3c853" or
    hash.sha256(0, filesize) == "e250eef1eaea9092ecaa3ecd7a94b02720a9fb2aadd9c8a3b234e52ed7710ae8" or
    hash.sha256(0, filesize) == "2772267437ac2a4a39e1c4893788b420e3eafd75c0517c3d8bb58516c8e2b196" or
    hash.sha256(0, filesize) == "f29177a4cfd69578f868616ce53b974ee5c362b2d43e70a17277ac18bbe4d125" or
    hash.sha256(0, filesize) == "76b695c17786615cfe769077dde4f7d7dae83e8a6f638680c9e0e59b8d1f582c" or
    hash.sha256(0, filesize) == "91b0829c56341b5ebe30e0b59b263f8d174bcf4b1718bbfe5cb18b7faa2d606f" or
    hash.sha256(0, filesize) == "c073d55e30e424b99d07e376c38ca35b579dbd327da6be96cec527b0e3132ccd" or
    hash.sha256(0, filesize) == "cb15630de2fc38b0f07691ab16cfebcc1a6a940c867c0fc41a811c26525d9fc4" or
    hash.sha256(0, filesize) == "d8c86642c4e7e86d3591143c9bd7a7ca0278ed8812908b81e5633948ebee2eee" or
    hash.sha256(0, filesize) == "780864eca14f5609a0466e0831fd4ea929247f1bc6768ef0aabbb4a12135b319" or
    hash.sha256(0, filesize) == "7c694dd1d56f0082c40c850df23deb92f994cabc5af5a391f52e7e1702b50def" or
    hash.sha256(0, filesize) == "c804d3785acf26364471c13ee7b8714bce6329666877dff5541252ae0613af55" or
    hash.sha256(0, filesize) == "9b1a04a9a7488c5c618d00ee10920203d5bb51cc2c3470aae460f7a971a44843" or
    hash.sha256(0, filesize) == "8992f05844656419027980e08a09950c5162846b52277dc662b4866dcfa18871" or
    hash.sha256(0, filesize) == "e0a14b9acddbf73d270c2eabf671ce58e1c2aaa237ccf2de320efedc947b6ccc" or
    hash.sha256(0, filesize) == "899c4c78e96a4c19a650d2cad2ad6b7e358bc78f42c9ba9407821e0be43347f6" or
    hash.sha256(0, filesize) == "c49d3c572cd0b818ced382d46198cd833015f79459b10e2cb4caee1bd18f5e72" or
    hash.sha256(0, filesize) == "1e6327a5456f3aac77ec28cc80c9f9f8cff8a157a25a8a2f597764dcbccce3ea" or
    hash.sha256(0, filesize) == "e90446f4637905f90836fe5c684ac38531090b2f64bb561a555e09cb4af076fc" or
    hash.sha256(0, filesize) == "e5a39d95388a1324e37c31b9bc6a527941dd0c0736a0971ead7ec611474d2eb7" or
    hash.sha256(0, filesize) == "1e1a3828028401c6052fd951935347159121c19c01e7dc47fa2d4620a60c720d" or
    hash.sha256(0, filesize) == "6c3aa6c7804d75cd98888500430589c9996bd681881fdac1850590343ab4d13d" or
    hash.sha256(0, filesize) == "4ae304d194dbeac326186c31c58bbf4f4c87791ddbb048efc34854e75dde91bc" or
    hash.sha256(0, filesize) == "7a04dd7893f89eeffa0df553493f9a5367bf08e041c4989888e84d7006a65a65" or
    hash.sha256(0, filesize) == "57454ca5dffc314f665767b53dde6778afe2ef9b3470eadc71ada2130854ab2d" or
    hash.sha256(0, filesize) == "73a225250c2ccdff194478cd7d7aa96a04b314c6fbdf105183198548a0f93684" or
    hash.sha256(0, filesize) == "aebcd6039f3bfcf9ddfadaee2d5e631afb676e36e1497036283b24c73b810800" or
    hash.sha256(0, filesize) == "f45cce1292aa30dc88decc03fe81e7c10a64e4302eb1e3faa81c385e36d2a1ff" or
    hash.sha256(0, filesize) == "3f0f2b7e3062679b5ba9559637eee1d3ab15dea790fbf3c85b69fcccb3edc8bf" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_unknown {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-15 14:20:43"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "unknown"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "2a8f9fa9e3d05c509f9858cae27a530a1cd6284c9bd4b77e12c811c28b9dadb7" or
    hash.sha256(0, filesize) == "b6702aff8b11508caf4a291f7580eeda872dd8d8d46b31bd342828fa23124e46" or
    hash.sha256(0, filesize) == "70aa5561a87f3d07e2ade10726204db619f4370632d44bd9ff2b6619e4755803" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_msi {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 06:30:05"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "msi"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "d82ea0bf95437276d3c5bc8f78b6f3ca21e028ec69e3c0ec15bdca37badcbef6" or
    hash.sha256(0, filesize) == "a8338b8fece4e078c2ec6b634d6d1a161beb68cc8632e41127edb24e2b9ec80c" or
    hash.sha256(0, filesize) == "70ae0ba7881ccde62370f1168b00662af52a354b97f6cf8b01219f9046c0270f" or
    hash.sha256(0, filesize) == "ab6b3a30d643bd1a807d4415e554a7e005c9320d1adbd0bfb4666cf1509c3078" or
    hash.sha256(0, filesize) == "69925c370a71b0bc37eb5d6381e8fc3309a7e71a7bdade54233214c73c728170" or
    hash.sha256(0, filesize) == "24e7e2dcb6102224d489081a32b1aee6c1ea035295d58fbce7f85c7f22c543fe" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_AMADEY_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AMADEY_LAB"
    date_IOC   = "2023-11-14 09:23:43"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AMADEY"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "a4528e6b733c6b595e93e3d50fb849edbe9fcd062b65fb2bd4ae5d8d76ac5b76" or
    hash.sha256(0, filesize) == "755cbdd175e237a66a78ed70d9d8a39c8946a57e64c199be154b86f528671d51" or
    hash.sha256(0, filesize) == "92b44334a248b6b3850c38fc3aadb63d0ae1828cc2a6617be41299eb4707d82e" or
    hash.sha256(0, filesize) == "75b6b00dcdb1025df8a76e02a7c989b5c6d670e0dcf1737be4f20641b89cde77" or
    hash.sha256(0, filesize) == "83ef6d2414a5c0c9cb6cfe502cb40cdda5c425ee7408a4075e32891f4599d938" or
    hash.sha256(0, filesize) == "6d3cd39358c91c56b4798b64c73f03e3877a80dffe01d07e2ad13e979e845ed0" or
    hash.sha256(0, filesize) == "75521cc92675383e1f9b8996fd925345e562da8b2a2aedb9cebacb9cc0ee0a80" or
    hash.sha256(0, filesize) == "d3a40144912dfa3f095ab0526aba7c0ce4950793090a632dc76f9fd93be815ab" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_ASYNCRAT_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_ASYNCRAT_LAB"
    date_IOC   = "2023-11-14 09:19:43"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "ASYNCRAT"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "a9b516990db5fb757d5745cbca218fb6996562af0454dc3820403890d77abcb6" or
    hash.sha256(0, filesize) == "ebb3a5afeb6a34fd0ca7e4ee234a04f66de5b7a38fbc4171ff5e8bcaeec8e100" or
    hash.sha256(0, filesize) == "2a318235a7908da2cfacd1711becc3c0da7a23359a98628f6d1fe14a7dd97b70" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_dll {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 04:42:31"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "dll"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "3afd0ec9ff87802fecb70c64bf0c0b86081bd909b9b649f902931964d585632a" or
    hash.sha256(0, filesize) == "d6f843c7ea0e1bbef9b381b35d2e942b88f204c1a43de76011da57563f21c95e" or
    hash.sha256(0, filesize) == "379e01a20f66afe32b7792eab0bc3d97179ee0fcca919e4604769d6a6fc3c2e1" or
    hash.sha256(0, filesize) == "506bc39774eea82a02c20bce1ef02b751133eee9e512747c250d972124fef76b" or
    hash.sha256(0, filesize) == "ea44b39b32fd766f5a4c9b0d426451065e3ed6d9d977cddcb7cfacfcd82be47d" or
    hash.sha256(0, filesize) == "5cc6b31669023b1f74191cc76d25924fb652a19c92eb3bef80d176304b0cee1a" or
    hash.sha256(0, filesize) == "035243c99d29f9f785e7f76ac3e744c56c7386449ad51b1d7cce9c19380a487c" or
    hash.sha256(0, filesize) == "ba3b6093e676d0d4ed3832efc496ad3a1b7c24e9a27574520c7b54e84b93de32" or
    hash.sha256(0, filesize) == "cd12655ebbcfc6789326d27f125ee39ec47b49c93ffd3e80af11d308a917107d" or
    hash.sha256(0, filesize) == "1f0dd88879a0facb7ad1cec668a9c65bcf06ac1d69945989770f04740e1117a7" or
    hash.sha256(0, filesize) == "fd45836d17756388b7bf67083e5247fdbe2154149f4a9cf3d30fc8348e3020ac" or
    hash.sha256(0, filesize) == "e4f32b898bb95e747f9b11d1b7dd52a8a36e7116e66fa171eebed1bb290eabe5" or
    hash.sha256(0, filesize) == "af32907430cff27948a020b20e76c590d6561e1a9f7464d7071fc4d5c4db7b1d" or
    hash.sha256(0, filesize) == "080c2b0ebcaa675f7cc3087a62b458bd05829a5056b93b478b0c137140e613ed" or
    hash.sha256(0, filesize) == "c367c645711aeebb01f2332638dbad2b665bb9cc7e34fcc6c2eae91385da730d" or
    hash.sha256(0, filesize) == "98cd89574c41cd0f664b482c7964386b96987b8dac316860f4f02b351da8a77e" or
    hash.sha256(0, filesize) == "fd84fbbb02015979484e56ee1f8de94df66b7c031c8df094c25ee8d4189e2f62" or
    hash.sha256(0, filesize) == "5dce23221c5c4ce62fb33f2de5438ae15b86d796c39091cfb495ca01f8eb04c2" or
    hash.sha256(0, filesize) == "2eef4b05700162c4b8b9f00d8ef7b0d11e1e273219d30130561293bb429f1850" or
    hash.sha256(0, filesize) == "f4b90e1ceaa1c88458604f34205b55f5cc7bbd11dc9da6e5fb0b2dd20215774a" or
    hash.sha256(0, filesize) == "8383d1cf45e6dd5345dc5d6e7aff4dff75a5dac629a617cc08150924ab019fee" or
    hash.sha256(0, filesize) == "7b9c99c1aeb0681b96a38c5084658497d4ebd6a196f8618030cb034295d825b3" or
    hash.sha256(0, filesize) == "1f9a4fa0a9cb98637bf34cf919c0f964551b79abcce5621d7b165720aa45988c" or
    hash.sha256(0, filesize) == "f122b4ab576902c76b6f127399d6fa51c94fcc90a87c4f870acb6aa2c74fc2be" or
    hash.sha256(0, filesize) == "7dfc837c2da8c5a32150052a9876447170d8923b31409a3a1919d918027cae19" or
    hash.sha256(0, filesize) == "591d2575c173f07028f37e371da17f7727c78d31ab1578b222c976fa5fad2b3c" or
    hash.sha256(0, filesize) == "bc60d6b0dd2558c683f2db24c79187f1c870e35deb4dd5586965f49e2d24de33" or
    hash.sha256(0, filesize) == "f366d535c63702f7412cfe4ec1c63edc3dd86c44f2d42ce9e6cfd63cec78d930" or
    hash.sha256(0, filesize) == "b9a953af462e7c92a64aa70d6e596cd715b3e0cf5761bd76a80d8c252c45a38c" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_RACCOONSTEALER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_RACCOONSTEALER_LAB"
    date_IOC   = "2023-11-14 04:33:07"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "RACCOONSTEALER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "bdcb0564911bdb1f151d4f58f82bce75a8c861ee251ea7273487a34fec865654" or
    hash.sha256(0, filesize) == "d74b9b445cc4cb4fef7ce48910ef2f930bb044dc09221df368ff3353aff70841" or
    hash.sha256(0, filesize) == "f6be22baa5e6bc398c0130a7d93411166fd2441722cdd6a3ec3f7205a384acfe" or
    hash.sha256(0, filesize) == "79ead2d23149eaa2413377b314d1e4351cbe2451839cd652ed51c5c2e9a006dc" or
    hash.sha256(0, filesize) == "8e6021918d108cbb2e19ab300a03e25b1e1e0c6e621754f5940e6db2ac195d0a" or
    hash.sha256(0, filesize) == "f14734d04f355fa903c6482fc4f3662c3ac1ab892ad14f2f135ae357d1f04db4" or
    hash.sha256(0, filesize) == "c6d0d98dd43822fe12a1d785df4e391db3c92846b0473b54762fbb929de6f5cb" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_REMCOSRAT_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_REMCOSRAT_LAB"
    date_IOC   = "2023-11-14 10:11:09"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "REMCOSRAT"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "e6324e216c641b6d10f7acbd518cc6d859a842c80e5c58e852e64b6e8a0b7666" or
    hash.sha256(0, filesize) == "39c906f25a69d675d9636c3dcfd78c18cae6a9b7a49697c23a08d54004b4c6ee" or
    hash.sha256(0, filesize) == "3f631c04c084cad9373730dad3b838b4c4f4d079e825ccffdab3b09d12b027c2" or
    hash.sha256(0, filesize) == "82801d63eca2fdd570d211cdffe08f8aeb3ead46d51dec316ca36f389fe29d8b" or
    hash.sha256(0, filesize) == "2abba169b2f3be758c20b3d23dd9fac351a2c6aed1caa97e32ccbbb888e83c80" or
    hash.sha256(0, filesize) == "40870b8167513757fd7d369a7db8f32b828a0ba1540d88324ff19867f9045494" or
    hash.sha256(0, filesize) == "67c980215d2b7daa075a60a95527409258475ab2e6e71a1fa59a18dff0cb0c19" or
    hash.sha256(0, filesize) == "ef9982ce0b9a6a27c0fccc7017093b567663e1ab30bee707bb4316dbfa5e6793" or
    hash.sha256(0, filesize) == "6b17811bf0955ae82d108f30f526b741e15e6f00024cc71b34cc315cd64297b0" or
    hash.sha256(0, filesize) == "d1fc6f72efcb3534ded2e3b870fa01ab945babf2b30d3505573f9f6bb81979eb" or
    hash.sha256(0, filesize) == "f7ea87d7e1c7167b0ee3091546b6740386996794f72ea603c10c4643609b0747" or
    hash.sha256(0, filesize) == "76143c27dd7b0f5017b03d53fffaf18ded8b2c4b310ca61f89b2a6ca78786b7e" or
    hash.sha256(0, filesize) == "7fc8d7dc73ea28fb88262e807b2707ff6bdf2ba3b84ca2b4d866dc5e9e2def8e" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_FORMBOOK_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_FORMBOOK_LAB"
    date_IOC   = "2023-11-14 05:40:06"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "FORMBOOK"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "10f863afc82cd61fdc8a55bc67e2726401ac51c4e9647ddd19dbf1ea30df9e09" or
    hash.sha256(0, filesize) == "c88aa06f7f7d22f3a6c66c84bf6aafd8838357d02d2287bbbcd61fb21264dfe4" or
    hash.sha256(0, filesize) == "0838dcd24cf228707272c365f4a9552e4d3b69b43716cea36fd95f250f62a7ab" or
    hash.sha256(0, filesize) == "6282a84266a87aa1e62b1304913bfdc8ce4c122f59f5731503f78655beaaa27e" or
    hash.sha256(0, filesize) == "d2799bffc4e285fb9472cdf9e68b4637288c44cd7ed7d5ff7680228c63d525b7" or
    hash.sha256(0, filesize) == "f93737e8575d0af497e1432588bea5d62c86f7984605af2c257002b73563d0f8" or
    hash.sha256(0, filesize) == "1263a6f6ffb8706a7785cc11b08c4a9c6609a3823ca758dbc4777b4639ebd2a8" or
    hash.sha256(0, filesize) == "a3e4cc3747006495c9cae3e6f08010b8368ebd5883b556e021a923fc20f5bef1" or
    hash.sha256(0, filesize) == "de370b8f6e1ebb2f43c5fb9ac7392cc5c70224f10c31bdad38cf369744d03d52" or
    hash.sha256(0, filesize) == "03ff02d6d7a259734c8733614089ac81324a837102a6ae3484491cfe7eed975f" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_COINMINER_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_COINMINER_LAB"
    date_IOC   = "2023-11-15 09:24:49"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "COINMINER"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "199c01b177aa7c4bb01dae876012c696e4e30aada4cf1c7edf7936eee0d7876e" or
    hash.sha256(0, filesize) == "5082ed106ffd1f4f71e016e49b88c0e61d3ffd00f7860ebc4fa1406735cd84da" or
    hash.sha256(0, filesize) == "151df3364d6d3ff361ed45ea944386ad8b45fc8327929447de5f7a86bc19547b" or
    hash.sha256(0, filesize) == "0233e973071b55934eeafc66da12e02587c5b1604d3b300ccbc44f018c2b80cf" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_AGENTTESLA_rar {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 08:16:01"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "rar"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "cc9ceb589bbbf22fee3f7456b0269d06773a6e96974aa20936868bcbbce88ba6" or
    hash.sha256(0, filesize) == "ff28a45905e0bb9d9af43c5e4d8e8fa27248880cb7a24d2bd7c16d5ddcdb8caf" or
    hash.sha256(0, filesize) == "4bc3218865e598320faef41090da4ab23101fff8531ffebcaf6523a0217ea898" or
    hash.sha256(0, filesize) == "6f005ba0b96e1110d036613975314ef0827afae187ac93384770ea57c3103c26" or
    hash.sha256(0, filesize) == "2c1ac1fdee3753349c582a5a518c301baee1144d0ab52827792919dcf3e4c7cd" or
    hash.sha256(0, filesize) == "1bc363ba8df6cc044fe7eea73aab1ec7276ee28afa716b19e5681335189aa070" or
    hash.sha256(0, filesize) == "ad654aeceeb0af81e68181bb70bfe413527895eb4b23b378bb084129f9ae1a0c" or
    hash.sha256(0, filesize) == "861f1511b4464e0c3fd64db843fe357894204b1427014232c6c7434b02947811" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NA_doc {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 14:54:58"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "doc"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "44b2f311eaba2e49b175ac9126fdcee092b1bfce3f7d5581a615c80afcfd0d1a" or
    hash.sha256(0, filesize) == "54376ee15cca7c6cdecc27b701b85bdd2aa618fe8158a453d65030425154299a" or
    hash.sha256(0, filesize) == "d8a012a24aa805042bc416d6d72694d6c3c0b726b571f5ef57ecab8690b87b99" or
    hash.sha256(0, filesize) == "976c4fdf5120d4a6e6b5d1cd26d70244fb788ea1cb50031a129ea8da9509f86a" or
    hash.sha256(0, filesize) == "69f1ebe7c4fafa1798aa4ccdc52785e5015456e2837b9a234031884f196fda62" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_AGENTTESLA_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 08:46:46"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "5841001fb1a91673e31a012d599cbad0e47c93c37beba3426e7fda17dcca5cd4" or
    hash.sha256(0, filesize) == "8dc7626964bb2236228f1cd54d064c5a03deeecb0fd4cd64ee010e36bb046d23" or
    hash.sha256(0, filesize) == "b05c4c012a23a232bb4cb07b15af09c7df8ff87cd664f6169bf2b9cf0ec392d3" or
    hash.sha256(0, filesize) == "0598d24987b6a7a5421e7e34589b81a5f2ff9e8e1f176569d0f4d33783e93f57" or
    hash.sha256(0, filesize) == "ceb734f8c9859a740dc419596343529552f55f8956790a001b33850ca5150c35" or
    hash.sha256(0, filesize) == "51024442ed796e4de733bbbc83457b1cc193ab447e428a2a58972ce338864b6a" or
    hash.sha256(0, filesize) == "2d0c195cad42c20024600cfa6643a66c7dfe17ec96cc5f36bddb3b48f53ba0ea" or
    hash.sha256(0, filesize) == "6767b678fcd5cf5e973501473e540fe5c1c716101b952071f075d9ba0402be77" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_GAFGYT_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_GAFGYT_LAB"
    date_IOC   = "2023-11-14 19:12:25"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "GAFGYT"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "b6ee6cc4d468044d42a71e0cc4ae1b15a352baa52e84671f8a0e8bba743e8788" or
    hash.sha256(0, filesize) == "2b2ec22f0dd019563b5ca08f2956b78a72fe009c86dd581885b11a8feedf5bc9" or
    hash.sha256(0, filesize) == "5ae7b28dbd86a21f6686e0db77f06536e9a090569e78b0d60e9c924dacc3b7e2" or
    hash.sha256(0, filesize) == "41382ba72b27d90f0c8e72293cccce520751d1b87a841e72be95f558b0bea002" or
    hash.sha256(0, filesize) == "7f571631dc5974149b8f7165b999f09f179e5674260b173fe0bbc38e221a8e88" or
    hash.sha256(0, filesize) == "e85426f6c3244bdf96fde023e7e2d25d88b061a7ae622203427247068af067cb" or
    hash.sha256(0, filesize) == "e1a6bd6f51a9fcae5e8fccc41554f19c431b1418dec4964947c18d643a1bcdef" or
    hash.sha256(0, filesize) == "34254e7c3ec86e864cfc6f88a62bb25187cddefcfaaa6079926ef374fdb74b5e" or
    hash.sha256(0, filesize) == "4a74258dd1dd503a07111074382b11f791c03e94dddc06d04680ae0d61f98de6" or
    hash.sha256(0, filesize) == "74426a4c85dc167e3d82b2f405d9a9ab6b9e2cf4c7ee93fce8a9a0a5fd21c823" or
    hash.sha256(0, filesize) == "83981024c834aacc141729a185cc3f3771e04feb8632ea209d47909e3b82d4b1" or
    hash.sha256(0, filesize) == "d511c100966b936df679e667e2cc18bd4bdef37c2d65ddd5ff32932b4815309c" or
    hash.sha256(0, filesize) == "53d5d833fb1e0b2df11b1c33e696fb490576d1a54b9d509eafe19afa9ee67912" or
    hash.sha256(0, filesize) == "3c7dfa7bd2bd84da4d5be3357806bbc792428bb82a5acb0f350c01affd1a7a8f" or
    hash.sha256(0, filesize) == "e827b2fa3363a526db964ea77b13a38edf35996619f1bf5bf5e5ecc6179b4989" or
    hash.sha256(0, filesize) == "eac009df353d224b3a564310e10e1aea77e0cb8806e56ec0c8dbe84a3af4747e" or
    hash.sha256(0, filesize) == "96041a9b535707f03ead8059db28c2fd76247794c2020eba53e09e52c2e45bb6" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_MIRAI_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_MIRAI_LAB"
    date_IOC   = "2023-11-14 06:10:22"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "MIRAI"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "c8112fddbfed0adfa62343a770dc09984c306063cfe01e4989f8a96893fdb908" or
    hash.sha256(0, filesize) == "0e9ec7fffe192bb53a79d9a71ba74884bc9493cc55c6e363e7ad952c53da25fe" or
    hash.sha256(0, filesize) == "eec68e0190cb6b7683556b3fde3922936b0b0a70d0efd2062c53c87f2adfdb1f" or
    hash.sha256(0, filesize) == "0433abed1161da8a9c18a8855f9a65d9dd2ce66392107e989e058e510033f26e" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_LOKI_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_LOKI_LAB"
    date_IOC   = "2023-11-14 20:10:07"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "LOKI"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "d4285f204614a02df0ce4b1e6e80f402057495dfcdba66993fb94ad5e686e2bd" or
    hash.sha256(0, filesize) == "0a9a1a3c031e0eb6c938510830144f26f88effe94230b1467e09123393b99650" or
    hash.sha256(0, filesize) == "835179a5b8a9c27a30cd81a9caa1e5af30f9e2fc9e6c1cc0c05187049d184faf" or
    hash.sha256(0, filesize) == "c6a124887bee7710a6bfebbc4af9a094cab70e3b82e2bf82a2c75b96424b6142" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_MARSSTEALER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_MARSSTEALER_LAB"
    date_IOC   = "2023-11-14 08:40:14"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "MARSSTEALER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "487ca2266b9ddac43dde09ad484b1b73ca38071698bfda25d419dcf6c5ed3a22" or
    hash.sha256(0, filesize) == "961fa39e74e92717c34a65cefca250df55cfc76faf1780c45e6b7dfc0fc80eca" or
    hash.sha256(0, filesize) == "b4177d3d69f7951f46d07b01204fc749befc81531720de78ab7e75e93db35c58" or
    hash.sha256(0, filesize) == "349f4ed12f7b4cd5d2cecc282f03ca70a28518094973e66749086920ec47fea4" or
    hash.sha256(0, filesize) == "a79f593a22f2698e351aee60ab23afdaa239ef545297e495df30ecedb99fe222" or
    hash.sha256(0, filesize) == "f94464959b33782231ae5a82624d3407833a812cb17c09bca2647e4476b78fde" or
    hash.sha256(0, filesize) == "e878a8eca5b7f4408bfbd0ccd365f04d4e7d0735a45ea3228ffc322fbb36ee9b" or
    hash.sha256(0, filesize) == "c1463af12fd0e9bda5b5c94381ea22d82abd5d95008ffb77894c5be3c77e3bbc" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_SMOKE_LOADER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_SMOKE_LOADER_LAB"
    date_IOC   = "2023-11-14 08:55:41"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "SMOKE_LOADER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "ea226ab509f8001582cace500f1890df678371771cf7ee1cf1d61f949f201c5e" or
    hash.sha256(0, filesize) == "d2a5bffc667647e9ba8a0d1733f9a27df01af72b9dbc7193031aad4c8853c6e4" or
    hash.sha256(0, filesize) == "22f1911d81e0e2feaf26b7b28208b5cbb68be45c39d5a6630c40047de2446f4e" or
    hash.sha256(0, filesize) == "a6189864b80a674de976bc67a13f42fc6e601f2ea11c446047c84e2d12e120ae" or
    hash.sha256(0, filesize) == "95396f2372d133a24cb6a06307c865f37441cb985baa6ce021387ac7b0a2de91" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_ADWARE_NEOREKLAMI_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_ADWARE_NEOREKLAMI_LAB"
    date_IOC   = "2023-11-14 09:01:29"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "ADWARE_NEOREKLAMI"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "fd5d862f187f2b06569ceba8c3cf0960f6446904d88ec36da96cde8ba984e17b" or
    hash.sha256(0, filesize) == "5b8a371c20b16861e2dfc33f4757ffab43c79361a21099d92acda671e46d1f3d" or
    hash.sha256(0, filesize) == "7918ab26eeb714d19d3af80cc905ad014ac6e6a337d7bec51206d17a6ddb24e0" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_STEALC_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_STEALC_LAB"
    date_IOC   = "2023-11-14 08:09:03"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "STEALC"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "18db81d906e97ea89314ddaa87811b43e349e08a2af276dcfe21f3031131e69f" or
    hash.sha256(0, filesize) == "0552f23284ed52e84060cdc66d242f9258bbe0555eab899355b9d848bbf70605" or
    hash.sha256(0, filesize) == "60e9383ff5038ed988a1b988b66091bac7bf93a6d070763f45479dccdfd9d147" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_GLUPTEBA_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_GLUPTEBA_LAB"
    date_IOC   = "2023-11-14 03:47:09"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "GLUPTEBA"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "e26a36702257f07a25adc0e5b1a3ceeabcbcb18b63c8d83c0ccb988f848e4a08" or
    hash.sha256(0, filesize) == "7e2fc238252c47231d37ab938055672b07423ce2688bb32cff3b97dc179fee9b" or
    hash.sha256(0, filesize) == "3648e16fc4cff692d591d0074ce50481a5a3451153a875ddde85ee82dea63614" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_RECORDBREAKER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_RECORDBREAKER_LAB"
    date_IOC   = "2023-11-14 10:05:08"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "RECORDBREAKER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "9b6a1d1a00ddd716e344cc64e5592291bb2eb2f5d36a95a32a7b2bddd02a1402" or
    hash.sha256(0, filesize) == "c3ca3799150177eddce80d6eaf8905f29b02c31651f565a913690b83ba36a788" or
    hash.sha256(0, filesize) == "1abb8e978cc50ac436946ba779cfc8bdd5022a6251aca2d761b09b5a6433fbee" or
    hash.sha256(0, filesize) == "114e74be49ed1e1bc90c85a74aaf60fbc8d766d0e8755c100ffab51a43d71404" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_NETSKY_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NETSKY_LAB"
    date_IOC   = "2023-11-14 12:23:33"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NETSKY"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "6f03ec60269a12b5067044a49f64c77108828bec971cacd120bf777d4c2b8fc0" or
    hash.sha256(0, filesize) == "58a6efaa90c5ee105e520c14c687f9ebefd733dd7d0f9eb599631b650804eb41" or
    hash.sha256(0, filesize) == "8bcd589ae4587480a36aaa7d1c610308f7915195dab6cfe95c106bf854c8e1f6" or
    hash.sha256(0, filesize) == "13b7d1449daae56c1d9e61b2b877a1f06cb1889eb2e7adb895a7af5695bf9eed" or
    hash.sha256(0, filesize) == "2daaafa914c24ec2d2191907e05d92738f5bd0da020bf7c696d1a7664273e175" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

rule IOC_AGENTTESLA_7z {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 08:08:31"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "7z"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "04a69ab46c2e8bbdb13a2da0516d6caad98637405e6f7c580c18cd46b3b8094f" or
    hash.sha256(0, filesize) == "42296e0960cd2bebfb412cfe15f7bdf9f8d0fe2587afc0d09fb1f8655a273a87" or
    hash.sha256(0, filesize) == "458f3af48bcb01ad84a623f56afa02b5bc4758b6e4b7c0c3cd1e0224254b1302" or
    hash.sha256(0, filesize) == "99d376b4afcda6983c0030431b264aaedcfc09d7b805fe0d3c372175695da8a8" or
    hash.sha256(0, filesize) == "caeb162a67c1946c9234161ea37cc50fa5956fce5a3296ef36b7f9a6ba68f889" or
    hash.sha256(0, filesize) == "6d833846ce0ffab7ee3c9f8872fc99e9a06ce8fa0cbcbeb039c00ba209256116" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}
