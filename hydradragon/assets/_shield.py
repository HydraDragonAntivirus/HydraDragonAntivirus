"""Professional heavy H + shield mark."""
import resvg_py

CRIM   = "#A80E1C"
CRIM_L = "#D42535"
CRIM_LL= "#E8566A"
CHAR   = "#0E1118"
CHAR_L = "#181D28"
GOLD   = "#C8961A"
GOLD_L = "#F0CC60"
GOLD_LL= "#FFF0A0"

svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
<defs>
  <linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%"   stop-color="''' + CHAR_L + '''"/>
    <stop offset="100%" stop-color="''' + CHAR + '''"/>
  </linearGradient>
  <linearGradient id="gg" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%"   stop-color="''' + GOLD_LL + '''"/>
    <stop offset="45%"  stop-color="''' + GOLD_L + '''"/>
    <stop offset="100%" stop-color="''' + GOLD + '''"/>
  </linearGradient>
  <linearGradient id="hg" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%"   stop-color="''' + CRIM_LL + '''"/>
    <stop offset="40%"  stop-color="''' + CRIM_L + '''"/>
    <stop offset="100%" stop-color="''' + CRIM + '''"/>
  </linearGradient>
  <linearGradient id="hshine" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0%"   stop-color="#fff" stop-opacity="0.18"/>
    <stop offset="40%"  stop-color="#fff" stop-opacity="0.06"/>
    <stop offset="100%" stop-color="#fff" stop-opacity="0.0"/>
  </linearGradient>
  <!-- drop shadow -->
  <filter id="shadow" x="-12%" y="-8%" width="130%" height="130%">
    <feDropShadow dx="0" dy="14" stdDeviation="28" flood-color="#000" flood-opacity="0.9"/>
  </filter>
  <!-- emboss on H -->
  <filter id="emboss">
    <feGaussianBlur in="SourceAlpha" stdDeviation="3" result="blur"/>
    <feOffset dx="0" dy="-3" result="off"/>
    <feComposite in="SourceGraphic" in2="off" operator="over"/>
  </filter>
</defs>

<!-- ── SHIELD ─────────────────────────────────────────────── -->
<g filter="url(#shadow)">

  <!-- outermost black shadow ring -->
  <path d="M 512,108
           L 820,185 L 820,562
           C 820,768 672,892 512,952
           C 352,892 204,768 204,562
           L 204,185 Z"
        fill="#000" opacity="0.5"/>

  <!-- outermost gold rim — very thick -->
  <path d="M 512,118
           L 808,192 L 808,560
           C 808,758 664,878 512,938
           C 360,878 216,758 216,560
           L 216,192 Z"
        fill="url(#gg)"/>

  <!-- dark bevel inset -->
  <path d="M 512,156
           L 768,224 L 768,558
           C 768,738 638,852 512,908
           C 386,852 256,738 256,558
           L 256,224 Z"
        fill="''' + CHAR + '''"/>

  <!-- second gold inner ring — bold -->
  <path d="M 512,168
           L 756,234 L 756,558
           C 756,726 632,834 512,888
           C 392,834 268,726 268,558
           L 268,234 Z"
        fill="none" stroke="url(#gg)" stroke-width="5"/>

  <!-- third thinner inner gold hairline -->
  <path d="M 512,184
           L 740,247 L 740,558
           C 740,714 622,816 512,868
           C 402,816 284,714 284,558
           L 284,247 Z"
        fill="none" stroke="''' + GOLD + '''" stroke-width="1.5" opacity="0.5"/>

  <!-- main dark face -->
  <path d="M 512,192
           L 732,252 L 732,558
           C 732,708 618,808 512,860
           C 406,808 292,708 292,558
           L 292,252 Z"
        fill="url(#sg)"/>

</g>

<!-- ── H MONOGRAM ──────────────────────────────────────────── -->
<!--
  Large, bold, fills the shield.
  Total H: 340 wide x 340 tall, centered at 512,555
  Leg width: 72px. Crossbar height: 62px, centered vertically.
-->
<g filter="url(#emboss)">
  <path d="M 318,368
           L 400,368 L 400,516 L 624,516 L 624,368 L 706,368
           L 706,742 L 624,742 L 624,580 L 400,580 L 400,742 L 318,742
           Z"
        fill="url(#hg)"
        stroke="''' + CHAR + '''" stroke-width="6" stroke-linejoin="miter"/>

  <!-- H left-leg shine -->
  <path d="M 318,368 L 362,368 L 362,516 L 318,516 Z"
        fill="url(#hshine)"/>
  <!-- H right-leg shine -->
  <path d="M 624,368 L 668,368 L 668,516 L 624,516 Z"
        fill="url(#hshine)"/>
  <!-- H crossbar top edge highlight -->
  <path d="M 400,516 L 624,516 L 624,532 L 400,532 Z"
        fill="#fff" opacity="0.10"/>
</g>

<!-- outer gold top-edge specular -->
<path d="M 512,130 C 400,130 280,165 224,200 C 290,158 390,142 512,142 C 634,142 734,158 800,200 C 744,165 624,130 512,130 Z"
      fill="#fff" opacity="0.15"/>

</svg>'''

for fname, bg in [("HydraDragonShield.png", None), ("_shield_preview.png", "#FFFFFF")]:
    data = resvg_py.svg_to_bytes(svg_string=svg, background=bg)
    if isinstance(data, (list, tuple)): data = bytes(data)
    open(fname, "wb").write(data)

with open("HydraDragonShield.svg", "w", encoding="utf-8") as f:
    f.write(svg)

print("done")
