PyLingual bundle generated from Nuitka marshal/code blobs.

Files:
  - bytecode_topXXXX*.marshal : raw marshal/code-object blob
  - bytecode_topXXXX*.pyc     : .pyc rebuilt with the selected magic
  - pyc_list.txt              : one .pyc path per line
  - marshal_list.txt          : one raw marshal path per line
  - manifest.tsv              : export manifest with top-level indexes

Default MAGIC_NUMBER used here: F30D0D0A
For Python 3.11 final that value is A70D0D0A.
If you need a different header, run:
  python make_pyc_list.py --magic-hex <8hex> .

PyLingual usage example:
  pylingual -v 3.13 -o out bytecode_*.pyc
