PyLingual bundle generated from Nuitka 'X' bytecode blobs.

Files:
  - bytecode_XXXX.marshal : raw marshal/code-object blob
  - bytecode_XXXX.pyc     : .pyc rebuilt with the selected magic
  - pyc_list.txt          : one .pyc path per line
  - marshal_list.txt      : one raw marshal path per line
  - manifest.tsv          : bundle manifest

Default MAGIC_NUMBER used here: A70D0D0A
For Python 3.11 final that value is A70D0D0A.
If you need a different header, run:
  python make_pyc_list.py --magic-hex <8hex> .

PyLingual usage example:
  pylingual -v 3.11 -o out bytecode_*.pyc
