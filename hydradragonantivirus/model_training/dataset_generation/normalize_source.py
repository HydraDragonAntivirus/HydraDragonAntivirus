#!/usr/bin/env python3

import ast
import pathlib
import sys
from typing import Tuple


def version_str_to_tuple(version_str: str) -> tuple[int, int]:
    # a version string is a string like 3.9.2
    versions = [int(version) for version in version_str.split(".")]
    return tuple(versions[:2])


# must be run in python 3.9 or later for ast.unparse() support
# version defaults to whatever version this script is running in; needs to be set explicitly for backwards compatibility
#   ast only supports versions 3.4 and later
def normalize_source(
    source: str,
    version: Tuple[int, int] = sys.version_info[0:2],
    replace_docstrings=False,
) -> str:
    """
    Parse the source code into an AST, then convert back to source.
    This has the following normalizing effects:
        1. whitespace is set according to the PEP standard
        2. each statement is on exactly one line
        3. # comments are removed (note: docstrings are not removed)

    :param str source: The source code to normalize
    :param tuple version: The (Major, Minor) version of python to parse with; must be at least (3, 4); defaults to
                            same version as this script
    :param bool replace_docstrings: Replace all docstrings with 'pass'
    """
    tree = ast.parse(source, feature_version=version)
    if replace_docstrings:
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Str):
                node.value.s = "pass"
    return ast.unparse(tree)


def normalize_source_file(
    source_file_path: str,
    cleaned_suffix: str = "-cleaned",
    version: tuple[int, int] = sys.version_info[0:2],
):
    """
    Normalizes the source code in a given file, then saves it to a '-cleaned' version in the same directory

    :param str source_file_path: The absolute or relative path to the source .py file
    :param str cleaned_suffix: The suffix to add to the cleaned file, typically left as default
    :param tuple version: The (Major, Minor) version of python to parse with; must be at least (3, 4); defaults to
                            same version as this script
    """

    # add the cleaned_suffix to the output_path
    input_path = pathlib.Path(source_file_path).resolve()
    output_path = input_path.with_stem(f"{input_path.stem}{cleaned_suffix}")

    with open(input_path, "r") as source_file:
        normalized_source = normalize_source(source_file.read(), version=version)

    with open(output_path, "w") as cleaned_file:
        cleaned_file.write(normalized_source)

    return output_path
