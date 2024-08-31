import ast
import re

class FunctionOrderChecker(ast.NodeVisitor):
    def __init__(self):
        self.function_defs = {}  # Dictionary to store function definitions and their line numbers
        self.function_calls = []  # List to store function calls and their line numbers

    def visit_FunctionDef(self, node):
        # Store function definitions
        self.function_defs[node.name] = node.lineno
        self.generic_visit(node)

    def visit_Call(self, node):
        # Handle function calls, including those with dots
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            self.function_calls.append((func_name, node.lineno))
        elif isinstance(node.func, ast.Attribute):
            # Capture method calls and use base name for checking
            func_name = node.func.attr
            self.function_calls.append((func_name, node.lineno))
        self.generic_visit(node)

def check_function_order(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        source_code = file.read()

    tree = ast.parse(source_code)
    checker = FunctionOrderChecker()
    checker.visit(tree)

    # Check function calls against definitions
    issues = []
    for func_name, call_line in checker.function_calls:
        # For method calls, we use the base name (before the dot)
        base_func_name = func_name.split('.')[0]
        if base_func_name in checker.function_defs:
            def_line = checker.function_defs[base_func_name]
            if call_line < def_line:
                issues.append((func_name, call_line, def_line))

    if issues:
        print("Function order issues detected:")
        for func, call_line, def_line in issues:
            print(f"Function '{func}' is called on line {call_line} but defined on line {def_line}.")
    else:
        print("No function order issues detected.")

# Example usage
file_path = 'antivirus.py'
check_function_order(file_path)
# You can also check is he doesn't start with whiespace but it will cause not detect other problems like def open function detection which already defined in python
