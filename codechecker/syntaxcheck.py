import ast

class FunctionOrderChecker(ast.NodeVisitor):
    def __init__(self):
        self.function_defs = {}
        self.issues = []

    def visit_FunctionDef(self, node):
        # Store the function definition line number
        self.function_defs[node.name] = node.lineno
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check function calls
        if isinstance(node.func, ast.Name) and node.func.id in self.function_defs:
            call_line = node.lineno
            def_line = self.function_defs[node.func.id]
            if call_line < def_line:
                self.issues.append((node.func.id, call_line, def_line))
        self.generic_visit(node)

def check_function_order(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        source_code = file.read()

    tree = ast.parse(source_code)
    checker = FunctionOrderChecker()
    checker.visit(tree)

    if checker.issues:
        print("Function order issues detected:")
        for func, call_line, def_line in checker.issues:
            print(f"Function '{func}' is called on line {call_line} but defined on line {def_line}.")
    else:
        print("No function order issues detected.")

# Example usage
file_path = 'antivirus.py'
check_function_order(file_path)
