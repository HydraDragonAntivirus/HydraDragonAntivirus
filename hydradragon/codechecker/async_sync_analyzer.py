import ast
import sys
import logging
import os
import glob
from typing import Optional

# Configure logging for the analyzer
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class AsyncSyncAnalyzer(ast.NodeVisitor):
    """
    An AST visitor to detect async/sync mismatches.
    - Detects async functions called without 'await'.
    - Detects sync functions called with 'await'.
    """
    def __init__(self):
        self.async_defs = set()
        self.sync_defs = set()
        self.await_stack = []  # To track if we are inside an await expression
        self.errors = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Record a synchronous function definition."""
        self.sync_defs.add(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Record an asynchronous function definition."""
        self.async_defs.add(node.name)
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await):
        """
        Mark that we are inside an await, then visit the call.
        Also checks for awaiting a sync function.
        """
        self.await_stack.append(True)
        
        # Check for awaiting a sync function
        if isinstance(node.value, ast.Call):
            func_name = self.get_function_name(node.value)
            if func_name in self.sync_defs:
                self.log_error(
                    node.lineno,
                    f"Sync function '{func_name}' is being called with 'await'. "
                    f"This will raise a TypeError at runtime."
                )

        self.generic_visit(node.value) # Visit only the awaited call
        self.await_stack.pop()

    def visit_Call(self, node: ast.Call):
        """
        Check a function call for async/sync mismatch.
        """
        func_name = self.get_function_name(node)
        if not func_name:
            self.generic_visit(node)
            return

        is_awaited = bool(self.await_stack)

        # Check for async function called without await
        if func_name in self.async_defs and not is_awaited:
            # We must be inside an async function to call an async function
            # This check is simpler and just flags the missing await
            self.log_error(
                node.lineno,
                f"Async function '{func_name}' is being called without 'await'. "
                f"This will return a coroutine object, not the result."
            )

        self.generic_visit(node)

    def get_function_name(self, call_node: ast.Call) -> Optional[str]:
        """Utility to get the name of the function being called."""
        func = call_node.func
        if isinstance(func, ast.Name):
            return func.id  # e.g., my_function()
        elif isinstance(func, ast.Attribute):
            return func.attr  # e.g., self.my_function() or obj.my_function()
        return None

    def log_error(self, lineno, message):
        """Helper to format and store errors."""
        error_msg = f"L{lineno}: {message}"
        self.errors.append(error_msg)
        logger.warning(error_msg)

def analyze_file(file_path: str, analyzer: AsyncSyncAnalyzer):
    """
    Reads a Python file, parses it, and runs the analyzer.
    """
    logger.info(f"--- Analyzing {file_path} ---")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content, filename=file_path)
        
        # We only visit, the analyzer object is passed in
        analyzer.visit(tree)
        
        # Analyzer now contains all errors for this file
        if not analyzer.errors:
            logger.info(f"Analysis complete for {file_path}: No async/sync mismatches found.")
        else:
            logger.warning(f"Analysis complete for {file_path}: Found {len(analyzer.errors)} potential issue(s).")
            
    except FileNotFoundError:
        logger.error(f"Error: File not found at {file_path}")
    except SyntaxError as e:
        logger.error(f"Error: Could not parse {file_path}. Syntax error on line {e.lineno}.")
    except Exception as e:
        logger.error(f"An unexpected error occurred while analyzing {file_path}: {e}")

if __name__ == "__main__":
    print("Starting async/sync analysis for all .py files in current directory...")
    
    # Find all .py files in the current directory
    py_files = glob.glob('*.py')
    
    if not py_files:
        print("No .py files found in this directory.")
        sys.exit(0)
        
    analyzer = AsyncSyncAnalyzer()
    total_issues = 0
    
    # First pass: Build a list of all function definitions in all files
    for file_to_analyze in py_files:
        try:
            with open(file_to_analyze, 'r', encoding='utf-8') as f:
                content = f.read()
            tree = ast.parse(content, filename=file_to_analyze)
            
            # Create a temporary visitor just to find defs
            def_finder = AsyncSyncAnalyzer()
            def_finder.visit(tree)
            analyzer.async_defs.update(def_finder.async_defs)
            analyzer.sync_defs.update(def_finder.sync_defs)
        except Exception as e:
            logger.error(f"Error during definition pass on {file_to_analyze}: {e}")

    logger.info(f"Found {len(analyzer.async_defs)} async defs and {len(analyzer.sync_defs)} sync defs in total.")

    # Second pass: Analyze all files for call mismatches
    for file_to_analyze in py_files:
        # We don't want the analyzer to analyze itself
        if file_to_analyze == os.path.basename(__file__):
            continue
        
        file_errors_before = len(analyzer.errors)
        analyze_file(file_to_analyze, analyzer)
        file_errors_after = len(analyzer.errors)
        total_issues += (file_errors_after - file_errors_before)

    print("\n--- Analysis Summary ---")
    if total_issues == 0:
        print("All analyzed files passed.")
    else:
        print(f"Found a total of {total_issues} potential issues across all files.")
