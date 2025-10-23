# async_sync_analyzer.py  (improved, less noisy)
import ast
import sys
import logging
import os
import glob
from typing import Optional, Set, Dict, Tuple, List
import argparse

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

_COROUTINE_CONSUMERS = {
    "create_task",
    "ensure_future",
    "gather",
    "run_coroutine_threadsafe",
    "as_completed",
    "wait",
    "wait_for",
    "run",
    "to_thread",
    "submit",  # executor.submit(coro) can be used intentionally (rare)
}

_TASK_VAR_SUFFIXES = ("_task", "_future", "_coro", "_promise")

class DefCollector(ast.NodeVisitor):
    """Collect async/sync function names defined in a single file."""
    def __init__(self):
        self.async_defs: Set[str] = set()
        self.sync_defs: Set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.sync_defs.add(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.async_defs.add(node.name)
        self.generic_visit(node)


class AsyncSyncAnalyzer(ast.NodeVisitor):
    """
    Analyze a single file using that file's defs. Less noisy heuristics:
     - Only warn for calls inside function bodies (skip top-level module calls)
     - Check ancestor chain up to a few levels for coroutine consumers (create_task/gather/etc)
     - Allow assignment to task-like variable names
     - Allow configurable ignore-list (--ignore)
    """
    def __init__(self, async_defs: Set[str], sync_defs: Set[str], filename: str, ignore_names: Set[str]):
        self.async_defs = async_defs
        self.sync_defs = sync_defs
        self.filename = filename
        self.node_stack: List[ast.AST] = []
        self.function_stack: List[bool] = []  # True if inside async function
        self.errors: List[str] = []
        self.ignore_names = ignore_names

    def generic_visit(self, node):
        self.node_stack.append(node)
        super().generic_visit(node)
        self.node_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.function_stack.append(False)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.function_stack.append(True)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Await(self, node: ast.Await):
        # If awaiting a sync function defined in this file -> warn
        if isinstance(node.value, ast.Call):
            func_name = self.get_function_name(node.value)
            if func_name and func_name in self.sync_defs and func_name not in self.ignore_names:
                self.log_error(node.lineno,
                    f"Sync function '{func_name}' is being called with 'await'. This will raise a TypeError at runtime."
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self.get_function_name(node)
        if not func_name:
            self.generic_visit(node)
            return

        # If this call is at module top-level (no enclosing FunctionDef/AsyncFunctionDef), skip warnings
        if not self._is_inside_function():
            self.generic_visit(node)
            return

        # If ignored by user, skip all checks
        if func_name in self.ignore_names:
            self.generic_visit(node)
            return

        # Determine if this Call is directly awaited (handled by visit_Await)
        parent = self._get_parent()
        is_directly_awaited = isinstance(parent, ast.Await)

        # Only warn about async defs defined in the same file
        if func_name in self.async_defs and not is_directly_awaited:
            # If passed to known coroutine consumer anywhere up the ancestor chain -> safe
            if self._is_passed_to_coroutine_consumer_upwards():
                pass
            elif self._is_assigned_to_task_like_var(node):
                pass
            else:
                self.log_error(
                    node.lineno,
                    f"Async function '{func_name}' is being called without 'await'. This will return a coroutine object, not the result."
                )

        self.generic_visit(node)

    # --- helpers ---
    def _is_inside_function(self) -> bool:
        # return True if any ancestor is a FunctionDef or AsyncFunctionDef
        for n in reversed(self.node_stack):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return True
        return False

    def _get_parent(self) -> Optional[ast.AST]:
        if len(self.node_stack) >= 2:
            return self.node_stack[-2]
        return None

    def _is_passed_to_coroutine_consumer_upwards(self, max_depth: int = 6) -> bool:
        """
        Walk ancestors up to `max_depth` levels to check if this call is (directly or nested)
        used as an arg to a Call whose name is in _COROUTINE_CONSUMERS.
        """
        # walk parents: node_stack[-1] is current node, so skip that and examine parents
        stack = self.node_stack[:-1]
        # We examine parent nodes (calls) up the chain
        depth = 0
        for parent in reversed(stack):
            if depth >= max_depth:
                break
            depth += 1
            if isinstance(parent, ast.Call):
                pfunc = self.get_function_name(parent)
                if pfunc and pfunc in _COROUTINE_CONSUMERS:
                    return True
            # also allow attribute call names (e.g., loop.create_task -> 'create_task' returned by get_function_name)
        return False

    def _is_assigned_to_task_like_var(self, call_node: ast.Call) -> bool:
        """
        If the call_node is on the RHS of an Assign/AnnAssign and the LHS name ends with a task-like suffix,
        treat as intentional and safe.
        """
        parent = self._get_parent()
        if parent is None:
            return False
        if isinstance(parent, ast.Assign):
            for t in parent.targets:
                # name or attribute like self.my_task
                if isinstance(t, ast.Name) and t.id.endswith(_TASK_VAR_SUFFIXES):
                    return True
                if isinstance(t, ast.Attribute) and isinstance(t.attr, str) and t.attr.endswith(_TASK_VAR_SUFFIXES):
                    return True
        if isinstance(parent, ast.AnnAssign):
            t = parent.target
            if isinstance(t, ast.Name) and t.id.endswith(_TASK_VAR_SUFFIXES):
                return True
            if isinstance(t, ast.Attribute) and isinstance(t.attr, str) and t.attr.endswith(_TASK_VAR_SUFFIXES):
                return True
        return False

    def get_function_name(self, call_node: ast.Call) -> Optional[str]:
        func = call_node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    def log_error(self, lineno, message):
        error_msg = f"L{lineno}: {message}"
        self.errors.append(error_msg)
        logger.warning(error_msg)


# --- File helpers ---
def build_defs_for_files(py_files) -> Dict[str, Tuple[Set[str], Set[str]]]:
    defs_by_file: Dict[str, Tuple[Set[str], Set[str]]] = {}
    for file_path in py_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            tree = ast.parse(content, filename=file_path)
            collector = DefCollector()
            collector.visit(tree)
            defs_by_file[file_path] = (collector.async_defs, collector.sync_defs)
        except SyntaxError as e:
            logger.error(f"Syntax error parsing {file_path} on line {e.lineno}: {e.msg}")
            defs_by_file[file_path] = (set(), set())
        except Exception as e:
            logger.error(f"Error collecting defs from {file_path}: {e}")
            defs_by_file[file_path] = (set(), set())
    return defs_by_file

def analyze_file(file_path: str, async_defs: Set[str], sync_defs: Set[str], ignore_names: Set[str]) -> Tuple[int, list]:
    logger.info(f"--- Analyzing {file_path} ---")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content, filename=file_path)
        analyzer = AsyncSyncAnalyzer(async_defs=async_defs, sync_defs=sync_defs, filename=file_path, ignore_names=ignore_names)
        analyzer.visit(tree)

        if not analyzer.errors:
            logger.info(f"Analysis complete for {file_path}: No async/sync mismatches found.")
        else:
            logger.warning(f"Analysis complete for {file_path}: Found {len(analyzer.errors)} potential issue(s).")

        return len(analyzer.errors), analyzer.errors

    except FileNotFoundError:
        logger.error(f"Error: File not found at {file_path}")
        return 0, []
    except SyntaxError as e:
        logger.error(f"Error: Could not parse {file_path}. Syntax error on line {e.lineno}.")
        return 0, []
    except Exception as e:
        logger.error(f"An unexpected error occurred while analyzing {file_path}: {e}")
        return 0, []


# --- CLI ---
def parse_cli():
    p = argparse.ArgumentParser(description="Async/sync analyzer (less noisy)")
    p.add_argument("--ignore", type=str, default="", help="Comma-separated function names to ignore (example: scan_and_warn,scan)")
    p.add_argument("--dir", type=str, default=".", help="Directory to analyze (default current dir)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_cli()
    ignore_names = set(n.strip() for n in args.ignore.split(",") if n.strip())

    print("Starting async/sync analysis for all .py files in current directory...")
    py_files = sorted(glob.glob(os.path.join(args.dir, "*.py")))
    if not py_files:
        print("No .py files found in this directory.")
        sys.exit(0)

    defs_map = build_defs_for_files(py_files)
    total_issues = 0
    all_errors = {}

    for file_to_analyze in py_files:
        # skip analyzer itself
        if os.path.basename(file_to_analyze) == os.path.basename(__file__):
            continue

        async_defs, sync_defs = defs_map.get(file_to_analyze, (set(), set()))
        num_errors, errors = analyze_file(file_to_analyze, async_defs, sync_defs, ignore_names=ignore_names)
        total_issues += num_errors
        if errors:
            all_errors[file_to_analyze] = errors

    print("\n--- Analysis Summary ---")
    if total_issues == 0:
        print("All analyzed files passed.")
    else:
        print(f"Found a total of {total_issues} potential issue(s) across all files.")
        for fname, errs in all_errors.items():
            print(f"\n{fname}:")
            for e in errs:
                print(f"  {e}")
