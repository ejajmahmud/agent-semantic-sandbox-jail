"""AST-based deterministic Python code sandbox jail."""
import ast
from typing import Dict, List, Optional, Tuple, Any

BANNED_MODULES = {"os", "sys", "subprocess", "socket", "shutil", "urllib", "requests", "importlib"}
BANNED_BUILTINS = {"eval", "exec", "open", "__import__", "compile", "globals", "locals"}

class JailResult:
    def __init__(self, success: bool, output: Any = None, error: Optional[str] = None):
        self.success = success
        self.output = output
        self.error = error

class ASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.errors: List[str] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            root_mod = alias.name.split(".")[0]
            if root_mod in BANNED_MODULES:
                self.errors.append(f"Forbidden module import: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and node.module.split(".")[0] in BANNED_MODULES:
            self.errors.append(f"Forbidden module import: {node.module}")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if node.id in BANNED_BUILTINS:
            self.errors.append(f"Forbidden builtin call: {node.id}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if node.attr.startswith("__") and node.attr.endswith("__"):
            self.errors.append(f"Forbidden dunder attribute access: {node.attr}")
        self.generic_visit(node)

class SemanticSandboxJail:
    """Verifies AST safety and executes verified Python snippets in restricted scope."""

    def __init__(self):
        self.safe_builtins = {
            "abs": abs, "min": min, "max": max, "len": len, "range": range,
            "int": int, "float": float, "str": str, "bool": bool, "list": list,
            "dict": dict, "set": set, "sum": sum, "round": round, "zip": zip
        }

    def execute(self, code: str) -> JailResult:
        try:
            tree = ast.parse(code)
        except Exception as e:
            return JailResult(False, error=f"Syntax error: {e}")

        visitor = ASTSecurityVisitor()
        visitor.visit(tree)
        if visitor.errors:
            return JailResult(False, error=f"Security violation: {'; '.join(visitor.errors)}")

        safe_globals = {"__builtins__": self.safe_builtins}
        safe_locals: Dict[str, Any] = {}

        try:
            compiled = compile(tree, "<sandbox>", "exec")
            exec(compiled, safe_globals, safe_locals)
            return JailResult(True, output=safe_locals.get("result", safe_locals))
        except Exception as e:
            return JailResult(False, error=f"Runtime error: {e}")
