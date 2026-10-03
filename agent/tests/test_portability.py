"""The suite runs on Linux too (CI): a test that needs Windows says so.

A test that imports a Windows-only module (`agent.winservice`, pywin32's
``win32*``, ``servicemanager``, ``pywintypes``, ``winreg``) and neither fakes
pywin32 nor skips off Windows passes here and fails on the Linux runner -- the
first CI run of the desktop application found one exactly like that. This
reads every test module and names the ones that would.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
WINDOWS_ONLY = ("agent.winservice", "winservice", "servicemanager", "pywintypes", "winreg", "win32")
#: Lo que hace segura a una importación así: un pywin32 de mentira, un salto
#: fuera de Windows, o un try/except ImportError alrededor.
GUARDS = ("fake_pywin32", "skipUnless", "skipIf", "skipTest", "ImportError", "ModuleNotFoundError")


def _windows_only(node: ast.AST) -> bool:
    names: list[str] = []
    if isinstance(node, ast.Import):
        names = [alias.name for alias in node.names]
    elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        names = [module] + [f"{module}.{alias.name}" for alias in node.names]
    return any(name == w or name.startswith(w) for name in names for w in WINDOWS_ONLY if name)


def unguarded_windows_imports(source: str) -> list[int]:
    """Lines of imports of Windows-only modules inside a test with no guard around them. Pure.

    Guardada es una importación con un guard en su función o en cualquier
    clase o función que la contenga (decoradores incluidos).
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def text(scope: ast.ClassDef | ast.FunctionDef) -> str:
        start = min([scope.lineno, *(d.lineno for d in scope.decorator_list)])
        return "\n".join(lines[start - 1 : scope.end_lineno])

    found: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Import | ast.ImportFrom) and _windows_only(node)):
            continue
        scopes = []
        current = parents.get(node)
        while current is not None:
            if isinstance(current, ast.ClassDef | ast.FunctionDef):
                scopes.append(current)
            current = parents.get(current)
        if not scopes:
            continue  # en el módulo: la pila entera de imports ya lo diría al cargar
        if not any(guard in text(scope) for scope in scopes for guard in GUARDS):
            found.append(node.lineno)
    return sorted(set(found))


class WindowsOnlyImportsAreGuardedTests(unittest.TestCase):
    def test_no_test_imports_windows_only_code_without_faking_or_skipping(self) -> None:
        offenders = {}
        for path in sorted(TESTS.glob("test_*.py")):
            lines = unguarded_windows_imports(path.read_text(encoding="utf-8"))
            if lines:
                offenders[path.name] = lines
        self.assertEqual(offenders, {}, "importan algo de Windows sin pywin32 de mentira ni salto fuera de Windows")

    def test_the_check_sees_an_unguarded_import(self) -> None:
        bad = "class T:\n    def test_x(self):\n        from agent import winservice\n"
        good = "class T:\n    @unittest.skipUnless(sys.platform == 'win32', 'x')\n    def test_x(self):\n        from agent import winservice\n"
        self.assertEqual(unguarded_windows_imports(bad), [3])
        self.assertEqual(unguarded_windows_imports(good), [])


if __name__ == "__main__":
    unittest.main()
