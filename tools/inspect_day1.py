"""Offline source inventory. Does not import RiskLens or execute scanner code."""

import ast
import difflib
import hashlib
import json
from pathlib import Path
import re
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect():
    source_files = sorted([
        *ROOT.joinpath("backend").rglob("*.py"),
        *ROOT.joinpath("frontend").rglob("*.html"),
        *ROOT.joinpath("frontend").rglob("*.js"),
        *ROOT.joinpath("frontend").rglob("*.css"),
    ])
    source_files = [p for p in source_files if "__pycache__" not in p.parts]
    manifest = {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in source_files}
    trees = {
        p.relative_to(ROOT).as_posix(): ast.parse(p.read_text(encoding="utf-8-sig"), filename=str(p))
        for p in source_files if p.suffix == ".py"
    }
    routes = []
    for node in trees["backend/main.py"].body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "app"
                    and decorator.args and isinstance(decorator.args[0], ast.Constant)):
                routes.append({"method": decorator.func.attr.upper(), "path": decorator.args[0].value,
                               "handler": node.name, "line": node.lineno})
    archives = []
    for path in sorted(ROOT.glob("*.zip")):
        comparisons = []
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            # Inspect in memory. Never extract archives, including the bundled .git directory.
            for entry in entries:
                if entry.filename not in manifest:
                    continue
                archived = archive.read(entry)
                item = {"file": entry.filename, "bytes_equal": digest(archived) == manifest[entry.filename]}
                if entry.filename.endswith(".py"):
                    item["ast_equal"] = ast.dump(ast.parse(archived.decode("utf-8-sig"))) == ast.dump(trees[entry.filename])
                    if not item["ast_equal"]:
                        item["source_diff"] = list(difflib.unified_diff(
                            archived.decode("utf-8-sig").splitlines(),
                            ROOT.joinpath(entry.filename).read_text(encoding="utf-8-sig").splitlines(),
                            fromfile="ZIP", tofile="working", lineterm="",
                        ))
                comparisons.append(item)
        archives.append({"archive": path.name, "sha256": digest(path.read_bytes()),
                         "entries": len(entries), "expanded_bytes": sum(e.file_size for e in entries),
                         "source_comparisons": comparisons})
    # Exercise only the isolated, pure findings builder with invented in-memory data.
    # No app import, stored targets, reverse DNS, NVD calls, credentials, or subprocesses.
    builder = next(n for n in trees["backend/main.py"].body
                   if isinstance(n, ast.FunctionDef) and n.name == "build_findings")
    module = ast.Module(body=[builder], type_ignores=[])
    namespace = {"Optional": __import__("typing").Optional}
    exec(compile(module, "<isolated-build_findings>", "exec"), namespace)
    findings = namespace["build_findings"]({"hosts": [{"ip": "192.0.2.10", "services": [{
        "port": 22, "protocol": "tcp", "service": "ssh", "product": "synthetic-product",
        "nse_findings": [{"id": "synthetic-script", "output": "NOT VULNERABLE"}],
        "nvd": {"cves": [{"id": "SYNTHETIC-CANDIDATE", "description": "Unverified keyword candidate",
                           "severity": "HIGH", "score": 7.5}]},
    }]}]})
    js = ROOT.joinpath("frontend/static/app.js").read_text(encoding="utf-8-sig")
    frontend_calls = [
        {"line": number, "source": line.strip()}
        for number, line in enumerate(js.splitlines(), 1)
        if re.search(r"fetch\(|window\.location\.href|const url = `/scan/", line)
    ]
    return {"mode": "offline; no app import or target requests", "source_sha256": manifest,
            "python_files_parsed": len(trees), "routes": routes, "archives": archives,
            "frontend_calls": frontend_calls,
            "synthetic_findings_reproduction": findings}


if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2))
