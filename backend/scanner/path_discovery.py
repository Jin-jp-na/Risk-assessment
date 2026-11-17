"""Bounded optional Gobuster process. All output remains path observations."""

import os
from pathlib import Path
import re
import subprocess
from time import monotonic

from backend.scanner.scan_policy import ConfigurationError

JOB_TIMEOUT = 120
MAX_WORDS = 32


class DiscoveryStopped(RuntimeError):
    pass


def prepare_wordlist(source: Path, destination: Path):
    if not source.is_file() or source.stat().st_size > 8192:
        raise ConfigurationError("The bounded web discovery wordlist is missing or too large")
    words = list(dict.fromkeys(line.strip() for line in source.read_text(encoding="utf-8").splitlines()
                              if line.strip() and not line.lstrip().startswith("#")))
    if not 1 <= len(words) <= MAX_WORDS:
        raise ConfigurationError(f"Optional discovery requires 1-{MAX_WORDS} paths")
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,79}", word)
           or any(part in {"", ".", ".."} for part in word.split("/")) for word in words):
        raise ConfigurationError("Discovery wordlist contains unsafe paths")
    destination.write_text("\n".join(words) + "\n", encoding="utf-8")
    return len(words)


def execute_discovery(executable, url, wordlist, output, stop_event, validate_scope):
    command = [executable, "dir", "-u", url, "-w", str(wordlist), "-o", str(output),
               "-t", "1", "--delay", "1s", "--timeout", "5s", "--no-color", "--no-progress", "-q"]
    # No -k, redirect-following, extensions, recursion, retries or extra targets.
    process = None
    started = monotonic()
    try:
        validate_scope()
        if stop_event.is_set():
            raise DiscoveryStopped("Path discovery stopped before launch")
        with output.with_suffix(".stdout.log").open("wb") as stdout, output.with_suffix(".stderr.log").open("wb") as stderr:
            process = subprocess.Popen(
                command, shell=False, stdout=stdout, stderr=stderr,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                env={key: value for key, value in os.environ.items()
                     if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}})
            while process.poll() is None:
                if stop_event.is_set():
                    raise DiscoveryStopped("Path discovery stopped by the operator")
                if monotonic() - started >= JOB_TIMEOUT:
                    raise subprocess.TimeoutExpired(command, JOB_TIMEOUT)
                validate_scope()
                stop_event.wait(0.2)
            code = process.wait(timeout=5)
        if code:
            with output.with_suffix(".stderr.log").open("rb") as diagnostic:
                diagnostic.seek(max(0, output.with_suffix(".stderr.log").stat().st_size - 2000))
                detail = diagnostic.read(2000).decode("utf-8", errors="replace")
            raise RuntimeError(f"Gobuster exited with code {code}: {detail or 'No diagnostic output'}")
        # Some versions log per-request failures but still exit zero. Such a run
        # cannot establish negative path coverage for later comparisons.
        for suffix in (".stderr.log", ".stdout.log"):
            diagnostic_path = output.with_suffix(suffix)
            with diagnostic_path.open("rb") as diagnostic:
                diagnostic.seek(max(0, diagnostic_path.stat().st_size - 4000))
                detail = diagnostic.read(4000).decode("utf-8", errors="replace").strip()
            if detail and (suffix == ".stderr.log" or "[ERROR]" in detail):
                raise RuntimeError(f"Gobuster diagnostics indicate uncertain coverage: {detail}")
        return command
    finally:
        # Popen has no shell/child launcher; kill and reap the actual job on every early exit.
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def parse_paths(path):
    entries, seen = [], set()
    if not path.exists():
        return entries
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            match = re.fullmatch(r"(/\S*)\s+\(Status:\s*(\d{3})\)\s*(?:\[Size:\s*(\d+)\])?.*", line.strip())
            if not match:
                continue
            web_path, status, size = match.groups()
            status = int(status)
            if web_path.startswith("//") or not 100 <= status <= 599 or (web_path, status) in seen:
                continue
            seen.add((web_path, status))
            entries.append({"path": web_path, "status": status, "size": int(size) if size else None,
                            "category": "path_observation", "evidence": line.strip(),
                            "interpretation": "A path response was observed; access, sensitivity and vulnerability are not established."})
    return entries
