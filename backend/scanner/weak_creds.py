import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
from typing import Dict, Any, List, Tuple, Iterator
import socket
import paramiko
import ftplib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import threading

# ✅ Common usernames to pair with passwords
COMMON_USERNAMES: List[str] = [
    "root", "admin", "user", "test", "guest", "administrator",
    "ubuntu", "pi", "oracle", "postgres", "mysql", "ftp", "www",
]

ROCKYOU_PATH = Path(__file__).resolve().parent.parent.parent / "wordlists" / "rockyou.txt"

# ✅ Fallback if rockyou not found
FALLBACK_PASSWORDS: List[str] = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "111111", "dragon", "123123", "letmein", "monkey", "master",
    "admin", "root", "toor", "test", "user", "guest", "admin123",
    "password1", "passw0rd", "1234", "1234567", "12345678", "000000",
]

# ✅ Load top N passwords from rockyou.txt lazily
def load_rockyou(limit: int = 10000) -> List[str]:
    if not ROCKYOU_PATH.exists():
        return FALLBACK_PASSWORDS
    passwords = []
    try:
        with ROCKYOU_PATH.open("r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                pw = line.strip()
                if pw:
                    passwords.append(pw)
    except Exception as e:
        return FALLBACK_PASSWORDS
    return passwords

# ✅ Build credential pairs
def build_creds() -> List[Tuple[str, str]]:
    passwords = load_rockyou(limit=10000)
    creds = []
    for username in COMMON_USERNAMES:
        creds.append((username, username))  # username == password
        for password in passwords:
            creds.append((username, password))
    return creds

# ✅ Load once at module level
COMMON_CREDS: List[Tuple[str, str]] = build_creds()


# ✅ Chunked parallel executor — stops immediately on first match
def _parallel_check(
    check_fn,         # function(username, password) -> Dict | None
    creds: List[Tuple[str, str]],
    batch_size: int = 500,
    max_workers: int = 50,
    max_attempts: int = 200,  # Limit total attempts to prevent hanging
) -> Dict[str, Any]:
    found_event = threading.Event()
    found_result: Dict[str, Any] = {}

    # Limit credentials to max_attempts
    creds = creds[:max_attempts]

    for i in range(0, len(creds), batch_size):
        if found_event.is_set():
            break

        batch = creds[i:i + batch_size]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_fn, u, p): (u, p)
                for u, p in batch
                if not found_event.is_set()
            }
            for future in as_completed(futures):
                if found_event.is_set():
                    break
                try:
                    result = future.result(timeout=5)  # 5s timeout per credential attempt
                    if result and result.get("found"):
                        found_event.set()
                        found_result = result
                        break
                except Exception:
                    continue  # Skip failed attempts

        if found_event.is_set():
            break

    return found_result if found_result else {"found": False}


# ─── SSH ────────────────────────────────────────────────────────────────────

def check_ssh_weak_creds(ip: str, port: int = 22, timeout: int = 3) -> Dict[str, Any]:
    def try_ssh(username: str, password: str) -> Dict | None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=ip, port=port,
                username=username, password=password,
                timeout=timeout, banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False, allow_agent=False,
            )
            return {"found": True, "username": username, "password": password, "protocol": "ssh"}
        except (paramiko.AuthenticationException, paramiko.SSHException, EOFError, socket.error, TimeoutError):
            return None
        finally:
            try: client.close()
            except: pass

    return _parallel_check(try_ssh, COMMON_CREDS, batch_size=200, max_workers=20, max_attempts=200)


# ─── FTP ────────────────────────────────────────────────────────────────────

def check_ftp_weak_creds(ip: str, port: int = 21, timeout: int = 3) -> Dict[str, Any]:
    def try_ftp(username: str, password: str) -> Dict | None:
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=timeout)
            ftp.login(username, password)
            ftp.quit()
            return {"found": True, "username": username, "password": password, "protocol": "ftp"}
        except ftplib.error_perm:
            return None
        except Exception:
            return None

    return _parallel_check(try_ftp, COMMON_CREDS, batch_size=200, max_workers=20, max_attempts=200)


# ─── HTTP Basic ─────────────────────────────────────────────────────────────

def check_http_basic_weak_creds(
    base_url: str, timeout: int = 3, paths: List[str] | None = None
) -> Dict[str, Any]:
    if paths is None:
        paths = ["/", "/admin", "/login", "/secure"]

    session = requests.Session()

    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            r0 = session.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue

        www = (r0.headers.get("WWW-Authenticate") or "").lower()
        if not (r0.status_code == 401 and "basic" in www):
            continue

        def try_http(username: str, password: str) -> Dict | None:
            try:
                r1 = session.get(url, auth=(username, password), timeout=timeout, allow_redirects=False)
                if r1.status_code != 401:
                    return {
                        "found": True, "username": username, "password": password,
                        "protocol": "http_basic", "url": url, "status_code": r1.status_code,
                    }
            except requests.RequestException:
                pass
            return None

        result = _parallel_check(try_http, COMMON_CREDS, batch_size=200, max_workers=20, max_attempts=200)
        if result.get("found"):
            return result

    return {"found": False, "protocol": "http_basic"}


# ─── Annotate ───────────────────────────────────────────────────────────────

def annotate_services_with_weak_creds(parsed_scan: Dict[str, Any]) -> None:
    hosts = parsed_scan.get("hosts", [])
    for host in hosts:
        ip = host.get("ip")
        if not ip:
            continue

        for svc in host.get("services", []):
            name = (svc.get("service") or "").lower()
            port = svc.get("port")
            proto = (svc.get("protocol") or "tcp").lower()
            weak_info: Dict[str, Any] = {"found": False}

            if proto == "tcp" and (port == 22 or name == "ssh"):
                weak_info = check_ssh_weak_creds(ip, port=port)

            elif proto == "tcp" and (port == 21 or name == "ftp"):
                weak_info = check_ftp_weak_creds(ip, port=port)

            elif proto == "tcp" and (port in {80, 8080, 443} or name in {"http", "https"}):
                scheme = "https" if port == 443 or name == "https" else "http"
                base_url = f"{scheme}://{ip}:{port}"
                weak_info = check_http_basic_weak_creds(base_url)

            svc["weak_creds"] = weak_info
