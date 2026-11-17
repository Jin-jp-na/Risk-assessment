"""Finite, IP-only scan policy. Scope is supplied by the local operator, not the request."""

import ipaddress
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit


MAX_HOSTS = 32
PROFILES = {
    "quick": {"top_ports": 100, "host_timeout": 30, "timeout": 120, "version": False},
    "standard": {"top_ports": 1000, "host_timeout": 60, "timeout": 300, "version": True},
    "web": {"top_ports": 1000, "host_timeout": 60, "timeout": 300, "version": True},
}


class ScopeError(ValueError):
    pass


class ConfigurationError(ValueError):
    pass


def resolve_executable(variable: str, program: str) -> str:
    configured = os.environ.get(variable, "").strip()
    if configured:
        path = Path(configured)
        if not path.is_absolute() or not path.is_file():
            raise ConfigurationError(f"{variable} must be an absolute path to an existing executable")
        if os.name == "nt" and path.suffix.lower() != ".exe":
            raise ConfigurationError(f"{variable} must point to an .exe file")
        if os.name != "nt" and not os.access(path, os.X_OK):
            raise ConfigurationError(f"{variable} is not executable")
        return str(path.resolve())
    located = shutil.which(program)
    if not located:
        raise ConfigurationError(f"{program} not found; add it to PATH or set {variable}")
    path = Path(located)
    if not path.is_file() or (os.name == "nt" and path.suffix.lower() != ".exe"):
        raise ConfigurationError(f"{program} must resolve to an executable file")
    return str(path.resolve())


def approved_networks() -> list:
    raw = os.environ.get("RISKLENS_ALLOWED_TARGETS", "").strip()
    if not raw:
        raise ScopeError("No approved scope. Set RISKLENS_ALLOWED_TARGETS to authorized IPs/CIDRs")
    try:
        parts = raw.split(",")
        if len(parts) > 64 or any(not part.strip() for part in parts):
            raise ValueError()
        return [ipaddress.ip_network(part.strip(), strict=True) for part in parts]
    except ValueError as exc:
        raise ConfigurationError("RISKLENS_ALLOWED_TARGETS contains an invalid or noncanonical IP/CIDR") from exc


def allowed_address(address) -> bool:
    return address.is_loopback or not (address.is_multicast or address.is_unspecified or address.is_link_local or address.is_reserved)


def validate_targets(targets: list[str], scope: list[str] | None = None) -> list[str]:
    current = approved_networks()
    submitted = [ipaddress.ip_network(item, strict=True) for item in scope] if scope is not None else current
    if not targets or len(targets) > MAX_HOSTS:
        raise ValueError(f"Scan requires 1–{MAX_HOSTS} target addresses")
    addresses = []
    for raw in targets:
        address = ipaddress.ip_address(raw)
        if not allowed_address(address):
            raise ScopeError("Multicast, unspecified, link-local, and reserved targets are not supported")
        for networks in (current, submitted):
            if not any(address.version == net.version and address in net for net in networks):
                raise ScopeError(f"Target {address} is outside explicitly approved scope")
        addresses.append(address)
    if len({address.version for address in addresses}) != 1:
        raise ValueError("A scan must use one IP address family")
    return list(dict.fromkeys(str(address) for address in addresses))


def normalize_ports(raw: str | None, profile: str) -> str | None:
    if not raw:
        return None
    if len(raw) > 4096 or not re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", raw):
        raise ValueError("Ports must be numeric ports/ranges, for example 22,80,8000-8010")
    ports = set()
    for entry in raw.split(","):
        bounds = entry.split("-")
        low, high = int(bounds[0]), int(bounds[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError("Ports must be within 1–65535 with ascending ranges")
        if high - low + 1 > PROFILES[profile]["top_ports"]:
            raise ValueError(f"Too many ports for {profile}")
        ports.update(range(low, high + 1))
        if len(ports) > PROFILES[profile]["top_ports"]:
            raise ValueError(f"Too many ports for {profile}")
    return ",".join(str(port) for port in sorted(ports))


def validate_request(target: str, ports: str | None, profile: str) -> dict:
    if profile not in PROFILES:
        raise ValueError("Supported profiles: quick, standard, web; intrusive vulnerability/full profiles are disabled")
    target = target.strip()
    if not target or len(target) > 256 or "%" in target:
        raise ValueError("Enter an IP address or a canonical CIDR, without zone IDs")
    scope = approved_networks()
    scheme = None
    implied_port = None
    is_cidr = "/" in target and "://" not in target
    if is_cidr:
        network = ipaddress.ip_network(target, strict=True)
        if network.num_addresses > MAX_HOSTS:
            raise ValueError(f"CIDR is limited to {MAX_HOSTS} total addresses")
        if not any(network.version == net.version and network.subnet_of(net) for net in scope):
            raise ScopeError("CIDR is outside explicitly approved scope")
        targets = [str(address) for address in network.hosts()]
        label = str(network)
    else:
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            parsed = urlsplit(target if "://" in target else "//" + target)
            if parsed.scheme and parsed.scheme not in {"http", "https"}:
                raise ValueError("Only HTTP/HTTPS origins are supported")
            if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("Use an IP address or origin without credentials, paths, query, or fragment")
            address = ipaddress.ip_address(parsed.hostname or "")
            implied_port = parsed.port
            scheme = parsed.scheme or None
        targets = [str(address)]
        label = str(address)
    targets = validate_targets(targets)
    if implied_port is not None and ports and normalize_ports(ports, profile) != str(implied_port):
        raise ValueError("Target port conflicts with the ports field")
    ports = normalize_ports(ports or (str(implied_port) if implied_port is not None else None), profile)
    web_url = None
    if profile == "web":
        if is_cidr or len(targets) != 1:
            raise ValueError("Web assessment requires a single IP origin")
        if ports is not None and not ports.isdigit():
            raise ValueError("Web assessment requires one explicit port")
        scheme = scheme or "http"
        port = ports or ("443" if scheme == "https" else "80")
        ports = port
        host = f"[{targets[0]}]" if ":" in targets[0] else targets[0]
        web_url = f"{scheme}://{host}:{port}"
    return {"target": label, "targets": targets, "ports": ports, "scope": [str(net) for net in scope],
            "web_url": web_url, "cidr": is_cidr}


def nmap_command(executable: str, targets: list[str], profile: str, ports: str | None, output: Path) -> list[str]:
    settings = PROFILES[profile]
    command = [executable, "-sT", "-n", "-Pn", "-T3", "--max-retries", "1",
               "--host-timeout", f"{settings['host_timeout']}s"]
    if ":" in targets[0]:
        command.append("-6")
    if settings["version"]:
        command += ["-sV", "--version-light"]
    command += ["-p", ports] if ports else ["--top-ports", str(settings["top_ports"])]
    return command + ["-oX", str(output), *targets]
