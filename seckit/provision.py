"""Non-destructive user-local installation, with verification before execution."""
from __future__ import annotations
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import sys
import venv
import zipfile
from pathlib import Path

from . import sandbox

TRIVY = "0.76.1"
SEMGREP = "1.182.0"
PIP = "26.2.2"
# sha256 of pip-26.2.2-py3-none-any.whl, pinned like the Trivy manifest: PyPI metadata
# must agree with it, so a substituted file or metadata response is rejected.
PIP_SHA256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
# Pinned digest of the publisher's checksum manifest, from immutable GitHub release.
CHECKSUM_SHA256 = "885debc41b570179e81af560e5f393a66be29b9ff8c52915674f3eb2304c535d"

def _note(message: str) -> None:
    """Progress goes to stderr so JSON on stdout stays clean."""
    print(f"seckit: {message}", file=sys.stderr, flush=True)


class ProvisionError(RuntimeError):
    pass

def cache_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "seckit"

def ensure_private_dir(path: Path) -> None:
    """Create the directory owner-only, or refuse one that is a symlink or owned by someone else."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise OSError("cache path is not a directory")
    if hasattr(os, "getuid"):
        if info.st_uid != os.getuid():
            raise OSError("cache directory belongs to another user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            path.chmod(0o700)


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect to anything but HTTPS before the request is made."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ProvisionError("Insecure download redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_MAX_DOWNLOAD = 512 * 1024 * 1024


def fetch(url: str) -> bytes:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ProvisionError("Only HTTPS downloads are allowed")
    try:
        with urllib.request.build_opener(_HttpsOnly).open(url, timeout=60) as response:
            if urllib.parse.urlsplit(response.url).scheme != "https":
                raise ProvisionError("Insecure download redirect")
            data = response.read(_MAX_DOWNLOAD + 1)
    except OSError as exc:
        raise ProvisionError("Download unavailable. Check network access and run seckit doctor.") from exc
    if len(data) > _MAX_DOWNLOAD:
        raise ProvisionError("Download is larger than the allowed limit")
    return data

def verify(data: bytes, digest: str) -> None:
    if hashlib.sha256(data).hexdigest() != digest:
        raise ProvisionError("Download checksum mismatch; nothing executed")

def compatible(path: str, version: str) -> bool:
    try:
        with sandbox.no_network() as proxy:
            p = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15,
                               env=sandbox.environment(None, proxy))
        return p.returncode == 0 and re.search(r"(?<![\d.])" + re.escape(version) + r"(?![\d.])", p.stdout) is not None
    except (OSError, subprocess.TimeoutExpired):
        return False

def _trivy(base: Path) -> str:
    system = {"Linux": "Linux", "Darwin": "macOS", "Windows": "windows"}.get(platform.system())
    arch = {"x86_64": "64bit", "AMD64": "64bit", "aarch64": "ARM64", "arm64": "ARM64"}.get(platform.machine())
    if not system or not arch:
        raise ProvisionError("Unsupported Trivy platform; use Linux, macOS, or Windows x64/ARM64")
    name = "trivy.exe" if os.name == "nt" else "trivy"
    dest = base / f"trivy-{TRIVY}" / name
    if dest.is_file() and compatible(str(dest), TRIVY): return str(dest)
    _note(f"downloading Trivy {TRIVY} (first run only, ~1 min including all scanners)")
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY}/"
    checksums = fetch(url + f"trivy_{TRIVY}_checksums.txt")
    verify(checksums, CHECKSUM_SHA256)
    filename = f"trivy_{TRIVY}_{system}-{arch}." + ("zip" if os.name == "nt" else "tar.gz")
    sums = dict((line.split()[-1].lstrip("*"), line.split()[0]) for line in checksums.decode().splitlines() if len(line.split()) == 2)
    if filename not in sums: raise ProvisionError("No verified binary for this platform")
    data = fetch(url + filename)
    verify(data, sums[filename])
    import io
    if filename.endswith("zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            binary = archive.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember(name)
            if not member.isfile(): raise ProvisionError("Unexpected archive member")
            binary = archive.extractfile(member).read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    temporary = dest.with_suffix(".tmp")
    temporary.write_bytes(binary)
    temporary.chmod(0o700)
    temporary.replace(dest)
    if not compatible(str(dest), TRIVY): raise ProvisionError("Installed Trivy did not pass version check")
    return str(dest)

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _tail(output: bytes, lines: int = 12, limit: int = 2000) -> str:
    """Last lines of installer output, without terminal control or bidi characters."""
    text = _CONTROL.sub("", output.decode("utf-8", "replace"))
    return "\n".join(text.strip().splitlines()[-lines:])[-limit:]


def _checked(command: list[str]) -> str:
    try:
        proc = subprocess.run(command, capture_output=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProvisionError("Scanner installation could not complete") from exc
    if proc.returncode:
        detail = _tail(proc.stderr) or _tail(proc.stdout)
        raise ProvisionError("Semgrep installation failed. A Python covered by the Semgrep lock, binary wheels "
                             "and network access are required; run seckit doctor."
                             + (f"\npip output:\n{detail}" if detail else ""))
    return proc.stdout.decode("utf-8", "replace")


def semgrep_lock() -> Path:
    return Path(__file__).with_name("locks") / f"semgrep-{SEMGREP}.txt"


def lock_header(lock: Path | None = None) -> tuple[list[str], dict[str, set[str]]]:
    """Pythons the lock was resolved for, and packages it deliberately leaves out per Python
    (Semgrep requires them but they publish no wheel there and have a pure-Python fallback)."""
    pythons: list[str] = []
    omitted: dict[str, set[str]] = {}
    try:
        text = (lock or semgrep_lock()).read_text()
    except OSError:
        return pythons, omitted
    for line in text.splitlines():
        if not line.startswith("#"):
            break
        words = line[1:].split()
        if words[:1] == ["pythons:"]:
            pythons = words[1:]
        elif words[:1] == ["omitted:"] and len(words) >= 3:
            omitted.setdefault(words[1], set()).update(words[2:])
    return pythons, omitted


def _current_python() -> str:
    return "%d.%d" % sys.version_info[:2]


def _check_dependencies(python: str, omitted: set[str]) -> None:
    """`pip check` after a --no-deps install: only the lock's declared omissions may be missing."""
    try:
        proc = subprocess.run([python, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "check"],
                              capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProvisionError("Semgrep dependency check could not complete") from exc
    problems, allowed = [], False
    for line in _tail(proc.stdout, lines=200, limit=20000).splitlines():
        line = line.strip()
        match = re.fullmatch(r"\S+ \S+ requires ([A-Za-z0-9_.-]+), which is not installed\.", line)
        if match and re.sub(r"[-_.]+", "-", match.group(1)).lower() in omitted:
            allowed = True
        elif line and line != "No broken requirements found.":
            problems.append(line)
    if problems or (proc.returncode and not allowed):
        raise ProvisionError("Installed Semgrep dependencies are inconsistent:\n" + "\n".join(problems[-12:]))

def _pip_version(python: str) -> str | None:
    """Read the venv pip version without allowing the project cwd to shadow it."""
    try:
        proc = subprocess.run([python, "-I", "-m", "pip", "--version"], capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode:
        return None
    match = re.search(r"\bpip\s+([0-9]+(?:\.[0-9A-Za-z]+)+)", proc.stdout)
    return match.group(1) if match else None

def _ensure_pip(python: str, base: Path) -> None:
    """Replace venv bootstrap pip with a PyPI-metadata-verified pinned wheel."""
    if _pip_version(python) == PIP:
        return
    try:
        metadata = json.loads(fetch(f"https://pypi.org/pypi/pip/{PIP}/json"))
    except (json.JSONDecodeError, TypeError) as exc:
        raise ProvisionError("Pinned pip release metadata was invalid") from exc
    info = metadata.get("info") or {}
    if info.get("name", "").lower() != "pip" or info.get("version") != PIP:
        raise ProvisionError("Pinned pip release metadata did not match the requested version")
    filename = f"pip-{PIP}-py3-none-any.whl"
    matches = [item for item in metadata.get("urls", [])
               if item.get("filename") == filename and item.get("packagetype") == "bdist_wheel"]
    if len(matches) != 1:
        raise ProvisionError("Pinned pip universal wheel was missing from publisher metadata")
    artifact = matches[0]
    url = urllib.parse.urlsplit(artifact.get("url", ""))
    digest = (artifact.get("digests") or {}).get("sha256", "")
    if url.scheme != "https" or url.hostname != "files.pythonhosted.org" or digest != PIP_SHA256:
        raise ProvisionError("Pinned pip wheel metadata was invalid")
    wheel_data = fetch(artifact["url"])
    verify(wheel_data, PIP_SHA256)
    with tempfile.TemporaryDirectory(dir=base) as tmp:
        wheel = Path(tmp) / filename
        wheel.write_bytes(wheel_data)
        requirements = Path(tmp) / "verified-pip.txt"
        requirements.write_text(f"pip=={PIP} --hash=sha256:{digest}\n")
        _checked([python, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
                  "install", "--no-index", "--no-deps", "--find-links", tmp,
                  "--require-hashes", "--upgrade", "-r", str(requirements)])
    if _pip_version(python) != PIP:
        raise ProvisionError("Installed pip did not pass the pinned version check")

def _semgrep(base: Path) -> str:
    folder = base / f"semgrep-{SEMGREP}"
    bindir = folder / ("Scripts" if os.name == "nt" else "bin")
    executable = bindir / ("semgrep.exe" if os.name == "nt" else "semgrep")
    python = str(bindir / ("python.exe" if os.name == "nt" else "python"))
    lock = semgrep_lock()
    if not lock.is_file():
        raise ProvisionError("Seckit is missing the dependency lock for the pinned Semgrep version")
    # The marker is written only after every check passed, so an interrupted or failed install
    # (for example one rejected by `pip check`) is rebuilt instead of reused.
    marker = folder / "verified-requirements.txt"
    if _verified(marker, lock) and executable.exists() and compatible(str(executable), SEMGREP):
        _ensure_pip(python, base)
        return str(executable)
    pythons, omitted = lock_header(lock)
    current = _current_python()
    if sys.implementation.name != "cpython" or current not in pythons:
        supported = ", ".join(pythons) or "none"
        raise ProvisionError(f"Semgrep {SEMGREP} is locked for CPython {supported}; this is "
                             f"{sys.implementation.name} {current}. Reinstall Seckit with a covered Python "
                             "(for example: pipx reinstall --python python3.14 seckit).")
    _note(f"installing Semgrep {SEMGREP} into the scanner cache (first run only)")
    try:
        marker.unlink(missing_ok=True)
        # clear: nothing left over from an earlier failed attempt survives into this install.
        venv.EnvBuilder(with_pip=True, clear=True).create(folder)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvisionError("Python venv/pip support is unavailable; use a full user-space Python installation.") from exc
    _ensure_pip(python, base)
    # Install only wheels (no source builds) whose sha256 is in the lock shipped with Seckit,
    # so a newly published or tampered dependency release cannot be installed. pip's resolver
    # also proves the lock is a complete tree (a dependency without a hash is rejected). Only
    # where the lock declares an omission (Semgrep pins ruamel.yaml.clib, which has no wheel for
    # that Python) is resolution skipped with --no-deps; `pip check` then allows exactly the
    # declared omissions, and runs everywhere as a second check.
    skipped = omitted.get(current, set())
    _checked([python, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "install",
              "--index-url", "https://pypi.org/simple", "--only-binary=:all:",
              *(["--no-deps"] if skipped else []), "--require-hashes", "-r", str(lock)])
    _check_dependencies(python, skipped)
    if not compatible(str(executable), SEMGREP): raise ProvisionError("Installed Semgrep did not pass version check")
    folder.mkdir(parents=True, exist_ok=True)
    temporary = marker.with_suffix(".tmp")
    shutil.copyfile(lock, temporary)
    temporary.replace(marker)
    return str(executable)


def _verified(marker: Path, lock: Path) -> bool:
    """The cached environment finished installing from exactly this lock."""
    try:
        return marker.is_file() and marker.read_bytes() == lock.read_bytes()
    except OSError:
        return False

def _locked_install(base: Path, name: str, installer) -> str:
    """Serialize installers for the same cache, including across CLI processes."""
    with (base / f".{name}.install.lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt
            if lock.tell() == 0:
                lock.write(b"0"); lock.flush()
            lock.seek(0)
            while True:
                try:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.5)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            return installer(base)
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def tools(install: bool = True) -> dict[str, str]:
    base = cache_dir()
    def resolve(spec):
        name, version, installer = spec
        # Executables found on PATH are never reused: PATH (and, on Windows, the
        # working directory) can be controlled by the repository being scanned.
        if install:
            try:
                ensure_private_dir(base)
            except OSError as exc:
                raise ProvisionError("Scanner cache is not writable. Set XDG_CACHE_HOME (LOCALAPPDATA on Windows) to a writable directory.") from exc
            return name, _locked_install(base, name, installer)
        path = base / f"{name}-{version}"
        path = path / ("trivy.exe" if os.name == "nt" else "trivy") if name == "trivy" else path / ("Scripts/semgrep.exe" if os.name == "nt" else "bin/semgrep")
        return name, str(path) if path.exists() and compatible(str(path), version) else None
    specs = (("trivy", TRIVY, _trivy), ("semgrep", SEMGREP, _semgrep))
    with ThreadPoolExecutor(max_workers=2) as workers:
        return {name: path for name, path in workers.map(resolve, specs) if path is not None}
