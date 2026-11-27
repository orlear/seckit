"""Regenerate seckit/locks/semgrep-<version>.txt (run by maintainers when SEMGREP changes).

Resolves Semgrep for every supported platform and Python with `pip install --dry-run`,
then records each package with the sha256 of every published wheel of that release.
Regenerating an existing lock keeps its versions (a newly added Python starts from the newest
older Python's pins); only what no longer resolves moves to the newest release.
Needs network access to pypi.org. Usage: python scripts/lock_semgrep.py
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from seckit import provision  # noqa: E402

PYTHONS = ["3.10", "3.11", "3.12", "3.13", "3.14", "3.15"]
# Requirements of Semgrep left out on a Python where they publish no wheel. Each must have a
# pure-Python fallback (ruamel.yaml runs without its C accelerator). Seckit installs the lock
# with --no-deps and lets `pip check` report only these as missing.
OMIT = {"3.15": {"ruamel-yaml-clib"}}
# (marker os, marker machine, pip --platform tags)
PLATFORMS = {
    ("linux", "x86_64", "gnu"): ["manylinux_2_34_x86_64", "manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64"],
    ("linux", "aarch64", "gnu"): ["manylinux_2_34_aarch64", "manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64"],
    ("linux", "x86_64", "musl"): ["musllinux_1_2_x86_64", "musllinux_1_1_x86_64", "musllinux_1_0_x86_64"],
    ("linux", "aarch64", "musl"): ["musllinux_1_2_aarch64", "musllinux_1_1_aarch64", "musllinux_1_0_aarch64"],
    ("darwin", "x86_64", ""): ["macosx_10_14_x86_64", "macosx_10_9_x86_64"],
    ("darwin", "arm64", ""): ["macosx_11_0_arm64"],
    ("win32", "AMD64", ""): ["win_amd64"],
}


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


try:
    from packaging.markers import Marker
except ImportError:  # pip is required anyway and vendors packaging
    from pip._vendor.packaging.markers import Marker  # type: ignore[no-redef]


def previous_pins(lock: Path) -> tuple[list[tuple[str, str, str | None]], list[str]]:
    """(name, version, marker) of an existing lock, and the Pythons it covered."""
    if not lock.is_file():
        return [], []
    text = lock.read_text().replace("\\\n", " ")
    pins, pythons = [], []
    for line in text.splitlines():
        if line.startswith("# pythons:"):
            pythons = line.split()[2:]
        if not line or line.startswith("#"):
            continue
        requirement = line.split("--hash=")[0].strip()
        spec, _, marker = requirement.partition(";")
        name, _, version = spec.strip().partition("==")
        pins.append((_norm(name), version.strip(), marker.strip() or None))
    if not pythons:  # locks written before the header existed
        pythons = sorted(set(re.findall(r'python_version == "(3\.\d+)"', text)), key=lambda v: int(v.split(".")[1]))
    return pins, pythons


def constraints(key: tuple[str, str, str, str], pins, pythons) -> list[str]:
    """Keep the previous lock's versions: same Python where it was covered, else the newest older one."""
    os_name, machine, _, python = key
    older = [p for p in pythons if int(p.split(".")[1]) <= int(python.split(".")[1])]
    if not pins or not older:
        return []
    base = python if python in pythons else older[-1]
    env = {"sys_platform": os_name, "platform_machine": machine, "python_version": base,
           "python_full_version": base + ".0", "implementation_name": "cpython",
           "platform_python_implementation": "CPython",
           "platform_system": {"linux": "Linux", "darwin": "Darwin", "win32": "Windows"}[os_name],
           "os_name": "nt" if os_name == "win32" else "posix"}
    omitted = OMIT.get(python, set())
    return sorted(f"{n}=={v}" for n, v, m in pins
                  if n not in omitted and n != "semgrep" and (m is None or Marker(m).evaluate(env)))


def resolve(python: str, tags: list[str], pinned: list[str] | None = None) -> dict[str, str] | None:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        command = [sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet", "--isolated",
                   "--report", str(report), "--only-binary=:all:", "--target", str(Path(tmp) / "t"),
                   "--python-version", python, "--implementation", "cp", *_requirements(python)]
        for tag in tags:
            command += ["--platform", tag]
        if pinned:
            constraint = Path(tmp) / "constraints.txt"
            constraint.write_text("\n".join(pinned) + "\n")
            command += ["--constraint", str(constraint)]
        proc = subprocess.run(command, capture_output=True, text=True)
        if proc.returncode:
            return None
        items = json.loads(report.read_text())["install"]
    found = {_norm(i["metadata"]["name"]): i["metadata"]["version"] for i in items}
    if python in OMIT:
        if "semgrep" in found:
            raise SystemExit("semgrep must not be resolved with its dependencies where some are omitted")
        found["semgrep"] = provision.SEMGREP
    return found


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_SEMGREP_REQUIRES: list[str] = []


def _requirements(python: str) -> list[str]:
    """`semgrep==X` itself, or, where some of its requirements are omitted, its other requirements
    (resolved transitively) so the omitted ones never enter the resolution."""
    if python not in OMIT:
        return [f"semgrep=={provision.SEMGREP}"]
    if not _SEMGREP_REQUIRES:
        _SEMGREP_REQUIRES.extend(get_json(f"https://pypi.org/pypi/semgrep/{provision.SEMGREP}/json")["info"]["requires_dist"])
    kept = [r for r in _SEMGREP_REQUIRES if _norm(re.split(r"[\s\[<>=!~;(]", r, maxsplit=1)[0]) not in OMIT[python]]
    if len(kept) == len(_SEMGREP_REQUIRES):
        raise SystemExit(f"OMIT for {python} names nothing Semgrep requires")
    return kept


def main() -> None:
    points: dict[tuple, dict[str, str]] = {}
    jobs = {(o, m, l, py): tags for (o, m, l), tags in PLATFORMS.items() for py in PYTHONS}
    target = ROOT / "seckit" / "locks" / f"semgrep-{provision.SEMGREP}.txt"
    pins, old_pythons = previous_pins(target)

    def job(key):
        pinned = constraints(key, pins, old_pythons)
        found = resolve(key[3], jobs[key], pinned) if pinned else None
        if found is None:
            if pinned:
                print("previous pins do not resolve, using newest releases:", *key, file=sys.stderr)
            found = resolve(key[3], jobs[key])
        return found

    with ThreadPoolExecutor(max_workers=8) as pool:
        for key, found in zip(jobs, pool.map(job, jobs)):
            if found is None:
                print("NO WHEEL-ONLY INSTALL (left out of the lock):", *key, file=sys.stderr)
            else:
                points[key] = found
    missing = sorted({py for (_, _, _, py) in jobs} - {py for (_, _, _, py) in points})
    if missing:
        raise SystemExit(f"no platform resolved for Python {', '.join(missing)}; is pip available? Lock left unchanged")
    for (os_name, machine, libc, python), found in points.items():
        if libc == "musl" and (os_name, machine, "gnu", python) in points and found != points[(os_name, machine, "gnu", python)]:
            raise SystemExit(f"glibc and musl resolve differently for {machine} {python}; markers cannot express that")
    marker_points = {k: v for k, v in points.items() if k[2] != "musl"}
    # (name, version) -> set of (os, machine, python)
    where: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    for (os_name, machine, _, python), found in marker_points.items():
        for name, version in found.items():
            where.setdefault((name, version), set()).add((os_name, machine, python))
    everywhere = set(marker_points_key[:2] + (marker_points_key[3],) for marker_points_key in marker_points)
    lines = [f"# Generated by scripts/lock_semgrep.py for semgrep {provision.SEMGREP}. Do not edit.",
             "# Every wheel published for each release is allowed; pip --require-hashes rejects anything else.",
             "# pythons: " + " ".join(PYTHONS)]
    lines += [f"# omitted: {python} " + " ".join(sorted(names)) for python, names in sorted(OMIT.items())]
    for (name, version), present in sorted(where.items()):
        urls = get_json(f"https://pypi.org/pypi/{name}/{version}/json")["urls"]
        hashes = sorted({u["digests"]["sha256"] for u in urls if u["packagetype"] == "bdist_wheel"})
        if not hashes:
            raise SystemExit(f"{name} {version} has no wheels")
        marker = "" if present == everywhere else " ; " + _marker(present, everywhere)
        lines.append(f"{name}=={version}{marker} " + " ".join(f"\\\n    --hash=sha256:{h}" for h in hashes))
    target.write_text("\n".join(lines) + "\n")
    print(f"wrote {target.relative_to(ROOT)} ({len(where)} packages)", file=sys.stderr)


def _marker(present: set, everywhere: set) -> str:
    clauses = []
    for os_name, machine in sorted({(o, m) for o, m, _ in present}):
        pythons = {p for o, m, p in present if (o, m) == (os_name, machine)}
        all_pythons = {p for o, m, p in everywhere if (o, m) == (os_name, machine)}
        clause = f'sys_platform == "{os_name}" and platform_machine == "{machine}"'
        if pythons != all_pythons:
            clause += " and (" + " or ".join(f'python_version == "{p}"' for p in sorted(pythons)) + ")"
        clauses.append(f"({clause})")
    return " or ".join(clauses)


if __name__ == "__main__":
    main()
