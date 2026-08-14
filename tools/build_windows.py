#!/usr/bin/env python3
"""Build and audit the unsigned self-contained Windows x64 Beta archive."""

from __future__ import annotations

import argparse
import calendar
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import build_release as release  # noqa: E402


PYINSTALLER_VERSION = "6.21.0"
REQUIRED_DISTRIBUTIONS = {
    "altgraph": "0.17.5",
    "packaging": "26.3",
    "pefile": "2024.8.26",
    "psutil": "7.2.2",
    "PyInstaller": PYINSTALLER_VERSION,
    "pyinstaller-hooks-contrib": "2026.6",
    "pywin32": "312",
    "pywin32-ctypes": "0.2.3",
    "setuptools": "84.0.0",
}
PRODUCT_NAME = "LocalOps"
SIGNING_STATUS = "UNSIGNED DEVELOPMENT BUILD"
MARKER_NAME = "UNSIGNED DEVELOPMENT BUILD.txt"
BUILD_INFO_NAME = "BUILD-INFO.json"
RUNTIME_LICENSES_DIR = "THIRD-PARTY-LICENSES"
DEFAULT_OUTPUT_DIR = ROOT / "dist" / "windows"
ENTRYPOINT = ROOT / "localops" / "windows" / "packaged_entry.py"
ICON = ROOT / "static" / "assets" / "favicon.ico"
DATA_INPUTS = (
    (ROOT / "VERSION", "."),
    (ROOT / "static", "static"),
    (ROOT / "LICENSE", "."),
    (ROOT / "THIRD_PARTY_NOTICES.md", "."),
    (ROOT / "licenses", "licenses"),
)
FORBIDDEN_RUNTIME_NAMES = {
    "config.json",
    "console.log",
    "receipt.json",
    "request.json",
    "token.bin",
}
FORBIDDEN_RUNTIME_PARTS = {
    "__pycache__",
    "cache",
    "data",
    "logs",
    "runtime",
}
WINDOWS_BINARY_SUFFIXES = {".dll", ".exe", ".pyd", ".pyc", ".zip"}
WINDOWS_FORBIDDEN_NAME_CHARS = frozenset('<>:"\\|?*')
WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    "com¹",
    "com²",
    "com³",
    "lpt¹",
    "lpt²",
    "lpt³",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def fail(message: str) -> None:
    raise SystemExit(message)


def archive_name(version: str) -> str:
    return f"local-ops-{version}-windows-x64-unsigned.zip"


def bundle_name(version: str) -> str:
    return f"LocalOps-{version}-windows-x64"


def checksum_path(archive: Path) -> Path:
    return archive.with_suffix(archive.suffix + ".sha256")


def manifest_path(archive: Path) -> Path:
    return archive.with_suffix(archive.suffix + ".manifest.json")


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate_windows_icon_bytes(data: bytes) -> None:
    if len(data) < 6 or data[:4] != b"\x00\x00\x01\x00":
        fail("Windows icon is not a valid ICO file")
    count = int.from_bytes(data[4:6], "little")
    if count < 1 or len(data) < 6 + count * 16:
        fail("Windows icon directory is truncated")
    sizes = {
        (
            data[6 + index * 16] or 256,
            data[7 + index * 16] or 256,
        )
        for index in range(count)
    }
    if (256, 256) not in sizes:
        fail("Windows icon must include a 256x256 image")


def validate_windows_icon(path: Path = ICON) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        fail(f"cannot read Windows icon: {exc}")
    validate_windows_icon_bytes(data)


def _numeric_version(version: str) -> tuple[int, int, int, int]:
    match = release.SEMVER_RE.fullmatch(version)
    if not match:
        fail(f"VERSION is not valid SemVer: {version!r}")
    return tuple(int(match.group(index)) for index in range(1, 4)) + (0,)


def version_resource(version: str) -> str:
    numeric = _numeric_version(version)
    dotted = ", ".join(str(value) for value in numeric)
    return f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({dotted}), prodvers=({dotted}),
    mask=0x3f, flags=0x20, OS=0x40004, fileType=0x1,
    subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', 'Local Ops contributors'),
        StringStruct('FileDescription', 'Local Ops Console'),
        StringStruct('FileVersion', '{version}'),
        StringStruct('InternalName', '{PRODUCT_NAME}'),
        StringStruct('LegalCopyright', 'MIT License'),
        StringStruct('OriginalFilename', '{PRODUCT_NAME}.exe'),
        StringStruct('ProductName', 'Local Ops Console'),
        StringStruct('ProductVersion', '{version}'),
        StringStruct('SpecialBuild', '{SIGNING_STATUS}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])])
"""


def _require_windows_build_host() -> None:
    if sys.platform != "win32":
        fail("Windows package builds must run on Windows")
    if sys.version_info[:2] != (3, 12):
        fail("Windows package builds require Python 3.12")
    machine = platform.machine().casefold()
    if machine not in {"amd64", "x86_64"} or struct.calcsize("P") != 8:
        fail("Windows package builds require native x64 Python")
    for distribution_name, expected in REQUIRED_DISTRIBUTIONS.items():
        try:
            actual = metadata.version(distribution_name)
        except metadata.PackageNotFoundError:
            fail(
                f"{distribution_name} is not installed; install the pinned "
                "Windows runtime and build requirements"
            )
        if actual != expected:
            fail(
                f"{distribution_name} {expected} is required; found {actual}"
            )


def pyinstaller_command(temp: Path, version_file: Path) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--noupx",
        "--name",
        PRODUCT_NAME,
        "--distpath",
        str(temp / "pyinstaller-dist"),
        "--workpath",
        str(temp / "pyinstaller-work"),
        "--specpath",
        str(temp / "pyinstaller-spec"),
        "--paths",
        str(ROOT),
        "--icon",
        str(ICON),
        "--version-file",
        str(version_file),
        "--hidden-import",
        "localops.platform.windows",
        "--hidden-import",
        "localops.windows.runner",
        "--hidden-import",
        "win32timezone",
    ]
    for source, destination in DATA_INPUTS:
        command.extend(("--add-data", f"{source};{destination}"))
    command.append(str(ENTRYPOINT))
    return command


def pyinstaller_environment() -> dict[str, str]:
    """Freeze PyInstaller ordering and PE timestamps for reproducible bytes."""
    environment = dict(os.environ)
    environment["PYTHONHASHSEED"] = "0"
    environment["SOURCE_DATE_EPOCH"] = str(
        calendar.timegm(release.archive_timestamp())
    )
    return environment


def _license_files(distribution_name: str) -> list[tuple[Path, Path]]:
    try:
        distribution = metadata.distribution(distribution_name)
    except metadata.PackageNotFoundError:
        fail(f"required distribution is not installed: {distribution_name}")
    candidates = []
    for item in distribution.files or ():
        relative = PurePosixPath(str(item).replace("\\", "/"))
        lowered = relative.name.casefold()
        parts = [part.casefold() for part in relative.parts]
        if not (
            lowered.startswith(("license", "copying", "notice"))
            or "licenses" in parts
        ):
            continue
        source = Path(distribution.locate_file(item))
        if source.is_file():
            candidates.append((source, relative))
    if not candidates:
        fail(f"no distributable license files found for {distribution_name}")

    preferred = [
        item for item in candidates
        if any(part.endswith(".dist-info") for part in item[1].parts)
    ] or candidates
    result = []
    for source, relative in preferred:
        lowered_parts = [part.casefold() for part in relative.parts]
        if "licenses" in lowered_parts:
            index = lowered_parts.index("licenses")
            target = Path(*relative.parts[index + 1:])
        else:
            target = Path(relative.name)
        if not target.parts:
            target = Path(relative.name)
        result.append((source, target))
    return sorted(set(result), key=lambda item: item[1].as_posix().casefold())


def _copy_runtime_licenses(bundle: Path) -> None:
    destination = bundle / RUNTIME_LICENSES_DIR
    destination.mkdir()
    python_candidates = (
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.prefix) / "LICENSE.txt",
    )
    python_license = next((path for path in python_candidates if path.is_file()), None)
    if python_license is None:
        fail("Python runtime LICENSE.txt was not found")
    shutil.copyfile(python_license, destination / "Python-LICENSE.txt")

    for distribution_name in ("psutil", "pywin32", "PyInstaller"):
        target_root = destination / distribution_name
        for source, relative in _license_files(distribution_name):
            target = target_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)


def _write_build_metadata(bundle: Path, version: str) -> None:
    (bundle / MARKER_NAME).write_text(
        SIGNING_STATUS + "\n", encoding="ascii", newline="\n"
    )
    payload = {
        "architecture": "x64",
        "entrypoint": "localops.windows.packaged_entry",
        "packaging": "PyInstaller onedir windowed",
        "product": "Local Ops Console",
        "pyinstallerVersion": PYINSTALLER_VERSION,
        "pythonVersion": platform.python_version(),
        "runtimeDistributions": {
            name: metadata.version(name)
            for name in ("psutil", "pywin32")
        },
        "runnerDispatch": "-m localops.windows.runner",
        "schemaVersion": 1,
        "signingStatus": SIGNING_STATUS,
        "version": version,
    }
    (bundle / BUILD_INFO_NAME).write_bytes(_canonical_json(payload))


def _validate_build_info(value: object, version: str) -> None:
    if not isinstance(value, dict):
        fail("Windows BUILD-INFO.json must be an object")
    build_info = dict(value)
    python_version = build_info.pop("pythonVersion", None)
    if not isinstance(python_version, str) or not re.fullmatch(
        r"3\.12\.\d+", python_version
    ):
        fail("Windows BUILD-INFO.json requires a Python 3.12 build runtime")
    expected = {
        "architecture": "x64",
        "entrypoint": "localops.windows.packaged_entry",
        "packaging": "PyInstaller onedir windowed",
        "product": "Local Ops Console",
        "pyinstallerVersion": PYINSTALLER_VERSION,
        "runtimeDistributions": {
            "psutil": REQUIRED_DISTRIBUTIONS["psutil"],
            "pywin32": REQUIRED_DISTRIBUTIONS["pywin32"],
        },
        "runnerDispatch": "-m localops.windows.runner",
        "schemaVersion": 1,
        "signingStatus": SIGNING_STATUS,
        "version": version,
    }
    if build_info != expected:
        fail("Windows BUILD-INFO.json does not match the release contract")


def _bundle_files(bundle: Path) -> list[Path]:
    if bundle.is_symlink() or not bundle.is_dir():
        fail("PyInstaller output is not a regular onedir bundle")
    files = []
    for path in bundle.rglob("*"):
        if path.is_symlink():
            fail(f"Windows bundle contains a symlink: {path.relative_to(bundle)}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(f"Windows bundle contains a non-regular file: {path}")
        files.append(path)
    return sorted(files, key=lambda path: path.relative_to(bundle).as_posix())


def expected_bundled_data() -> dict[str, bytes]:
    """Return the exact source-controlled data PyInstaller must embed."""
    result = {}
    for source, destination in DATA_INPUTS:
        if source.is_symlink() or not source.exists():
            fail(f"Windows package data input is unsafe or missing: {source}")
        if source.is_file():
            items = ((source, PurePosixPath(source.name)),)
        elif source.is_dir():
            collected = []
            for item in sorted(source.rglob("*")):
                if item.is_symlink():
                    fail(f"Windows package data input contains a symlink: {item}")
                if item.is_file():
                    collected.append((
                        item,
                        PurePosixPath(item.relative_to(source).as_posix()),
                    ))
                elif not item.is_dir():
                    fail(f"Windows package data input is not regular: {item}")
            items = tuple(collected)
        else:
            fail(f"Windows package data input is not a regular path: {source}")
        target_root = PurePosixPath("_internal")
        if destination != ".":
            target_root /= destination
        for item, relative in items:
            result[(target_root / relative).as_posix()] = item.read_bytes()
    return result


def _validate_payload(relative: PurePosixPath, data: bytes) -> None:
    parts = {part.casefold() for part in relative.parts}
    name = relative.name.casefold()
    if name in FORBIDDEN_RUNTIME_NAMES or parts & FORBIDDEN_RUNTIME_PARTS:
        fail(f"Windows bundle contains user runtime state: {relative}")
    path = Path(*relative.parts)
    if release.has_excluded_part(path) or release.is_sensitive_path(path):
        fail(f"Windows bundle contains a forbidden path: {relative}")
    leaked_path = _find_package_path_leak(relative, data)
    if leaked_path:
        fail(f"Windows bundle contains an absolute user path: {relative} ({leaked_path})")
    secret = release.find_secret_marker(data)
    if secret:
        fail(f"Windows bundle contains sensitive content: {relative} ({secret})")


def _find_package_path_leak(relative: PurePosixPath, data: bytes) -> str | None:
    """Reject local build paths while tolerating upstream binary build metadata."""
    lowered = data.lower()
    for path in (Path.home().resolve(), ROOT.resolve(), Path(sys.prefix).resolve()):
        raw = str(path)
        for value in {raw, raw.replace("\\", "/")}:
            for encoded in (value.encode("utf-8"), value.encode("utf-16le")):
                if encoded.lower() in lowered:
                    return value
    if relative.suffix.casefold() in WINDOWS_BINARY_SUFFIXES:
        return None
    return release.find_path_leak(data)


def _validate_windows_archive_member(name: str, expected_root: str) -> PurePosixPath:
    raw_parts = name.split("/")
    if (
        not name
        or name.startswith(("/", "\\"))
        or "\\" in name
        or any(part in {"", ".", ".."} for part in raw_parts)
        or raw_parts[0] != expected_root
    ):
        fail(f"Windows archive member path is unsafe: {name}")
    for part in raw_parts:
        if (
            part[-1] in {" ", "."}
            or any(ord(character) < 32 for character in part)
            or any(character in WINDOWS_FORBIDDEN_NAME_CHARS for character in part)
            or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
        ):
            fail(f"Windows archive member path is unsafe: {name}")
    return PurePosixPath(*raw_parts)


def _zip_bundle(bundle: Path, archive: Path, version: str) -> None:
    timestamp = release.archive_timestamp()
    prefix = bundle_name(version)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{archive.name}.", suffix=".tmp", dir=archive.parent,
            delete=False,
        ) as output:
            temporary = Path(output.name)
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as target:
            for source in _bundle_files(bundle):
                relative = PurePosixPath(source.relative_to(bundle).as_posix())
                data = source.read_bytes()
                _validate_payload(relative, data)
                info = zipfile.ZipInfo(f"{prefix}/{relative.as_posix()}", timestamp)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                mode = 0o755 if relative.name.casefold().endswith(".exe") else 0o644
                info.external_attr = (stat.S_IFREG | mode) << 16
                target.writestr(info, data)
        os.replace(temporary, archive)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _payload_records(archive: Path) -> list[dict[str, object]]:
    records = []
    with zipfile.ZipFile(archive) as source:
        for info in source.infolist():
            data = source.read(info)
            records.append({
                "path": info.filename,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            })
    return records


def _manifest(archive: Path, version: str) -> dict[str, object]:
    return {
        "archive": {
            "file": archive.name,
            "sha256": release.sha256(archive),
            "size": archive.stat().st_size,
        },
        "architecture": "x64",
        "packaging": "PyInstaller onedir windowed",
        "payload": _payload_records(archive),
        "product": "Local Ops Console",
        "schemaVersion": 1,
        "signingStatus": SIGNING_STATUS,
        "version": version,
    }


def _write_sidecars(archive: Path, version: str) -> None:
    digest = release.sha256(archive)
    _atomic_write(
        checksum_path(archive), f"{digest}  {archive.name}\n".encode("ascii")
    )
    _atomic_write(manifest_path(archive), _canonical_json(_manifest(archive, version)))


def _archive_version(archive: Path) -> str:
    prefix = "local-ops-"
    suffix = "-windows-x64-unsigned.zip"
    name = archive.name
    if not name.startswith(prefix) or not name.endswith(suffix):
        fail("Windows archive name must include version, platform, x64, and unsigned")
    value = name[len(prefix):-len(suffix)]
    if not release.SEMVER_RE.fullmatch(value):
        fail(f"Windows archive name has an invalid version: {value!r}")
    return value


def _pe_version_fields(
    executable: bytes,
) -> tuple[dict[str, str], tuple[int, int, int, int], tuple[int, int, int, int]]:
    try:
        import pefile
    except ImportError:
        fail("pefile is required to audit Windows version resources")
    try:
        image = pefile.PE(data=executable, fast_load=False)
    except pefile.PEFormatError as exc:
        fail(f"LocalOps.exe version resources are unreadable: {exc}")
    try:
        fields = {}
        for group in getattr(image, "FileInfo", ()) or ():
            for entry in group:
                if getattr(entry, "Key", None) != b"StringFileInfo":
                    continue
                for table in getattr(entry, "StringTable", ()):
                    fields.update({
                        key.decode("utf-8"): value.decode("utf-8")
                        for key, value in table.entries.items()
                    })
        fixed = (getattr(image, "VS_FIXEDFILEINFO", ()) or (None,))[0]
        if fixed is None:
            fail("LocalOps.exe is missing VS_FIXEDFILEINFO")

        def components(ms: int, ls: int) -> tuple[int, int, int, int]:
            return (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)

        return (
            fields,
            components(fixed.FileVersionMS, fixed.FileVersionLS),
            components(fixed.ProductVersionMS, fixed.ProductVersionLS),
        )
    finally:
        image.close()


def _validate_pe(executable: bytes, version: str) -> None:
    if len(executable) < 0x40 or executable[:2] != b"MZ":
        fail("LocalOps.exe is not a PE executable")
    pe_offset = int.from_bytes(executable[0x3C:0x40], "little")
    if pe_offset + 96 > len(executable):
        fail("LocalOps.exe has a truncated PE header")
    if executable[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        fail("LocalOps.exe has an invalid PE signature")
    machine = int.from_bytes(executable[pe_offset + 4:pe_offset + 6], "little")
    if machine != 0x8664:
        fail("LocalOps.exe is not x64")
    optional = pe_offset + 24
    magic = int.from_bytes(executable[optional:optional + 2], "little")
    subsystem = int.from_bytes(executable[optional + 68:optional + 70], "little")
    if magic != 0x20B or subsystem != 2:
        fail("LocalOps.exe is not a windowed PE32+ executable")
    fields, file_version, product_version = _pe_version_fields(executable)
    expected_numeric = _numeric_version(version)
    if file_version != expected_numeric or product_version != expected_numeric:
        fail("LocalOps.exe fixed file/product versions do not match VERSION")
    expected_fields = {
        "FileDescription": "Local Ops Console",
        "FileVersion": version,
        "InternalName": PRODUCT_NAME,
        "OriginalFilename": PRODUCT_NAME + ".exe",
        "ProductName": "Local Ops Console",
        "ProductVersion": version,
        "SpecialBuild": SIGNING_STATUS,
    }
    if any(fields.get(key) != value for key, value in expected_fields.items()):
        fail("LocalOps.exe string version resources do not match the release contract")


def audit_archive(archive: Path) -> dict[str, object]:
    archive = archive.resolve()
    if not archive.is_file():
        fail(f"Windows archive does not exist: {archive}")
    version = _archive_version(archive)
    expected_root = bundle_name(version)
    try:
        with zipfile.ZipFile(archive) as source:
            if source.comment:
                fail("Windows archive contains a ZIP comment")
            infos = source.infolist()
            names = [info.filename for info in infos]
            if names != sorted(names) or len(names) != len(set(names)):
                fail("Windows archive members are duplicated or not sorted")
            damaged = source.testzip()
            if damaged:
                fail(f"Windows archive CRC failed: {damaged}")
            payload = {}
            windows_names = set()
            for info in infos:
                if info.is_dir():
                    fail(f"Windows archive member path is unsafe: {info.filename}")
                path = _validate_windows_archive_member(info.filename, expected_root)
                windows_name = info.filename.casefold()
                if windows_name in windows_names:
                    fail(
                        "Windows archive member paths collide case-insensitively: "
                        + info.filename
                    )
                windows_names.add(windows_name)
                data = source.read(info)
                relative = PurePosixPath(*path.parts[1:])
                _validate_payload(relative, data)
                payload[relative.as_posix()] = data
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        fail(f"cannot audit Windows archive: {exc}")

    required = {
        PRODUCT_NAME + ".exe",
        MARKER_NAME,
        BUILD_INFO_NAME,
        "_internal/VERSION",
        "_internal/LICENSE",
        "_internal/THIRD_PARTY_NOTICES.md",
        "_internal/static/index.html",
        "_internal/static/app.js",
        "_internal/static/assets/favicon.ico",
        "_internal/licenses/Geist-OFL-1.1.txt",
        "_internal/licenses/Lucide-LICENSE.txt",
        f"{RUNTIME_LICENSES_DIR}/Python-LICENSE.txt",
    }
    missing = sorted(required - payload.keys())
    if missing:
        fail("Windows archive is missing required files: " + ", ".join(missing))
    expected_data = expected_bundled_data()
    missing_data = sorted(expected_data.keys() - payload.keys())
    if missing_data:
        fail(
            "Windows archive is missing source-controlled package data: "
            + ", ".join(missing_data)
        )
    changed_data = sorted(
        name for name, data in expected_data.items() if payload.get(name) != data
    )
    if changed_data:
        fail(
            "Windows archive package data does not match the source: "
            + ", ".join(changed_data)
        )
    required_runtime_files = {
        "_internal/psutil/_psutil_windows.pyd",
        "_internal/win32/win32api.pyd",
        "_internal/win32/win32console.pyd",
        "_internal/win32/win32event.pyd",
        "_internal/win32/win32file.pyd",
        "_internal/win32/win32job.pyd",
        "_internal/win32/win32pipe.pyd",
        "_internal/win32/win32process.pyd",
        "_internal/win32/win32security.pyd",
        "_internal/win32com/shell/shell.pyd",
    }
    missing_runtime = sorted(required_runtime_files - payload.keys())
    if missing_runtime:
        fail(
            "Windows archive is missing required native runtime files: "
            + ", ".join(missing_runtime)
        )
    if not any(
        name.startswith("_internal/pywin32_system32/pywintypes")
        and name.endswith(".dll")
        for name in payload
    ):
        fail("Windows archive is missing the pywin32 runtime DLL")
    for distribution_name in ("psutil", "pywin32", "PyInstaller"):
        prefix = f"{RUNTIME_LICENSES_DIR}/{distribution_name}/"
        if not any(name.startswith(prefix) for name in payload):
            fail(f"Windows archive is missing {distribution_name} license files")
    if payload[MARKER_NAME] != (SIGNING_STATUS + "\n").encode("ascii"):
        fail("Windows archive unsigned marker is invalid")
    try:
        build_info = json.loads(payload[BUILD_INFO_NAME])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"Windows BUILD-INFO.json is invalid: {exc}")
    _validate_build_info(build_info, version)
    if payload["_internal/VERSION"].decode("utf-8").strip() != version:
        fail("Windows bundle VERSION does not match its archive name")
    validate_windows_icon_bytes(payload["_internal/static/assets/favicon.ico"])
    if "_internal/python312.dll" not in payload:
        fail("Windows archive does not contain the Python 3.12 runtime DLL")
    if "_internal/pywin32_system32/pywintypes312.dll" not in payload:
        fail("Windows archive does not contain the pinned pywin32 runtime DLL")
    _validate_pe(payload[PRODUCT_NAME + ".exe"], version)

    expected_checksum = f"{release.sha256(archive)}  {archive.name}\n"
    try:
        actual_checksum = checksum_path(archive).read_text(encoding="ascii")
    except OSError as exc:
        fail(f"cannot read Windows SHA-256 sidecar: {exc}")
    if actual_checksum != expected_checksum:
        fail("Windows SHA-256 sidecar does not match the archive")
    expected_manifest = _manifest(archive, version)
    try:
        actual_manifest_bytes = manifest_path(archive).read_bytes()
        actual_manifest = json.loads(actual_manifest_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read Windows manifest sidecar: {exc}")
    if (
        actual_manifest != expected_manifest
        or actual_manifest_bytes != _canonical_json(expected_manifest)
    ):
        fail("Windows manifest sidecar does not match the archive")
    return expected_manifest


def build(output_dir: Path) -> Path:
    _require_windows_build_host()
    validate_windows_icon()
    version = release.version()
    output_dir = release.validate_output_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    final_archive = output_dir / archive_name(version)
    with tempfile.TemporaryDirectory(
        prefix=".localops-windows-build-", dir=output_dir
    ) as temporary:
        temp = Path(temporary)
        version_file = temp / "version_info.txt"
        version_file.write_text(version_resource(version), encoding="utf-8")
        subprocess.run(
            pyinstaller_command(temp, version_file),
            cwd=ROOT,
            env=pyinstaller_environment(),
            check=True,
        )
        pyinstaller_bundle = temp / "pyinstaller-dist" / PRODUCT_NAME
        bundle = temp / bundle_name(version)
        if not pyinstaller_bundle.is_dir():
            fail("PyInstaller did not produce the expected onedir bundle")
        pyinstaller_bundle.rename(bundle)
        _copy_runtime_licenses(bundle)
        _write_build_metadata(bundle, version)
        archive = temp / archive_name(version)
        _zip_bundle(bundle, archive, version)
        _write_sidecars(archive, version)
        audit_archive(archive)
        for source in (archive, checksum_path(archive), manifest_path(archive)):
            os.replace(source, output_dir / source.name)
    audit_archive(final_archive)
    return final_archive


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build or audit the unsigned Local Ops Windows x64 archive"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    build_parser = subcommands.add_parser("build")
    build_parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    audit_parser = subcommands.add_parser("audit")
    audit_parser.add_argument("--archive", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "build":
        archive = build(args.output_dir)
        print(f"Built and audited {archive}")
        print(f"SHA-256 {release.sha256(archive)}")
        return 0
    manifest = audit_archive(args.archive)
    print(f"Audited {Path(args.archive).resolve()}")
    print(f"SHA-256 {manifest['archive']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
