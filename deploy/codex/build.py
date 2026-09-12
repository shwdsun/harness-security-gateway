#!/usr/bin/env python3
"""Offline assembly of the measured Codex development template; no installer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SERVICES = {"agentd": "agentd", "sandboxd-codex": "sandboxd",
            "hgwctl": "hgwctl", "fake-connector": "fake-connector",
            "discord-connector": "discord-connector"}
BUILD_FLAGS = ["-mod=readonly", "-buildvcs=false", "-trimpath"]
TEMPLATES = ["agentd.example.json", "sandboxd.example.json", "hgw.sysusers",
             "hgw.tmpfiles", "hgw-agentd.service", "hgw-sandboxd.service",
             "hgw-sandboxd-docker.service", "hgw-connector-discord.service",
             "hgw-discord.sysusers", "hgw-discord.tmpfiles",
             "discord-connector.example.json"]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def canonical_directory(value):
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
        raise ValueError("input/cache directory must be absolute and free of symlinks")
    return path


def check_layout(root, entries):
    """Reject extra entries before opening any input file, including auth.json."""
    root = canonical_directory(root)
    allowed = {root: True}
    for name in entries:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or str(relative) != name:
            raise ValueError("non-canonical pinned input name")
        path = root / relative
        allowed[path] = False
        for parent in path.parents:
            if parent == root:
                break
            allowed[parent] = True
    observed = {root, *root.rglob("*")}
    if observed != set(allowed):
        raise ValueError("input tree has missing or unexpected entries")
    for path, directory in allowed.items():
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or stat.S_ISDIR(info.st_mode) != directory
                or (not directory and not stat.S_ISREG(info.st_mode))
                or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o6022
                or (not directory and info.st_nlink != 1)):
            raise ValueError("unsafe pinned input metadata")


def copy_verified(source, destination, expected):
    # Bound the read; never follow a final symlink or block on a special file.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as src:
        info = os.fstat(src.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o6022
                or info.st_size != expected["bytes"]
                or (expected["executable"] and not info.st_mode & 0o111)):
            raise ValueError("pinned input attributes changed or do not match")
        # Path.mkdir(parents=True) applies its mode only to the final directory;
        # intermediate package directories would inherit the caller's umask.
        missing = []
        parent = destination.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for parent in reversed(missing):
            parent.mkdir(mode=0o700)
        checksum = hashlib.sha256()
        remaining = expected["bytes"]
        with destination.open("xb") as dst:
            while remaining:
                chunk = src.read(min(1 << 20, remaining))
                if not chunk:
                    raise ValueError("pinned input truncated during copy")
                dst.write(chunk)
                checksum.update(chunk)
                remaining -= len(chunk)
            if src.read(1) or checksum.hexdigest() != expected["sha256"]:
                raise ValueError("pinned input content mismatch")
    destination.chmod(0o555 if expected["executable"] else 0o444)


def source_manifest():
    # Explicit compiler inputs plus the recipe/templates. No local config,
    # credential, Git internals, runtime tree or arbitrary repository archive.
    paths = [REPO / "go.mod", REPO / "go.sum", REPO / "LICENSE"]
    for directory in (REPO / "cmd", REPO / "internal"):
        paths.extend(p for p in directory.rglob("*")
                     if p.suffix in (".go", ".sql", ".c", ".h", ".s", ".S"))
    paths.extend(HERE / name for name in ["build.py", "inputs.lock.json", "README.md", *TEMPLATES])
    if any(not p.is_file() or p.resolve() != p for p in paths):
        raise ValueError("build sources must be regular files without symlinks")
    return {str(p.relative_to(REPO)): digest(p) for p in sorted(paths)}


def archive(payload, output):
    # USTAR has no host paths, timestamps, UID/GID assignments or compressor
    # metadata. This is an artifact archive, not a filesystem ownership recipe.
    with tarfile.open(output, "x", format=tarfile.USTAR_FORMAT) as bundle:
        for path in sorted(payload.rglob("*")):
            entry = tarfile.TarInfo(str(path.relative_to(payload)))
            entry.mode = 0o755 if path.is_dir() else stat.S_IMODE(path.stat().st_mode)
            if path.is_dir():
                entry.type = tarfile.DIRTYPE
                bundle.addfile(entry)
            else:
                entry.size = path.stat().st_size
                with path.open("rb") as stream:
                    bundle.addfile(entry, stream)


def build(args):
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("build as a non-root Linux user")
    lock = json.loads((HERE / "inputs.lock.json").read_text())
    native = canonical_directory(args.native_artifacts)
    package = canonical_directory(args.tool_package)
    check_layout(native, lock["native"])
    check_layout(package, lock["tool_package"])
    output = Path(args.output)
    if (not output.is_absolute() or output.resolve() != output
            or not output.parent.is_dir() or output.exists()
            or any(output == p or output.is_relative_to(p) or p.is_relative_to(output)
                   for p in (REPO, native, package))):
        raise ValueError("output must be a new directory outside source and input trees")
    go = Path(args.go)
    if not go.is_absolute() or go.resolve(strict=True) != go or not go.is_file():
        raise ValueError("--go must name an explicit non-symlink executable")
    env = {"PATH": str(go.parent) + ":/usr/bin:/bin", "HOME": "/nonexistent",
           "LANG": "C.UTF-8", "CGO_ENABLED": "0", "GOTOOLCHAIN": "local",
           "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GOENV": "off",
           "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off", "GOMAXPROCS": "4"}
    for name in ("GOMODCACHE", "GOCACHE", "GOTMPDIR"):
        env[name] = str(canonical_directory(os.environ[name]))
    env["TMPDIR"] = env["GOTMPDIR"]
    version = subprocess.check_output([str(go), "version"], env=env, text=True).strip()
    if version != "go version " + lock["go_version"] + " linux/amd64":
        raise ValueError("Go toolchain does not match the frozen recipe")
    frozen = source_manifest()
    go_sha256 = digest(go)
    subprocess.run([str(go), "mod", "verify"], cwd=REPO, env=env, check=True)
    output.mkdir(mode=0o700)
    payload = output / "payload"
    payload.mkdir(mode=0o700)
    (payload / "bin").mkdir(mode=0o700)
    for prefix, root, entries in [("native", native, lock["native"]),
                                  ("codex-package", package, lock["tool_package"])]:
        for name, expected in sorted(entries.items()):
            copy_verified(root / name, payload / prefix / name, expected)
    for name, command in SERVICES.items():
        print("Building " + name, flush=True)
        tags = ["-tags=codexintegration"] if name == "sandboxd-codex" else []
        subprocess.run([str(go), "build", *BUILD_FLAGS, *tags,
                        "-o", str(payload / "bin" / name), "./cmd/" + command],
                       cwd=REPO, env=env, check=True)
        (payload / "bin" / name).chmod(0o555)
    (payload / "templates").mkdir(mode=0o700)
    for name, source in [("templates/" + n, HERE / n) for n in TEMPLATES] + [
            ("PREPARATION.md", HERE / "README.md"), ("LICENSE", REPO / "LICENSE"),
            ("inputs.lock.json", HERE / "inputs.lock.json")]:
        (payload / name).write_bytes(source.read_bytes())
        (payload / name).chmod(0o444)
    if source_manifest() != frozen or digest(go) != go_sha256:
        raise ValueError("build sources or Go executable changed during assembly")
    files = {str(p.relative_to(payload)): {"sha256": digest(p), "bytes": p.stat().st_size,
                                         "mode": format(stat.S_IMODE(p.stat().st_mode), "04o")}
             for p in sorted(payload.rglob("*")) if p.is_file()}
    write_json(payload / "manifest.json", {
        "schema": "hsg-codex-offline-bundle/v1", "status": "unactivated-development-template",
        "image": lock["image"], "profile_sha256": lock["profile_sha256"],
        "go_version": version, "go_executable_sha256": go_sha256,
        "go_build_flags": BUILD_FLAGS, "cgo_enabled": False,
        "source_sha256": frozen, "files": files})
    (payload / "manifest.json").chmod(0o444)
    with (payload / "SHA256SUMS").open("x") as stream:
        for path in sorted(payload.rglob("*")):
            if path.is_file() and path.name != "SHA256SUMS":
                stream.write(digest(path) + "  " + str(path.relative_to(payload)) + "\n")
    (payload / "SHA256SUMS").chmod(0o444)
    archive(payload, output / "bundle.tar")
    # Last file is the completion marker. Failed attempts retain partial work
    # but never emit this receipt, overwrite a prior bundle, or remove evidence.
    with (output / "BUNDLE.SHA256").open("x") as stream:
        stream.write(digest(output / "bundle.tar") + "  bundle.tar\n")
    print("Offline bundle complete: " + str(output), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True)
    parser.add_argument("--native-artifacts", required=True)
    parser.add_argument("--tool-package", required=True)
    parser.add_argument("--output", required=True)
    try:
        build(parser.parse_args())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, "offline bundle failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
