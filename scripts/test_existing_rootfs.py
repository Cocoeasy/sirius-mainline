#!/usr/bin/env python3
"""Read-only rootfs regression tests for the sirius initramfs.

The tests treat initramfs/build-initramfs.sh as the single source of truth: they
extract the *real* shell that the image ships and execute it, instead of
reimplementing the GPT parsing logic in Python.

Dynamic part
------------
``build-initramfs.sh`` is expected to carry the disk-layout validation between

    # BEGIN ROOTFS_VALIDATION
    ...
    # END ROOTFS_VALIDATION

with the interface ``read_root_layout <image> <device_sectors>``: on success it
sets ``ROOT_OFFSET`` / ``ROOT_SIZE`` (in bytes) and returns 0, on any invalid
input it returns non-zero.  Those real functions are extracted and run under
Git Bash against tiny in-memory GPT fixtures (a few KB - never a full image).

On the host a shim makes the busybox applet dispatcher run the host GNU tools::

    bb() { "$@"; }      # bb dd ...  ->  host dd ...

so ``bb dd`` / ``bb od`` / ``bb tr`` resolve to GNU dd/od/tr.  Fixture paths are
passed to bash as POSIX paths (``C:/...``), which Git Bash reads natively.

Static part
-----------
The embedded /init and scripts/mkbootimg.py are checked for the safety
properties of the read-only design: no formatting, no Alpine payload, no writes
to the on-disk /etc/{inittab,shadow}, applet dirs created before
``busybox --install``, the ``say`` helper free of ``ttyGS0``, a read-only mount
path (``losetup -r`` + ``mount -o ro,noload``), PID 1 handing over with
``exec switch_root``, and a kernel CMDLINE free of ``console=ttyGS0``.

Nothing outside this file is touched; fixtures live in the system temp dir.
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
import uuid
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BUILD_SCRIPT = os.path.join(REPO, "initramfs", "build-initramfs.sh")
MKBOOTIMG_PY = os.path.join(HERE, "mkbootimg.py")

BASH = shutil.which("bash") or shutil.which("bash.exe")

# --- GPT fixture constants (sirius userdata, 512-byte sectors) --------------
SECTOR = 512
HEADER_LBA = 1
ENTRIES_LBA = 2
NUM_ENTRIES = 128
ENTRY_SIZE = 128
DEVICE_SECTORS = 96452575
BACKUP_LBA = 96452574
FIRST_USABLE = 34
LAST_USABLE = 96452541
ROOT_FIRST_LBA = 999424
ROOT_LAST_LBA = 1957887

# Verified on device (COM6 read-only): the userdata partition carries an embedded
# GPT whose entry #1 is the ESP (0-based index 0) and whose entry #2 is the Linux
# ARM64 root (0-based index 1, i.e. table LBA 2 + 128 bytes).  "entry2" in the
# requirements is the 1-based partition number, so the root lives at index 1.
ROOT_ENTRY_INDEX = 1

# Inclusive extent: (last - first + 1) * SECTOR.
ROOT_OFFSET = ROOT_FIRST_LBA * SECTOR               # 511705088
ROOT_SIZE = (ROOT_LAST_LBA - ROOT_FIRST_LBA + 1) * SECTOR  # 490733568

ROOT_TYPE = uuid.UUID("b921b045-1df0-41c3-af44-4c6f280d3fae").bytes_le  # ARM64 root
ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").bytes_le   # EFI system
LINUX_FS_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le
OTHER_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le  # MS basic data


# --------------------------------------------------------------------------- #
# source extraction
# --------------------------------------------------------------------------- #
_VALIDATION_BEGIN = re.compile(r"^[ \t]*#\s*BEGIN ROOTFS_VALIDATION\b[^\n]*$", re.M)
_VALIDATION_END = re.compile(r"^[ \t]*#\s*END ROOTFS_VALIDATION\b[^\n]*$", re.M)


def read_build_script():
    with open(BUILD_SCRIPT, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def extract_init_heredoc(text):
    """Return the source between <<'INIT_EOF' and the closing INIT_EOF."""
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if "<<'INIT_EOF'" in line or '<<"INIT_EOF"' in line:
            start = idx
    if start is None:
        return None
    body = []
    for line in lines[start + 1:]:
        if line.strip() == "INIT_EOF":
            return "\n".join(body)
        body.append(line)
    return None


def extract_validation_block(text):
    """Return the source between the ROOTFS_VALIDATION markers (exclusive)."""
    begin = _VALIDATION_BEGIN.search(text)
    end = _VALIDATION_END.search(text)
    if not begin or not end or end.start() <= begin.end():
        return None
    return text[begin.end():end.start()]


def extract_function(text, name):
    """Return the shell function definition of ``name`` from ``text``."""
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^%s\s*\(\s*\)\s*\{" % re.escape(name), stripped):
            start = idx
            break
        if re.match(r"^function\s+%s\b" % re.escape(name), stripped):
            start = idx
            break
    if start is None:
        return None
    depth = 0
    body = []
    for line in lines[start:]:
        body.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
    return "\n".join(body)


def strip_comment_lines(code):
    """Drop whole-line shell comments so prose cannot trigger a check."""
    return "\n".join(
        line for line in code.splitlines()
        if not line.lstrip().startswith("#")
    )


# On-disk rootfs identity files that must never be modified in place.
_ID_FILE = re.compile(r"etc/(inittab|shadow)\b")
# Shell redirection / dd destinations ("2>" and "&>" are not file targets).
_REDIRECT_TARGET = re.compile(r"(?<![0-9&])>>?\s*(\"[^\"]*\"|'[^']*'|[^\s;&|<>]+)")
_OF_TARGET = re.compile(r"\bof=(\"[^\"]*\"|'[^']*'|[^\s;&|]+)")
_WRITER_CMDS = ("tee", "cp", "mv", "install")


def disk_idfile_writes(code):
    """Return the lines that *write* the on-disk /etc/inittab or /etc/shadow.

    Only the write destination counts.  A line such as ::

        sha256sum /newroot/etc/shadow /newroot/etc/inittab > /run/baseline

    reads (hashes) those files and redirects elsewhere, so it must not be
    reported even though it mentions the paths.  Reads, redirects into /run or
    other tmpfs paths, and comments are therefore all allowed; a redirect or
    in-place edit whose *target* is the identity file is not.
    """
    hits = []
    for line in code.splitlines():
        destinations = [d.strip("\"'") for d in _REDIRECT_TARGET.findall(line)]
        destinations += [d.strip("\"'") for d in _OF_TARGET.findall(line)]
        if any(_ID_FILE.search(dest) for dest in destinations):
            hits.append(line)
            continue
        if re.search(r"\bsed\b[^\n]*\s-i\b", line) and _ID_FILE.search(line):
            hits.append(line)
            continue
        args = line.split()
        if any(a.rsplit("/", 1)[-1] in _WRITER_CMDS for a in args):
            if args and _ID_FILE.search(args[-1].strip("\"'")):
                hits.append(line)
    return hits


# --------------------------------------------------------------------------- #
# tiny GPT fixtures (header + partition table only, a few KB)
# --------------------------------------------------------------------------- #
def _put_entry(buf, index, entry_size, num_entries, type_guid, first_lba, last_lba):
    if not (0 <= index < num_entries) or entry_size < 56:
        return
    off = index * entry_size
    entry = bytearray(entry_size)
    entry[0:16] = type_guid
    struct.pack_into("<Q", entry, 32, first_lba)
    struct.pack_into("<Q", entry, 40, last_lba)
    name = "linux".encode("utf-16-le")
    entry[56:56 + min(len(name), entry_size - 56)] = name[:entry_size - 56]
    buf[off:off + entry_size] = entry


def build_gpt(**over):
    """Build a minimal GPT disk image; ``truncate`` slices the result."""
    signature = over.get("signature", b"EFI PART")
    header_size = over.get("header_size", 92)
    current_lba = over.get("current_lba", HEADER_LBA)
    backup_lba = over.get("backup_lba", BACKUP_LBA)
    first_usable = over.get("first_usable", FIRST_USABLE)
    last_usable = over.get("last_usable", LAST_USABLE)
    entries_lba = over.get("entries_lba", ENTRIES_LBA)
    num_entries = over.get("num_entries", NUM_ENTRIES)
    entry_size = over.get("entry_size", ENTRY_SIZE)
    root_index = over.get("root_index", ROOT_ENTRY_INDEX)
    root_first = over.get("root_first", ROOT_FIRST_LBA)
    root_last = over.get("root_last", ROOT_LAST_LBA)
    root_type = over.get("root_type", ROOT_TYPE)
    truncate = over.get("truncate")

    entries = bytearray(num_entries * entry_size)
    # ESP at index 0 (the verified slot #1); a non-root decoy after the root slot
    # so the root is genuinely located by its slot, not by being the only entry.
    _put_entry(entries, 0, entry_size, num_entries, ESP_TYPE, 2048, 4095)
    if root_index != 2:
        _put_entry(entries, 2, entry_size, num_entries, LINUX_FS_TYPE, 4096, ROOT_FIRST_LBA - 1)
    _put_entry(entries, root_index, entry_size, num_entries, root_type, root_first, root_last)
    entries = bytes(entries)
    entries_crc = zlib.crc32(entries) & 0xffffffff

    header = bytearray(92)
    header[0:8] = signature.ljust(8, b"\x00")[:8]
    struct.pack_into("<I", header, 8, 0x00010000)           # revision
    struct.pack_into("<I", header, 12, header_size)
    struct.pack_into("<I", header, 20, 0)                   # reserved
    struct.pack_into("<Q", header, 24, current_lba)
    struct.pack_into("<Q", header, 32, backup_lba)
    struct.pack_into("<Q", header, 40, first_usable)
    struct.pack_into("<Q", header, 48, last_usable)
    # disk GUID (header[56:72]) left zero
    struct.pack_into("<Q", header, 72, entries_lba)
    struct.pack_into("<I", header, 80, num_entries)
    struct.pack_into("<I", header, 84, entry_size)
    struct.pack_into("<I", header, 88, entries_crc)
    struct.pack_into("<I", header, 16, zlib.crc32(bytes(header)) & 0xffffffff)

    mbr = b"\x00" * 510 + b"\x55\xaa"
    image = mbr + bytes(header).ljust(SECTOR, b"\x00") + entries
    if truncate is not None:
        image = image[:truncate]
    return image


# --------------------------------------------------------------------------- #
# bash harness
# --------------------------------------------------------------------------- #
def _build_driver(block):
    """A bash script that loads the real validation block and calls it."""
    return (
        'bb() { "$@"; }\n'
        + block + "\n"
        + "set +e\n"
        + 'bb() { "$@"; }\n'
        + 'busybox() { "$@"; }\n'
        + "if ! declare -F read_root_layout >/dev/null 2>&1; then\n"
        + "  echo FUNC_PRESENT=0\n"
        + "  exit 0\n"
        + "fi\n"
        + "echo FUNC_PRESENT=1\n"
        + 'ROOT_OFFSET=""\n'
        + 'ROOT_SIZE=""\n'
        + 'read_root_layout "$1" "$2"\n'
        + "rc=$?\n"
        + 'echo "RC=$rc"\n'
        + 'echo "ROOT_OFFSET=$ROOT_OFFSET"\n'
        + 'echo "ROOT_SIZE=$ROOT_SIZE"\n'
    )


def run_layout(block, fixture_path, device_sectors):
    """Run read_root_layout under Git Bash; return a dict of parsed outputs."""
    if BASH is None:
        raise RuntimeError("bash not found on PATH; Git Bash is required")
    driver = _build_driver(block)
    cmd = [BASH, "-s", "--", fixture_path, str(device_sectors)]
    # Feed bytes so the script keeps LF endings - a CRLF /init would be a
    # syntax error ("then\r") and would mask real results.
    proc = subprocess.run(
        cmd, input=driver.encode("utf-8"), capture_output=True, timeout=120
    )
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")

    def grab(key):
        match = re.search(r"^%s=(.*)$" % re.escape(key), out, re.M)
        return match.group(1).strip() if match else None

    rc_text = grab("RC")
    return {
        "present": grab("FUNC_PRESENT") == "1",
        "rc": int(rc_text) if rc_text and re.fullmatch(r"-?\d+", rc_text) else None,
        "offset": grab("ROOT_OFFSET"),
        "size": grab("ROOT_SIZE"),
        "stdout": out,
        "stderr": err,
        "returncode": proc.returncode,
    }


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_build_script()
        cls.block = extract_validation_block(cls.text)
        cls.init = extract_init_heredoc(cls.text)
        cls.tmp = tempfile.mkdtemp(prefix="sirius-rootfs-")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)

    def write_fixture(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(data)
        # POSIX form: "C:/..." is readable by Git Bash from a Windows path.
        return pathlib.Path(path).as_posix()


# --------------------------------------------------------------------------- #
# dynamic: the real read_root_layout
# --------------------------------------------------------------------------- #
class TestReadRootLayout(_Base):
    def _require_block(self):
        if self.block is None:
            self.fail(
                "initramfs/build-initramfs.sh has no "
                "'# BEGIN ROOTFS_VALIDATION' / '# END ROOTFS_VALIDATION' block"
            )
        if "read_root_layout" not in self.block:
            self.fail("the ROOTFS_VALIDATION block does not define read_root_layout")

    def _run(self, data, device_sectors, name):
        self._require_block()
        fixture = self.write_fixture(name, data)
        result = run_layout(self.block, fixture, device_sectors)
        self.assertTrue(
            result["present"],
            "read_root_layout was not defined by the executed block; "
            "stdout=%r stderr=%r" % (result["stdout"], result["stderr"]),
        )
        return result

    def _reject(self, data, device_sectors, name, why, control=None, control_sectors=None):
        """Assert a rejection is *caused by* the defect.

        The defective image must be rejected while an otherwise-identical
        control (the same image with just the defect removed) is accepted.
        Without that pair a rejection could pass vacuously - e.g. because the
        root entry is never located at all.
        """
        result = self._run(data, device_sectors, name)
        self.assertNotEqual(
            result["rc"], 0,
            "expected read_root_layout to reject %s, but rc=%r offset=%r size=%r"
            % (why, result["rc"], result["offset"], result["size"]),
        )
        self.assertIsNotNone(control, "internal: %s is missing its control" % name)
        sectors = device_sectors if control_sectors is None else control_sectors
        ctrl = self._run(control, sectors, "control_" + name)
        self.assertEqual(
            ctrl["rc"], 0,
            "the control for %s (identical image minus %s) must be accepted, "
            "otherwise the rejection is vacuous; rc=%r offset=%r size=%r"
            % (name, why, ctrl["rc"], ctrl["offset"], ctrl["size"]),
        )

    # -- happy path ---------------------------------------------------------
    def test_validation_block_present(self):
        self._require_block()

    def test_valid_layout(self):
        result = self._run(build_gpt(), DEVICE_SECTORS, "valid.img")
        self.assertEqual(
            result["rc"], 0,
            "valid GPT must be accepted; stderr=%r" % result["stderr"],
        )
        self.assertEqual(result["offset"], str(ROOT_OFFSET))
        self.assertEqual(result["size"], str(ROOT_SIZE))

    # -- rejections ---------------------------------------------------------
    def test_reject_bad_signature(self):
        self._reject(build_gpt(signature=b"XXXX XXXX"), DEVICE_SECTORS,
                     "bad_signature.img", "a corrupt GPT signature",
                     control=build_gpt())

    def test_reject_truncated_header(self):
        self._reject(build_gpt(truncate=SECTOR + 40), DEVICE_SECTORS,
                     "truncated_header.img", "a header truncated inside LBA1",
                     control=build_gpt())

    def test_reject_invalid_entries_geometry(self):
        self._reject(build_gpt(entry_size=64), DEVICE_SECTORS,
                     "bad_geometry.img", "an invalid 64-byte partition entry size",
                     control=build_gpt())

    def test_reject_wrong_root_type(self):
        self._reject(build_gpt(root_type=OTHER_TYPE), DEVICE_SECTORS,
                     "wrong_type.img", "a partition whose type is not the ARM64 root",
                     control=build_gpt())

    def test_reject_first_after_last(self):
        self._reject(build_gpt(root_first=ROOT_LAST_LBA, root_last=ROOT_FIRST_LBA),
                     DEVICE_SECTORS, "inverted.img", "first_lba > last_lba",
                     control=build_gpt())

    def test_reject_past_device_bounds(self):
        self._reject(build_gpt(root_last=DEVICE_SECTORS + 99), DEVICE_SECTORS,
                     "device_bounds.img", "a root partition past the usable/device end",
                     control=build_gpt())

    def test_reject_outside_usable_bounds(self):
        self._reject(build_gpt(root_first=FIRST_USABLE - 24), DEVICE_SECTORS,
                     "usable_bounds.img", "a partition below first_usable_lba",
                     control=build_gpt())

    def test_reject_nonnumeric_sectors(self):
        self._reject(build_gpt(), "12abc", "nonnumeric.img",
                     "a non-numeric device_sectors argument",
                     control=build_gpt(), control_sectors=DEVICE_SECTORS)

    def test_reject_high32_lba(self):
        hi = 1 << 32  # >= 2 TiB in sectors: beyond the supported range
        data = build_gpt(
            root_first=hi + ROOT_FIRST_LBA,
            root_last=hi + ROOT_LAST_LBA,
            backup_lba=hi + BACKUP_LBA,
            last_usable=hi + LAST_USABLE,
        )
        self._reject(data, hi + DEVICE_SECTORS, "high32.img",
                     "an LBA whose high 32 bits are non-zero",
                     control=build_gpt(), control_sectors=DEVICE_SECTORS)


# --------------------------------------------------------------------------- #
# static: the embedded /init
# --------------------------------------------------------------------------- #
class TestInitStatic(_Base):
    def _init(self):
        if self.init is None:
            self.fail(
                "could not extract the 'cat > \"$IRD/init\" <<'INIT_EOF'' heredoc "
                "from build-initramfs.sh"
            )
        return self.init

    def test_no_mke2fs_or_mkfs(self):
        code = strip_comment_lines(self._init())
        hits = [ln for ln in code.splitlines()
                if re.search(r"\bmke2fs\b|\bmkfs(\.[a-z0-9]+)?\b", ln)]
        self.assertEqual(hits, [], "init must not create a filesystem: %r" % hits)

    def test_no_alpine_rootfs_payload(self):
        code = strip_comment_lines(self.text)
        hits = [ln for ln in code.splitlines() if "alpine-rootfs" in ln]
        self.assertEqual(
            hits, [],
            "the initramfs must not carry the Alpine payload: %r" % hits,
        )

    def test_no_disk_inittab_or_shadow_write(self):
        code = strip_comment_lines(self._init())
        hits = disk_idfile_writes(code)
        self.assertEqual(
            hits, [],
            "init must not write the on-disk /etc/{inittab,shadow}: %r" % hits,
        )

    def test_busybox_dirs_before_install(self):
        code = strip_comment_lines(self.text)
        mkdir = re.search(r"(?m)^\s*mkdir\b[^\n]*\b(sbin|bin)\b", code)
        self.assertIsNotNone(
            mkdir, "the build script never creates the busybox applet dirs (bin/sbin)")
        install = re.search(r"busybox\s+--install", code)
        self.assertIsNotNone(install, "the build script never runs 'busybox --install'")
        self.assertLess(
            mkdir.start(), install.start(),
            "busybox applet dirs (bin/sbin) must be created before 'busybox --install'",
        )

    def test_say_has_no_ttyGS0(self):
        body = extract_function(self._init(), "say")
        self.assertIsNotNone(body, "the embedded init has no say() function")
        self.assertNotIn(
            "ttyGS0", body,
            "say() must not mirror output to ttyGS0:\n%s" % body,
        )

    def test_readonly_mount_path(self):
        init = self._init()
        self.assertRegex(
            init, r"losetup[^\n]*\s-r\b|losetup[^\n]*--read-only",
            "init must attach the loop device read-only (losetup -r)",
        )
        self.assertRegex(
            init, r"\bro\s*,\s*noload\b",
            "init must mount the ext4 root read-only as '-o ro,noload'",
        )

    def test_pid1_execs_switch_root(self):
        self.assertRegex(
            self._init(), r"(?m)^\s*exec\s+[^\n]*switch_root\b",
            "PID 1 must hand over with 'exec switch_root'",
        )

    def test_baseline_relative_paths_and_explicit_verdict(self):
        """The baseline manifest must use relative paths (so it can be checked
        against a second, original mount) and the check must print an explicit
        PASS/FAIL verdict."""
        init = self._init()
        gen = re.search(r"\(\s*cd\s+(\S+)\s*&&\s*sha256sum\b([^)]*)\)\s*>\s*(\S+)", init)
        self.assertIsNotNone(
            gen,
            "baseline must be written from a relative CWD: "
            "( cd <dir> && sha256sum <relative paths> ) > <manifest>",
        )
        self.assertNotIn(
            "/newroot/", gen.group(2),
            "baseline entries must be relative, not absolute /newroot/... paths: %r"
            % gen.group(2),
        )
        self.assertTrue(
            gen.group(3).startswith("/run/"),
            "the baseline manifest must live on the /run tmpfs, got %r" % gen.group(3),
        )
        self.assertRegex(
            init, r"sha256sum\s+-c\b",
            "the baseline must be verified with 'sha256sum -c <manifest>'",
        )
        self.assertIn("BASELINE_PASS", init, "verification must emit an explicit BASELINE_PASS")
        self.assertIn("BASELINE_FAIL", init, "verification must emit an explicit BASELINE_FAIL")
        self.assertRegex(
            init, r"cd\s+\S+\s*&&[^\n]*sha256sum\s+-c",
            "sha256sum -c must run from inside a mount of the original root",
        )

    def test_serial_fallback_after_dev_migration(self):
        """After 'mount --move /dev /newroot/dev' the old /dev paths are gone,
        so say() and serial_shell() must also try the migrated /newroot/dev."""
        init = self._init()
        self.assertRegex(
            init, r"mount\s+--move\s+/dev\s+/newroot/dev",
            "the init must move /dev onto /newroot/dev before switch_root",
        )
        say_body = extract_function(init, "say")
        shell_body = extract_function(init, "serial_shell")
        self.assertIsNotNone(say_body, "the embedded init has no say() function")
        self.assertIsNotNone(shell_body, "the embedded init has no serial_shell() function")
        self.assertIn(
            "/newroot/dev/kmsg", say_body,
            "say() must fall back to the migrated /newroot/dev/kmsg:\n%s" % say_body,
        )
        self.assertIn(
            "/newroot/dev/ttyGS0", shell_body,
            "serial_shell() must fall back to the migrated /newroot/dev/ttyGS0:\n%s"
            % shell_body,
        )

    def test_cache_log_rotation(self):
        init = self._init()
        rotate = re.search(r"\bmv\b[^\n]*\.prev\b", init)
        self.assertIsNotNone(
            rotate, "the cache boot log must be rotated (moved to *.prev) before reuse")
        truncate = re.search(r":\s*>\s*\"?\$LOG\b", init)
        self.assertIsNotNone(truncate, "the cache boot log must be recreated with ': > $LOG'")
        self.assertLess(
            rotate.start(), truncate.start(),
            "rotation to *.prev must happen before '$LOG' is truncated",
        )

    def test_kernel_log_streamed_from_kmsg_not_dmesg_follow(self):
        init = self._init()
        self.assertNotRegex(
            init, r"dmesg\s+-w\b",
            "do not use the unbounded 'dmesg -w'; stream /dev/kmsg instead",
        )
        self.assertRegex(
            init, r"cat\s+/dev/kmsg\b",
            "kernel log capture must read the bounded /dev/kmsg",
        )

    def test_ext4_identity_uuid_and_label(self):
        """The root identity is verified straight from the 1 KiB ext4 superblock
        (s_uuid at +104, s_volume_name at +120, 16 bytes each) before mounting."""
        init = self._init()
        want_uuid = uuid.UUID("c84b0979-b794-487b-a265-5acebece3f21").hex
        want_label = "pmOS_root".encode("ascii").ljust(16, b"\x00").hex()
        block = re.search(r"root_uuid=.*?identity mismatch", init, re.S)
        self.assertIsNotNone(
            block, "init never reads/validates the ext4 superblock identity")
        identity = block.group(0)
        self.assertRegex(identity, r"skip=1128\b", "s_uuid must be read at 1024+104 = 1128")
        self.assertRegex(identity, r"skip=1144\b", "s_volume_name must be read at 1024+120 = 1144")
        got_uuid = re.search(r'root_uuid"\]?\s*=\s*([0-9a-f]+)', identity)
        got_label = re.search(r'root_label"\]?\s*=\s*([0-9a-f]+)', identity)
        self.assertIsNotNone(got_uuid, "init never validates the root UUID")
        self.assertIsNotNone(got_label, "init never validates the root label")
        self.assertEqual(
            len(got_uuid.group(1)), 32, "s_uuid must be exactly 16 bytes (32 hex chars)")
        self.assertEqual(
            len(got_label.group(1)), 32, "s_volume_name must be exactly 16 bytes (32 hex chars)")
        self.assertEqual(got_uuid.group(1), want_uuid,
                         "checked root UUID must be the full c84b...f21")
        self.assertEqual(
            got_label.group(1), want_label,
            "checked root label must be 'pmOS_root' NUL-padded to exactly 16 bytes")
        mount = re.search(r"mount\s+-t\s+ext4\s+-o\s+ro,noload", init)
        self.assertIsNotNone(mount, "init never mounts the root read-only")
        self.assertLess(
            block.start(), mount.start(),
            "the root identity must be validated before the root is mounted",
        )


# --------------------------------------------------------------------------- #
# static: mkbootimg CMDLINE
# --------------------------------------------------------------------------- #
class TestMkbootimgCmdline(_Base):
    def test_cmdline_has_no_ttyGS0(self):
        with open(MKBOOTIMG_PY, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        match = re.search(r"CMDLINE\s*=\s*\((.*?)\)", src, re.S)
        if match:
            region = match.group(1)
        else:
            match = re.search(r"CMDLINE\s*=\s*([^\n]*)", src)
            self.assertIsNotNone(match, "scripts/mkbootimg.py has no CMDLINE definition")
            region = match.group(1)
        self.assertNotIn(
            "console=ttyGS0", region,
            "kernel CMDLINE must not contain console=ttyGS0: %r" % region,
        )


# --------------------------------------------------------------------------- #
# static: shell syntax of the build script
# --------------------------------------------------------------------------- #
class TestBuildScriptSyntax(unittest.TestCase):
    def test_bash_available(self):
        self.assertIsNotNone(BASH, "bash not found on PATH; Git Bash is required")

    def test_bash_syntax(self):
        self.assertIsNotNone(BASH, "bash not found on PATH; Git Bash is required")
        script = pathlib.Path(BUILD_SCRIPT).as_posix()
        proc = subprocess.run([BASH, "-n", script], capture_output=True, timeout=60)
        self.assertEqual(
            proc.returncode, 0,
            "bash -n failed: %s" % proc.stderr.decode("utf-8", "replace"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
