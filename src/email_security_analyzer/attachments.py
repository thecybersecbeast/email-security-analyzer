"""Attachment analysis: hashing, extension checks, and macro detection."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import PurePosixPath

from .models import AttachmentInfo

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".lnk", ".bat", ".cmd", ".ps1", ".psm1", ".msi", ".jar", ".hta",
    ".iso", ".img", ".cpl", ".dll", ".com", ".pif",
}

MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso"}

# Recognizable "safe-looking" extensions commonly abused in double-extension
# tricks, e.g. invoice.pdf.exe
BENIGN_LOOKING_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}


def _hash_bytes(data: bytes) -> tuple[str, str]:
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


def _extension_of(filename: str) -> str:
    return PurePosixPath(filename.lower()).suffix


def _has_double_extension(filename: str) -> bool:
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    second_to_last = "." + parts[-2]
    last = "." + parts[-1]
    return second_to_last in BENIGN_LOOKING_EXTENSIONS and last in (
        DANGEROUS_EXTENSIONS | {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1"}
    )


def _macro_present_in_office_zip(data: bytes) -> bool:
    """
    Modern Office formats (docx/xlsx/pptx and their macro-enabled 'm'
    variants) are ZIP containers. A macro-enabled file contains a
    vbaProject.bin part. This is a structural check, not full VBA analysis.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return any("vbaproject.bin" in name.lower() for name in zf.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


def analyze_attachment(filename: str, content_type: str, data: bytes) -> AttachmentInfo:
    md5, sha256 = _hash_bytes(data)
    extension = _extension_of(filename)
    double_ext = _has_double_extension(filename)
    dangerous = extension in DANGEROUS_EXTENSIONS

    macro_suspected = False
    if extension in MACRO_ENABLED_EXTENSIONS:
        macro_suspected = True
    elif extension in {".docx", ".xlsx", ".pptx"}:
        # Legitimate 'x' extension but structurally contains macro storage —
        # a strong sign the extension was tampered with to evade filters.
        macro_suspected = _macro_present_in_office_zip(data)

    info = AttachmentInfo(
        filename=filename,
        content_type=content_type,
        size_bytes=len(data),
        md5=md5,
        sha256=sha256,
        extension=extension,
        double_extension=double_ext,
        dangerous_extension=dangerous,
        macro_suspected=macro_suspected,
    )

    weight = 0
    if dangerous:
        info.findings.append(f"Extension '{extension}' is a common malware delivery format.")
        weight += 50
    if double_ext:
        info.findings.append(
            "Filename uses a double extension (e.g. document.pdf.exe) — a "
            "classic technique to disguise an executable as a document."
        )
        weight += 25
    if macro_suspected:
        info.findings.append(
            "Document contains an embedded VBA macro project "
            "(vbaProject.bin) — macros can execute code on open."
        )
        weight += 30
    if extension in ARCHIVE_EXTENSIONS:
        info.findings.append(
            f"'{extension}' archive/disk-image attachments are frequently "
            f"used to smuggle payloads past content filters."
        )
        weight += 10

    info.weight = weight
    return info
