import io
import zipfile

from email_security_analyzer.attachments import analyze_attachment


def test_dangerous_extension_flagged():
    info = analyze_attachment("malware.exe", "application/octet-stream", b"fake-bytes")
    assert info.dangerous_extension is True
    assert info.weight >= 50


def test_double_extension_flagged():
    info = analyze_attachment("invoice.pdf.exe", "application/octet-stream", b"fake-bytes")
    assert info.double_extension is True
    assert info.dangerous_extension is True


def test_benign_pdf_not_flagged():
    info = analyze_attachment("report.pdf", "application/pdf", b"%PDF-1.4 fake")
    assert info.dangerous_extension is False
    assert info.double_extension is False
    assert info.weight == 0


def test_macro_enabled_extension_flagged():
    info = analyze_attachment("budget.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", b"data")
    assert info.macro_suspected is True


def test_docx_with_embedded_vba_project_flagged():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"fake-vba")
    info = analyze_attachment(
        "sneaky.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        buf.getvalue(),
    )
    assert info.macro_suspected is True


def test_hashes_are_computed():
    info = analyze_attachment("file.txt", "text/plain", b"hello world")
    assert len(info.md5) == 32
    assert len(info.sha256) == 64
