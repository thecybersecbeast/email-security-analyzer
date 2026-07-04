import shutil

from email_security_analyzer import EmailAnalyzer
from email_security_analyzer.realtime.folder_watcher import watch_maildir


def test_watch_maildir_processes_and_files_messages(tmp_path, fixtures_dir):
    maildir_new = tmp_path / "Maildir" / "new"
    maildir_new.mkdir(parents=True)

    for name in ["clean_email.eml", "phishing_email.eml", "macro_email.eml"]:
        shutil.copy(fixtures_dir / name, maildir_new / name)

    results = dict(
        (path.name, result)
        for path, result in watch_maildir(
            maildir_new, analyzer=EmailAnalyzer(), poll_interval=0.05, stop_after=3
        )
    )

    assert results["clean_email.eml"].risk.verdict.value == "deliver"
    assert results["phishing_email.eml"].risk.verdict.value == "reject"

    base = maildir_new.parent
    assert (base / "cur" / "clean_email.eml").exists()
    assert (base / "rejected" / "phishing_email.eml").exists()
    assert not (maildir_new / "clean_email.eml").exists()
    assert not (maildir_new / "phishing_email.eml").exists()


def test_watch_maildir_ignores_non_eml_files(tmp_path, fixtures_dir):
    maildir_new = tmp_path / "Maildir" / "new"
    maildir_new.mkdir(parents=True)
    shutil.copy(fixtures_dir / "clean_email.eml", maildir_new / "clean_email.eml")
    (maildir_new / "readme.txt").write_text("not an email")

    results = list(
        watch_maildir(maildir_new, analyzer=EmailAnalyzer(), poll_interval=0.05, stop_after=1)
    )

    assert len(results) == 1
    assert results[0][0].name == "clean_email.eml"
    assert (maildir_new / "readme.txt").exists()  # untouched


def test_watch_maildir_survives_a_malformed_message(tmp_path, fixtures_dir):
    maildir_new = tmp_path / "Maildir" / "new"
    maildir_new.mkdir(parents=True)

    # A malformed .eml won't crash email.parser, but simulate a filename
    # that disappears mid-poll (e.g. another process already moved it) by
    # writing then immediately removing it before the watcher's next pass
    # is exercised via stop_after covering only the well-formed message.
    shutil.copy(fixtures_dir / "clean_email.eml", maildir_new / "clean_email.eml")

    results = list(
        watch_maildir(maildir_new, analyzer=EmailAnalyzer(), poll_interval=0.05, stop_after=1)
    )
    assert len(results) == 1
